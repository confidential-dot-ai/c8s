package coordinator

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// Enroll records a CVM boot as a participant.
//
// The enrollment is verified against the key it carries, and that key is the
// one every later message from this boot id must use. What the key proves is
// continuity, not hardware: nothing here ties it to a TEE report, so a boot id
// is only as trustworthy as the channel it arrived on.
//
// An enrollment is refused while an update is outstanding: a boot that joined
// mid-rollout would either be counted as having barriered against a publication
// it never saw, or block a completion it cannot speak for. It retries once the
// update finishes. For the same reason it is refused before the first
// publication — there is no state to have applied — which is what keeps the
// first update's frozen set empty.
//
// Re-sending an identical enrollment succeeds and changes nothing, so a node
// that cannot tell whether its message arrived can send it again. The same boot
// id under a different key is refused: a boot identity is its key.
func (c *Coordinator) Enroll(env policystate.Envelope[policystate.Enrollment]) error {
	msg := env.Message
	if msg.Protocol != policystate.Protocol {
		return fmt.Errorf("%w: enrollment protocol %q (want %q)", ErrInvalid, msg.Protocol, policystate.Protocol)
	}
	pub, err := policystate.DecodeBootKey(msg.BootKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if got := policystate.BootID(pub); got != msg.BootID {
		return fmt.Errorf("%w: boot id %s does not name the boot key (%s)", ErrInvalid, msg.BootID, got)
	}
	if err := policystate.VerifyMessage(pub, policystate.DomainAck, env); err != nil {
		return fmt.Errorf("%w: enrollment: %v", ErrUnauthenticated, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.published == 0 {
		return fmt.Errorf("%w: no policy has been published yet", ErrConflict)
	}
	if c.update != nil {
		return fmt.Errorf("%w: version %d is rolling out; enroll once it completes", ErrConflict, c.update.Version)
	}
	return c.write(func(a *appender) error {
		var stored string
		err := a.tx.QueryRow("SELECT boot_key FROM participants WHERE boot_id = ?", msg.BootID).Scan(&stored)
		switch {
		case err == nil && stored == msg.BootKey:
			return nil
		case err == nil:
			return fmt.Errorf("%w: boot id %s is already enrolled under a different key", ErrConflict, msg.BootID)
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		_, err = a.tx.Exec("INSERT INTO participants (boot_id, name, boot_key, applied_digest) VALUES (?, ?, ?, ?)",
			msg.BootID, msg.Name, msg.BootKey, msg.AppliedDigest)
		if err == nil {
			slog.Info("participant enrolled", "boot_id", msg.BootID, "name", msg.Name, "applied_digest", msg.AppliedDigest)
		}
		return err
	})
}

// Ack records one participant's barrier for the outstanding update: new work on
// that participant already satisfies the target. The update switches once every
// frozen participant has acknowledged.
//
// A retry is accepted and changes nothing, so a node that cannot tell whether
// its ack arrived can send it again.
func (c *Coordinator) Ack(env policystate.Envelope[policystate.Ack]) error {
	msg := env.Message
	if msg.Protocol != policystate.Protocol {
		return fmt.Errorf("%w: ack protocol %q (want %q)", ErrInvalid, msg.Protocol, policystate.Protocol)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var outstanding []string
	err := c.write(func(a *appender) error {
		if err := authenticate(a.tx, msg.BootID, env); err != nil {
			return err
		}
		if _, err := frozen(a.tx, msg.BootID, msg.Version, msg.TargetDigest); err != nil {
			return err
		}
		if _, err := a.tx.Exec("UPDATE update_participants SET acked = 1 WHERE boot_id = ?", msg.BootID); err != nil {
			return err
		}
		if err := c.advance(a); err != nil {
			return err
		}
		var err error
		outstanding, err = unacknowledged(a.tx)
		return err
	})
	if err != nil {
		return err
	}
	slog.Info("participant acknowledged the update barrier",
		"boot_id", msg.BootID, "version", msg.Version, "retired", msg.Retired, "outstanding", len(outstanding))
	if len(outstanding) > 0 {
		// No fence exists: these boots block the switch, and so every later
		// publication, until they answer or the deployment is rebuilt.
		slog.Warn("policy update is waiting on participants that have not acknowledged",
			"version", msg.Version, "outstanding", outstanding)
	}
	return nil
}

// Complete records that a participant has applied the target and holds nothing
// that still needs the source. It is a claim by the participant, not proof:
// what it is worth depends on that participant's measured enforcement profile.
//
// It is refused before the switch, because the target is not yet authorized:
// a participant that reports the source retired while admission still runs on
// it would let CDS narrow the advertised bound too early.
func (c *Coordinator) Complete(env policystate.Envelope[policystate.Completion]) error {
	msg := env.Message
	if msg.Protocol != policystate.Protocol {
		return fmt.Errorf("%w: completion protocol %q (want %q)", ErrInvalid, msg.Protocol, policystate.Protocol)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.write(func(a *appender) error {
		if err := authenticate(a.tx, msg.BootID, env); err != nil {
			return err
		}
		u, err := frozen(a.tx, msg.BootID, msg.Version, msg.TargetDigest)
		if err != nil {
			return err
		}
		if !u.Switched {
			return fmt.Errorf("%w: version %d has not switched yet, so nothing can have retired the source", ErrConflict, u.Version)
		}
		var acked int
		if err := a.tx.QueryRow("SELECT acked FROM update_participants WHERE boot_id = ?", msg.BootID).Scan(&acked); err != nil {
			return err
		}
		if acked == 0 {
			return fmt.Errorf("%w: %s never acknowledged version %d", ErrConflict, msg.BootID, u.Version)
		}
		if _, err := a.tx.Exec("UPDATE update_participants SET completed = 1 WHERE boot_id = ?", msg.BootID); err != nil {
			return err
		}
		return c.advance(a)
	})
	if err != nil {
		return err
	}
	slog.Info("participant completed the update", "boot_id", msg.BootID, "version", msg.Version, "closed", c.update == nil)
	return nil
}

// advance moves the outstanding update as far as the acknowledgements allow,
// inside the transaction that made the move possible: the switch when every
// frozen participant has acknowledged, then the drain and the release of the
// single-update lock when every one of them has completed.
func (c *Coordinator) advance(a *appender) error {
	u, ok, err := loadUpdate(a.tx)
	if err != nil || !ok {
		return err
	}
	if !u.Switched {
		waiting, err := countRows(a.tx, "SELECT COUNT(*) FROM update_participants WHERE acked = 0")
		if err != nil {
			return err
		}
		if waiting > 0 {
			return nil
		}
		if _, err := a.tx.Exec(`UPDATE "update" SET switched = 1 WHERE id = 1`); err != nil {
			return err
		}
		u.Switched = true
		slog.Info("policy update switched: admission, issuance and secret release now use the target",
			"version", u.Version, "target_digest", u.TargetDigest)
	}
	waiting, err := countRows(a.tx, "SELECT COUNT(*) FROM update_participants WHERE completed = 0")
	if err != nil {
		return err
	}
	if waiting > 0 {
		return nil
	}
	if u.RequiresDrain {
		if err := a.add(policystate.EventDrained, policystate.DrainedPayload{Version: u.Version}); err != nil {
			return err
		}
	}
	if _, err := a.tx.Exec(`DELETE FROM "update"`); err != nil {
		return err
	}
	if _, err := a.tx.Exec("DELETE FROM update_participants"); err != nil {
		return err
	}
	slog.Info("policy update complete", "version", u.Version, "drained", u.RequiresDrain)
	return nil
}

// frozen returns the outstanding update after checking that this boot is one of
// the participants it froze and that the message names that exact update. An
// ack or completion quoting another version could otherwise be counted against
// a publication the sender never saw.
func frozen(tx *sql.Tx, bootID string, version uint64, target string) (policystate.Update, error) {
	u, ok, err := loadUpdate(tx)
	if err != nil {
		return policystate.Update{}, err
	}
	if !ok {
		return policystate.Update{}, fmt.Errorf("%w: no update is outstanding", ErrConflict)
	}
	if version != u.Version || target != u.TargetDigest {
		return policystate.Update{}, fmt.Errorf("%w: message names version %d target %s, the outstanding update is version %d target %s",
			ErrConflict, version, target, u.Version, u.TargetDigest)
	}
	var found int
	if err := tx.QueryRow("SELECT COUNT(*) FROM update_participants WHERE boot_id = ?", bootID).Scan(&found); err != nil {
		return policystate.Update{}, err
	}
	if found == 0 {
		return policystate.Update{}, fmt.Errorf("%w: %s is not a participant of version %d", ErrConflict, bootID, u.Version)
	}
	return u, nil
}

// authenticate checks an envelope against the key the boot id enrolled with.
func authenticate[T any](tx *sql.Tx, bootID string, env policystate.Envelope[T]) error {
	var encoded string
	err := tx.QueryRow("SELECT boot_key FROM participants WHERE boot_id = ?", bootID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("participant %s: %w", bootID, ErrNotFound)
	}
	if err != nil {
		return err
	}
	pub, err := policystate.DecodeBootKey(encoded)
	if err != nil {
		return err
	}
	if err := policystate.VerifyMessage[T](pub, policystate.DomainAck, env); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	return nil
}

// loadUpdate reads the outstanding update row, if there is one.
func loadUpdate(src querier) (policystate.Update, bool, error) {
	var (
		u                 policystate.Update
		requiresDrain, sw int
	)
	err := src.QueryRow(`SELECT version, source, target, requires_drain, switched FROM "update" WHERE id = 1`).
		Scan(&u.Version, &u.SourceDigest, &u.TargetDigest, &requiresDrain, &sw)
	if errors.Is(err, sql.ErrNoRows) {
		return policystate.Update{}, false, nil
	}
	if err != nil {
		return policystate.Update{}, false, err
	}
	u.RequiresDrain, u.Switched = requiresDrain != 0, sw != 0
	return u, true, nil
}

func countRows(tx *sql.Tx, query string) (int, error) {
	var n int
	err := tx.QueryRow(query).Scan(&n)
	return n, err
}

// unacknowledged lists the frozen participants that still owe an ack, in boot
// id order. It is empty once the update has switched.
func unacknowledged(tx *sql.Tx) ([]string, error) {
	rows, err := tx.Query("SELECT boot_id FROM update_participants WHERE acked = 0 ORDER BY boot_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
