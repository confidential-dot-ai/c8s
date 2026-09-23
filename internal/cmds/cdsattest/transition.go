package cdsattest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	"github.com/confidential-dot-ai/c8s/pkg/policystateclient"
)

// Enrollment retry bounds. Declared as vars so tests can shrink the wait.
var (
	enrollInitialBackoff = 2 * time.Second
	enrollMaxBackoff     = time.Minute
)

// bootIdentity is this process's participant identity: a fresh Ed25519 key per
// start, whose public half names the boot.
//
// The key is generated, not derived: every input the untrusted host can also
// derive from would authenticate nothing. It is held only in memory, so a
// restarted sidecar is a new boot that re-enrols, and CDS keeps the old boot's
// obligations outstanding — there is no fence that clears them.
//
// FOLLOW-UP the design requires: bind this key to the CVM boot and the
// router's attested identity, so an enrollment proves which hardware boot it
// came from. Until then it is an unauthenticated claim CDS records on first
// use (CONTRACT.md, "Participant messages").
type bootIdentity struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	id      string
	name    string
}

// newBootIdentity generates the boot key. name falls back to the hostname; it
// is informational in the log, the key is the identity.
func newBootIdentity(name string) (bootIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return bootIdentity{}, fmt.Errorf("generate boot key: %w", err)
	}
	if name == "" {
		name, err = os.Hostname()
		if err != nil {
			return bootIdentity{}, fmt.Errorf("participant name: %w", err)
		}
	}
	return bootIdentity{private: priv, public: pub, id: policystate.BootID(pub), name: name}, nil
}

// routerUpdate is what this boot has done about the one update CDS has
// outstanding. V1 serializes updates, so one value is the whole record; a new
// version resets it.
type routerUpdate struct {
	version uint64
	// retired accumulates the sessions the barrier dropped for this update
	// across polls, so a retry that retires nothing still acknowledges what
	// the first pass cost.
	retired   uint64
	acked     bool
	completed bool
}

// updateDriver makes the ingress a participant in the rollout protocol
// (DESIGN2.md, "Internal update coordinator", step 2): it enrols with CDS,
// retires the sessions an outstanding update would widen, acknowledges the
// barrier, and reports completion once the target is in force.
//
// Its acknowledgement covers attest-pq sessions only. attest-lb traffic rides
// nginx TLS straight to the upstream and never reaches this sidecar, so an
// attest-lb deployment gets no session barrier from it and its bundles carry
// no state binding.
//
// The state cache calls it on its own goroutine after each verified refresh,
// so it may block on CDS or on a draining session, but never on a request
// path.
type updateDriver struct {
	client policystateclient.Client
	server *Server
	boot   bootIdentity
	log    *slog.Logger
	now    func() time.Time

	enrolled     bool
	enrollBackon time.Time
	enrollGap    time.Duration
	cur          routerUpdate
}

func newUpdateDriver(client policystateclient.Client, server *Server, boot bootIdentity, logger *slog.Logger) *updateDriver {
	if logger == nil {
		logger = slog.Default()
	}
	return &updateDriver{client: client, server: server, boot: boot, log: logger, now: time.Now}
}

// onState drives one verified statement: install the bound and retire what it
// no longer covers, then tell CDS where this ingress stands.
//
// The barrier runs before the acknowledgement and does not depend on it: an
// ingress CDS is not waiting for still must not hold a session open across a
// widening.
func (d *updateDriver) onState(ctx context.Context, stmt policystate.State) {
	retired := d.server.rebind(policystate.Bound(stmt))
	if retired > 0 {
		d.log.Info("retired sessions whose envelope no longer covers the deployment's policy bound; their clients re-attest",
			"retired_sessions", retired, "active_version", stmt.ActiveVersion)
	}
	if !d.enrolled {
		d.enroll(ctx, stmt)
	}
	if stmt.Update == nil {
		d.cur = routerUpdate{}
		return
	}
	d.track(stmt.Update.Version)
	d.cur.retired += uint64(retired)
	if !stmt.Update.Switched {
		d.ack(ctx, *stmt.Update)
		return
	}
	d.complete(ctx, *stmt.Update)
}

// ack tells CDS this ingress's barrier for the update is in place: new
// sessions carry the source-or-target envelope, and the sessions that held
// source-only permissions are gone, with their in-flight requests finished or
// cancelled.
func (d *updateDriver) ack(ctx context.Context, u policystate.Update) {
	if d.cur.acked {
		return
	}
	if !d.enrolled {
		d.log.Warn("not enrolled with CDS: this ingress's barrier is in place, but CDS will not wait for it before switching",
			"version", u.Version, "boot_id", d.boot.id)
		return
	}
	err := d.client.Ack(ctx, d.boot.private, policystate.Ack{
		Protocol:     policystate.Protocol,
		BootID:       d.boot.id,
		Version:      u.Version,
		TargetDigest: u.TargetDigest,
		Retired:      d.cur.retired,
	})
	if err != nil {
		d.log.Warn("acknowledging the outstanding update failed; retrying", "version", u.Version, "error", err)
		return
	}
	d.cur.acked = true
	d.log.Info("acknowledged the session barrier for an outstanding update; it covers this ingress's attest-pq sessions only, not attest-lb traffic riding nginx TLS to the upstream",
		"version", u.Version, "target_digest", u.TargetDigest, "retired_sessions", d.cur.retired)
}

// complete tells CDS nothing here still needs the source policy. The ingress
// holds no instances: once the switch is in force, the barrier it acknowledged
// is the whole of its drain. A boot that never acknowledged does not report —
// CDS counts completions against the participants its publication froze.
func (d *updateDriver) complete(ctx context.Context, u policystate.Update) {
	if !d.enrolled || !d.cur.acked || d.cur.completed {
		return
	}
	err := d.client.Complete(ctx, d.boot.private, policystate.Completion{
		Protocol:     policystate.Protocol,
		BootID:       d.boot.id,
		Version:      u.Version,
		TargetDigest: u.TargetDigest,
	})
	if err != nil {
		d.log.Warn("reporting completion failed; retrying", "version", u.Version, "error", err)
		return
	}
	d.cur.completed = true
	d.log.Info("reported completion: the ingress holds no instances and its source-only sessions are closed",
		"version", u.Version, "target_digest", u.TargetDigest)
}

// track resets the per-update record when CDS names a different version.
func (d *updateDriver) track(version uint64) {
	if d.cur.version != version {
		d.cur = routerUpdate{version: version}
	}
}

// enroll announces this boot to CDS, naming the policy the verified state
// reports as active. CDS holds a joining participant outside an outstanding
// update, so a 409 is the expected answer during one and costs no backoff: the
// next poll after the update completes enrols. The backoff is what keeps a CDS
// outage from costing one enrollment attempt per poll.
func (d *updateDriver) enroll(ctx context.Context, stmt policystate.State) {
	now := d.now()
	if now.Before(d.enrollBackon) {
		return
	}
	err := d.client.Enroll(ctx, d.boot.private, policystate.Enrollment{
		Protocol:      policystate.Protocol,
		BootID:        d.boot.id,
		Name:          d.boot.name,
		BootKey:       policystate.EncodeBootKey(d.boot.public),
		AppliedDigest: stmt.ActiveDigest,
	})
	switch {
	case err == nil:
		d.enrolled = true
		d.enrollGap = 0
		d.log.Info("enrolled with CDS as an ingress participant",
			"boot_id", d.boot.id, "name", d.boot.name, "applied_digest", stmt.ActiveDigest)
	case policystateclient.IsStatus(err, http.StatusConflict):
		d.log.Info("CDS is holding this ingress outside the participant set until the outstanding update completes",
			"boot_id", d.boot.id)
	default:
		d.enrollGap = nextEnrollGap(d.enrollGap)
		d.enrollBackon = now.Add(d.enrollGap)
		d.log.Warn("enrollment failed: this ingress still retires its source-only sessions, but CDS will not wait for it before switching",
			"boot_id", d.boot.id, "retry_after", d.enrollGap, "error", err)
	}
}

func nextEnrollGap(cur time.Duration) time.Duration {
	if cur <= 0 {
		return enrollInitialBackoff
	}
	return min(cur*2, enrollMaxBackoff)
}
