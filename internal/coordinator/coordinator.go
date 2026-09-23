package coordinator

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	_ "modernc.org/sqlite"
)

// Options configures a Coordinator. The zero value is usable: the deployment id
// is generated and the clock is time.Now.
type Options struct {
	// DeploymentID names the deployment in every signed statement. Empty
	// generates one. It is recorded when the database is created and may not
	// change afterwards: verifiers pin it.
	DeploymentID string
	// Now is the clock for entry timestamps and IssuedAt. Nil means time.Now.
	Now func() time.Time
}

// Coordinator owns one deployment's journal, signing key and update state.
// Every method is safe for concurrent use; writes serialize on one transaction
// at a time.
type Coordinator struct {
	mu sync.Mutex
	db *sql.DB

	now          func() time.Time
	deploymentID string

	// signingKey is this process's authority. It is generated at Open and
	// never written anywhere, so it dies with the process.
	signingKey ed25519.PrivateKey
	authority  string

	// head is the last journal entry and its digest, the link every append
	// extends. Both are zero until the first entry.
	head       *policystate.Entry
	headDigest string

	// published is the newest published version and the policy digest it
	// named; 0 and empty before the first publication.
	published       uint64
	publishedDigest string
	// publishedSource and publishedRequiresDrain are the rest of the newest
	// published entry, the values the private update row must agree with.
	publishedSource        string
	publishedRequiresDrain bool
	// drained is the newest version a drained entry closed, 0 when none has.
	drained uint64
	// update mirrors the one outstanding update row, nil when there is none.
	update *policystate.Update

	// generation counts committed changes, so a reader memoizing a view
	// derived from the active policy can tell when to rebuild. A switch moves
	// the active policy without appending an entry, so the journal position
	// cannot serve as this counter.
	generation uint64
}

// Open opens or creates the database at path and verifies it.
//
// Verification is fail-closed and has no repair path: a chain that does not
// recompute, a gap in the positions, a parent that does not match, or private
// state that disagrees with the journal head means the database was edited
// underneath CDS, and serving from it would tell verifiers a history that never
// happened.
func Open(path string, opts Options) (*Coordinator, error) {
	if path == "" {
		return nil, fmt.Errorf("coordinator: a database path is required (use OpenInMemory for a deployment with no durable storage)")
	}
	return open(path, opts)
}

// OpenInMemory opens a coordinator that lives only as long as the process.
func OpenInMemory(opts Options) (*Coordinator, error) {
	return open(":memory:", opts)
}

func open(path string, opts Options) (*Coordinator, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("coordinator: generate authority key: %w", err)
	}
	authority, err := policystate.AuthorityFingerprint(pub)
	if err != nil {
		return nil, fmt.Errorf("coordinator: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open coordinator database %q: %w", path, err)
	}
	// One connection: an in-memory database is per-connection, and every access
	// is already serialized by c.mu, so a pool would buy nothing but
	// SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(initSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("init coordinator schema %q: %w", path, err)
	}

	c := &Coordinator{db: db, now: opts.Now, signingKey: priv, authority: authority}
	if c.now == nil {
		c.now = time.Now
	}
	if err := c.start(path, opts.DeploymentID); err != nil {
		db.Close()
		return nil, fmt.Errorf("coordinator database %q: %w", path, err)
	}
	slog.Info("coordinator opened",
		"path", path, "authority", c.authority, "deployment_id", c.deploymentID,
		"log_position", c.position(), "published_version", c.published)
	return c, nil
}

// start verifies the journal, resolves the deployment id and loads the private
// update state.
func (c *Coordinator) start(path, configured string) error {
	if err := c.loadJournal(); err != nil {
		return err
	}
	if err := c.resolveDeploymentID(configured); err != nil {
		return err
	}
	if err := c.refresh(); err != nil {
		return err
	}
	return c.checkUpdate(path)
}

// loadJournal reads every entry in position order and checks that it is the
// chain it claims to be: dense positions, each entry valid on its own and
// hashing to the digest it is stored under, each naming its predecessor.
func (c *Coordinator) loadJournal() error {
	// The whole index is read before any entry is fetched: the pool holds one
	// connection, so a lookup while the rows are open would wait on itself.
	index, err := c.journalIndex()
	if err != nil {
		return err
	}

	var (
		want uint64 = 1
		prev string
	)
	for _, row := range index {
		position, digest := row.position, row.digest
		if position != want {
			return fmt.Errorf("journal jumps from position %d to %d: the chain has a gap", want-1, position)
		}
		raw, err := loadObject(c.db, digest)
		if err != nil {
			return fmt.Errorf("journal position %d: %w", position, err)
		}
		var entry policystate.Entry
		if err := policystate.Decode(raw, &entry); err != nil {
			return fmt.Errorf("entry %s does not parse: %w", digest, err)
		}
		if err := policystate.ValidateEntry(entry); err != nil {
			return fmt.Errorf("entry %s: %w", digest, err)
		}
		got, err := policystate.EntryDigest(entry)
		if err != nil {
			return err
		}
		if got != digest {
			return fmt.Errorf("entry stored as %s hashes to %s: the journal was modified outside CDS", digest, got)
		}
		if entry.Position != position {
			return fmt.Errorf("entry %s carries position %d but is stored at %d", digest, entry.Position, position)
		}
		if entry.Parent != prev {
			return fmt.Errorf("entry %s names parent %q, but its predecessor is %q", digest, entry.Parent, prev)
		}
		if err := c.applyEntry(entry); err != nil {
			return fmt.Errorf("entry %s: %w", digest, err)
		}
		c.head, c.headDigest = &entry, digest
		prev, want = digest, position+1
	}
	if len(index) > 0 && c.published == 0 {
		return fmt.Errorf("the journal has %d entries but no publication", len(index))
	}
	return nil
}

// journalRow is one journal index row: a position and the entry it names.
type journalRow struct {
	position uint64
	digest   string
}

func (c *Coordinator) journalIndex() ([]journalRow, error) {
	rows, err := c.db.Query("SELECT position, digest FROM journal ORDER BY position")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var index []journalRow
	for rows.Next() {
		var row journalRow
		if err := rows.Scan(&row.position, &row.digest); err != nil {
			return nil, err
		}
		index = append(index, row)
	}
	return index, rows.Err()
}

// applyEntry folds one verified entry into the publication head. It is the only
// thing derived from the journal: everything else the coordinator needs is in
// the private tables.
func (c *Coordinator) applyEntry(e policystate.Entry) error {
	switch e.Type {
	case policystate.EventPublished:
		payload, err := policystate.DecodePayload[policystate.PublishedPayload](e)
		if err != nil {
			return err
		}
		if payload.Version != c.published+1 {
			return fmt.Errorf("publishes version %d after version %d", payload.Version, c.published)
		}
		if payload.SourceDigest != c.publishedDigest {
			return fmt.Errorf("names source %q, but the previous publication was %q", payload.SourceDigest, c.publishedDigest)
		}
		c.published, c.publishedDigest = payload.Version, payload.TargetDigest
		c.publishedSource, c.publishedRequiresDrain = payload.SourceDigest, payload.RequiresDrain
	case policystate.EventDrained:
		payload, err := policystate.DecodePayload[policystate.DrainedPayload](e)
		if err != nil {
			return err
		}
		if payload.Version != c.published {
			return fmt.Errorf("drains version %d, but the newest publication is %d", payload.Version, c.published)
		}
		c.drained = payload.Version
	}
	return nil
}

// checkUpdate rejects a private update row that does not describe the journal's
// newest publication. The row is the coordinator's own state, so an operator
// who edits or replaces it must not be able to make CDS advertise a bound the
// journal never recorded.
func (c *Coordinator) checkUpdate(path string) error {
	if c.update == nil {
		return nil
	}
	u := c.update
	switch {
	case u.Version != c.published:
		return fmt.Errorf("the outstanding update is version %d, but the journal's newest publication is %d. Start from an empty database", u.Version, c.published)
	case u.TargetDigest != c.publishedDigest:
		return fmt.Errorf("the outstanding update targets %s, but version %d published %s", u.TargetDigest, u.Version, c.publishedDigest)
	case u.SourceDigest != c.publishedSource:
		return fmt.Errorf("the outstanding update names source %s, but version %d was published over %s", u.SourceDigest, u.Version, c.publishedSource)
	case u.RequiresDrain != c.publishedRequiresDrain:
		return fmt.Errorf("the outstanding update says requires_drain=%v, but version %d recorded %v", u.RequiresDrain, u.Version, c.publishedRequiresDrain)
	case c.drained >= u.Version:
		return fmt.Errorf("version %d is recorded as drained, so no update for it may be outstanding", u.Version)
	}
	var orphans int
	if err := c.db.QueryRow(
		"SELECT COUNT(*) FROM update_participants WHERE boot_id NOT IN (SELECT boot_id FROM participants)").Scan(&orphans); err != nil {
		return err
	}
	if orphans > 0 {
		return fmt.Errorf("update %d froze %d participant(s) the participant table does not hold", u.Version, orphans)
	}
	slog.Warn("resuming an outstanding policy update; it blocks every further publication until each frozen participant completes",
		"path", path, "version", u.Version, "switched", u.Switched, "requires_drain", u.RequiresDrain)
	return nil
}

// resolveDeploymentID keeps the recorded id authoritative. A configured id that
// disagrees is a configuration error, not an override: changing it would
// silently invalidate every verifier's pin.
func (c *Coordinator) resolveDeploymentID(configured string) error {
	var stored string
	err := c.db.QueryRow("SELECT deployment_id FROM meta WHERE id = 1").Scan(&stored)
	switch {
	case err == nil:
		if configured != "" && configured != stored {
			return fmt.Errorf("deployment id %q was recorded when this database was created; %q was configured. Keep the recorded id or start from an empty database", stored, configured)
		}
		c.deploymentID = stored
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	c.deploymentID = configured
	if c.deploymentID == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return fmt.Errorf("generate deployment id: %w", err)
		}
		c.deploymentID = hex.EncodeToString(raw)
	}
	_, err = c.db.Exec("INSERT INTO meta (id, deployment_id) VALUES (1, ?)", c.deploymentID)
	return err
}

// Close releases the database.
func (c *Coordinator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.db == nil {
		return nil
	}
	return c.db.Close()
}

// DeploymentID is the identifier every signed statement carries.
func (c *Coordinator) DeploymentID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deploymentID
}

// Authority is the fingerprint of this process's state signing key. It changes
// on every restart.
func (c *Coordinator) Authority() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authority
}

// Generation counts committed changes: a publication, a switch, a completion or
// an enrollment. A reader that memoizes a view of the active policy rebuilds it
// when this moves.
func (c *Coordinator) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

// Head is the publication head: the newest published version and the entry the
// journal currently ends at. Version is 0 before the first publication. It says
// what was published, not what any participant applied.
func (c *Coordinator) Head() policystate.Head {
	c.mu.Lock()
	defer c.mu.Unlock()
	return policystate.Head{
		Authority:    c.authority,
		Version:      c.published,
		PolicyDigest: c.publishedDigest,
		LogHead:      c.headDigest,
	}
}

// Object returns the exact stored bytes of a content-addressed object: a policy
// document or a journal entry.
func (c *Coordinator) Object(digest string) ([]byte, error) {
	if _, err := policystate.ParseHash(digest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return loadObject(c.db, digest)
}

// position is the journal head's position, 0 before the first entry.
func (c *Coordinator) position() uint64 {
	if c.head == nil {
		return 0
	}
	return c.head.Position
}

// refresh reloads the private update row into memory. Callers hold c.mu.
func (c *Coordinator) refresh() error {
	var (
		u                 policystate.Update
		requiresDrain, sw int
	)
	err := c.db.QueryRow(`SELECT version, source, target, requires_drain, switched FROM "update" WHERE id = 1`).
		Scan(&u.Version, &u.SourceDigest, &u.TargetDigest, &requiresDrain, &sw)
	if errors.Is(err, sql.ErrNoRows) {
		c.update = nil
		return nil
	}
	if err != nil {
		return err
	}
	u.RequiresDrain, u.Switched = requiresDrain != 0, sw != 0
	c.update = &u
	return nil
}

// appender appends entries inside one transaction, threading the chain link
// from one to the next so a transaction may append several.
type appender struct {
	c      *Coordinator
	tx     *sql.Tx
	head   *policystate.Entry
	digest string
}

// add appends one entry: it stores the canonical bytes as an object, since an
// entry is fetched by content digest like any other, and records its position.
func (a *appender) add(typ policystate.EventType, payload any) error {
	entry, err := policystate.NewEntryAt(a.head, a.digest, a.c.authority, typ, payload, a.c.now())
	if err != nil {
		return err
	}
	raw, err := policystate.Canonical(entry)
	if err != nil {
		return err
	}
	digest, err := putObject(a.tx, raw)
	if err != nil {
		return err
	}
	if _, err := a.tx.Exec("INSERT INTO journal (position, digest) VALUES (?, ?)", entry.Position, digest); err != nil {
		return err
	}
	a.head, a.digest = &entry, digest
	return nil
}

// write runs fn in one transaction and publishes its effects: the in-memory
// head, the update mirror and the generation move only once the rows are
// durable.
func (c *Coordinator) write(fn func(a *appender) error) error {
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	a := &appender{c: c, tx: tx, head: c.head, digest: c.headDigest}
	if err := fn(a); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	c.head, c.headDigest = a.head, a.digest
	c.generation++
	return c.refresh()
}

// querier is the subset of *sql.DB and *sql.Tx the lookups need.
type querier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// putObject stores content-addressed bytes and returns their digest. Storing
// the same object twice is a no-op: the digest names the bytes.
func putObject(tx *sql.Tx, data []byte) (string, error) {
	digest := policystate.ContentDigest(data)
	_, err := tx.Exec("INSERT OR IGNORE INTO objects (digest, bytes) VALUES (?, ?)", digest, data)
	return digest, err
}

func loadObject(src querier, digest string) ([]byte, error) {
	var data []byte
	err := src.QueryRow("SELECT bytes FROM objects WHERE digest = ?", digest).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("object %s: %w", digest, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}
