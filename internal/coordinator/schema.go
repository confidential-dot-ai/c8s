package coordinator

// initSQL creates every table.
//
// objects and journal are the public history: an object is named by the hash of
// its bytes, and the journal is only the ordered list of the entry objects that
// chain it. meta records the deployment id verifiers pin.
//
// The rest is private coordinator state, not part of the journal and not
// trustworthy merely because it was stored: participants and the one
// outstanding update with its frozen acknowledgement set. Open checks it
// against the journal head rather than replaying anything from it.
//
// "update" is quoted at every use because UPDATE is a SQL keyword.
const initSQL = `
CREATE TABLE IF NOT EXISTS objects (
	digest TEXT PRIMARY KEY,
	bytes  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS journal (
	position INTEGER PRIMARY KEY,
	digest   TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS meta (
	id            INTEGER PRIMARY KEY CHECK (id = 1),
	deployment_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS participants (
	boot_id        TEXT PRIMARY KEY,
	name           TEXT NOT NULL,
	boot_key       TEXT NOT NULL,
	applied_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS "update" (
	id             INTEGER PRIMARY KEY CHECK (id = 1),
	version        INTEGER NOT NULL,
	source         TEXT NOT NULL,
	target         TEXT NOT NULL,
	requires_drain INTEGER NOT NULL,
	switched       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS update_participants (
	boot_id   TEXT PRIMARY KEY,
	acked     INTEGER NOT NULL DEFAULT 0,
	completed INTEGER NOT NULL DEFAULT 0
);
`
