package whitelist

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/lunal-dev/c8s/pkg/types"
	_ "modernc.org/sqlite"
)

// Store provides persistent storage for the image digest whitelist using SQLite.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

const initSQL = `
CREATE TABLE IF NOT EXISTS whitelist (
	digest TEXT PRIMARY KEY,
	image  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS whitelist_version (
	version TEXT NOT NULL DEFAULT '1'
);
INSERT INTO whitelist_version (version)
	SELECT '1' WHERE NOT EXISTS (SELECT 1 FROM whitelist_version);
`

// OpenStore opens (or creates) a SQLite-backed whitelist store at the given path.
func OpenStore(path string) (Store, error) {
	_, err := os.Stat(path)
	isNew := os.IsNotExist(err)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return Store{}, fmt.Errorf("open whitelist db: %w", err)
	}

	if isNew {
		slog.Warn("WHITELIST DATABASE DID NOT EXIST, CREATING NEW FILE", "path", path)
	}

	if _, err := db.Exec(initSQL); err != nil {
		db.Close()
		return Store{}, fmt.Errorf("init whitelist schema: %w", err)
	}

	return Store{db: db}, nil
}

// OpenInMemory opens an in-memory whitelist store, useful for testing.
func OpenInMemory() (Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return Store{}, err
	}

	initMemSQL := `
CREATE TABLE whitelist (
	digest TEXT PRIMARY KEY,
	image  TEXT NOT NULL
);
CREATE TABLE whitelist_version (
	version TEXT NOT NULL DEFAULT '1'
);
INSERT INTO whitelist_version (version) VALUES ('1');
`
	if _, err := db.Exec(initMemSQL); err != nil {
		db.Close()
		return Store{}, err
	}

	return Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// row holds a single row from the whitelist query.
type row struct {
	version   string
	digestStr sql.NullString
	image     sql.NullString
}

// ListAll returns the current version string and all whitelisted digests.
// The mutex is only held while reading rows from SQLite; parsing happens outside the lock.
func (s *Store) ListAll() (string, map[types.Digest]string, error) {
	rawRows, err := s.queryAll()
	if err != nil {
		return "", nil, err
	}

	version := "1"
	digests := make(map[types.Digest]string, len(rawRows))
	for _, r := range rawRows {
		version = r.version
		if r.digestStr.Valid && r.image.Valid {
			d, err := types.ParseDigest(r.digestStr.String)
			if err != nil {
				// Data was validated on insert; skip corrupt rows
				continue
			}
			digests[d] = r.image.String
		}
	}

	return version, digests, nil
}

// queryAll reads all rows under the lock and returns them as a slice.
func (s *Store) queryAll() ([]row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`
		SELECT wv.version, w.digest, w.image
		FROM whitelist_version wv
		LEFT JOIN whitelist w ON 1=1
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.version, &r.digestStr, &r.image); err != nil {
			return nil, err
		}
		result = append(result, r)
	}

	return result, rows.Err()
}

// Add inserts or replaces a digest in the whitelist and increments the version.
func (s *Store) Add(digest types.Digest, image string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		"INSERT OR REPLACE INTO whitelist (digest, image) VALUES (?, ?)",
		digest.String(), image,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		"UPDATE whitelist_version SET version = CAST(CAST(version AS INTEGER) + 1 AS TEXT)",
	); err != nil {
		return err
	}

	return tx.Commit()
}

// Delete removes all given digests atomically. Returns false (and deletes nothing)
// if any digest is not present.
func (s *Store) Delete(digests []types.Digest) (bool, error) {
	if len(digests) == 0 {
		return true, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	placeholders := make([]string, len(digests))
	args := make([]any, len(digests))
	for i, d := range digests {
		placeholders[i] = "?"
		args[i] = d.String()
	}
	inClause := strings.Join(placeholders, ", ")

	var count int
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM whitelist WHERE digest IN (%s)", inClause)
	if err := tx.QueryRow(countSQL, args...).Scan(&count); err != nil {
		return false, err
	}

	if count != len(digests) {
		return false, nil
	}

	deleteSQL := fmt.Sprintf("DELETE FROM whitelist WHERE digest IN (%s)", inClause)
	if _, err := tx.Exec(deleteSQL, args...); err != nil {
		return false, err
	}

	if _, err := tx.Exec(
		"UPDATE whitelist_version SET version = CAST(CAST(version AS INTEGER) + 1 AS TEXT)",
	); err != nil {
		return false, err
	}

	return true, tx.Commit()
}
