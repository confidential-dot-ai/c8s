package cds

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/lunal-dev/c8s/internal/whitelist"
	"github.com/lunal-dev/c8s/pkg/types"
	pkgwhitelist "github.com/lunal-dev/c8s/pkg/whitelist"
)

// seedStore reads the JSON whitelist at path and seeds its digests into store.
// It owns the file/wire-format concerns; the additive, version-stable merge is
// Store.SeedDigests.
//
// Seeding runs before the HTTP server serves, so the first GET /whitelist
// reflects the seed. Any error fails closed: CDS must not serve an empty or
// partial allowlist because its seed could not be applied.
func seedStore(store *whitelist.Store, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read whitelist seed %q: %w", path, err)
	}

	seed, err := pkgwhitelist.ParseJSON(data)
	if err != nil {
		return fmt.Errorf("parse whitelist seed %q: %w", path, err)
	}

	digests := make(map[types.Digest]string, len(seed.Digests))
	for digestStr, image := range seed.Digests {
		digest, err := types.ParseDigest(digestStr)
		if err != nil {
			// ParseJSON already validated every key; treat a parse failure
			// here as a hard error rather than silently skipping a digest.
			return fmt.Errorf("seed digest %q: %w", digestStr, err)
		}
		digests[digest] = image
	}

	added, err := store.SeedDigests(digests)
	if err != nil {
		return fmt.Errorf("seed whitelist store: %w", err)
	}

	slog.Info("whitelist seeded", "added", added, "in_seed", len(seed.Digests), "already_present", len(seed.Digests)-added)
	return nil
}
