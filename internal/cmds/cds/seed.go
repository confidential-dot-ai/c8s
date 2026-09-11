package cds

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// seedStore reads the JSON allowlist at path and seeds its workload entries
// into store. It owns the file/wire-format concerns; the additive,
// version-stable merge is Store.SeedWorkloads.
//
// Seeding runs before the HTTP server serves, so the first GET /allowlist
// reflects the seed. Any error fails closed: CDS must not serve an empty or
// partial allowlist because its seed could not be applied.
func seedStore(store *allowlist.Store, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read allowlist seed %q: %w", path, err)
	}

	seed, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return fmt.Errorf("parse allowlist seed %q: %w", path, err)
	}

	added, err := store.SeedWorkloads(seed.Workloads)
	if err != nil {
		return fmt.Errorf("seed allowlist workloads: %w", err)
	}

	slog.Info("allowlist seeded", "workloads_added", added, "workloads_in_seed", len(seed.Workloads))
	return nil
}
