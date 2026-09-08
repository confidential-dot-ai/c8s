package launchvalues

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every allowlisted prefix must name a key the chart declares: the chart's
// values schema rejects unknown keys, so a fragment carrying a stale path
// would pass this allowlist and then fail the baked install at boot.
func TestAllowedPrefixesExistInChartValues(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "helmchart", "c8s", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range allowedPrefixes {
		cur := any(values)
		for _, key := range strings.Split(prefix, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				t.Errorf("%q: %q is not a mapping in values.yaml", prefix, key)
				break
			}
			if cur, ok = m[key]; !ok {
				t.Errorf("%q: key %q is not declared in values.yaml", prefix, key)
				break
			}
		}
	}
}
