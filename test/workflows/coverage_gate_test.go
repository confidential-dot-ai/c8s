package workflows

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCoverageGateMeasuresGoExecution(t *testing.T) {
	script, err := filepath.Abs("../../scripts/coverage-gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Go tracks this read so script-only changes invalidate cached test results.
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", "auto")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOSUMDB", "off")
	for _, name := range []string{"coverage includes test-only callers and untested code", "production test fails", "invalid module", "package discovery fails"} {
		t.Run(name, func(t *testing.T) {
			fixture := t.TempDir()
			files := map[string]string{
				"go.mod":              "module fixture.invalid/coverage\n\ngo 1.22\n",
				"go.work":             "go 1.22\nuse (\n .\n ./other-module\n)\n",
				"other-module/go.mod": "module fixture.invalid/other\n\ngo 1.22\n",
				"production/value.go": `package production
func Direct() int { return 1 }
func ViaHarness() int { return 2 }
`,
				"production/value_test.go": `package production
import "testing"
func TestDirect(t *testing.T) { if Direct() != 1 { t.Fatal("wrong result") } }
`,
				"test/goharness/value_test.go": `package goharness
import (
    "testing"
    "fixture.invalid/coverage/production"
)
func TestViaHarness(t *testing.T) { if production.ViaHarness() != 2 { t.Fatal("wrong result") } }
`,
				"untested/value.go": `package untested
func First() int { return 3 }
func Second() int { return 4 }
`,
				"test/workflows/fail_test.go": `package workflows
import "testing"
func TestWorkflow(t *testing.T) { t.Fatal("workflow harness intentionally fails") }
`,
			}
			switch name {
			case "production test fails":
				files["production/fail_test.go"] = "package production\nimport \"testing\"\nfunc TestFailure(t *testing.T) { t.Fatal(\"production failure sentinel\") }\n"
			case "invalid module":
				files["go.mod"] = "module fixture.invalid/coverage\n\ngo invalid\n"
			case "package discovery fails":
				files["broken/first.go"] = "package first\n"
				files["broken/second.go"] = "package second\n"
			}
			for path, contents := range files {
				path = filepath.Join(fixture, path)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			profile := filepath.Join(fixture, "coverage output.out")
			cmd := exec.CommandContext(ctx, "bash", "-c", string(body), script, "run", profile)
			cmd.Dir = fixture
			log, err := cmd.CombinedOutput()
			if name != "coverage includes test-only callers and untested code" {
				if err == nil {
					t.Fatalf("coverage suppressed a Go failure: %s", log)
				}
				if name == "production test fails" && !strings.Contains(string(log), "production failure sentinel") {
					t.Fatalf("coverage failed before reaching the production test: %s", log)
				}
				return
			}
			if err != nil {
				t.Fatalf("coverage executed the unrelated workflow harness: %v\n%s", err, log)
			}
			raw, err := os.ReadFile(profile)
			if err != nil {
				t.Fatal(err)
			}
			blocks := make(map[string]int)
			coveredBlocks := make(map[string]bool)
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n")[1:] {
				fields := strings.Fields(line)
				if len(fields) != 3 {
					t.Fatalf("invalid coverage record: %q", line)
				}
				count, err := strconv.Atoi(fields[1])
				if err != nil {
					t.Fatal(err)
				}
				blocks[fields[0]] = count
				if fields[2] != "0" {
					coveredBlocks[fields[0]] = true
				}
			}
			// -coverpkg emits the same blocks from multiple test binaries.
			// Union their covered blocks, just as the production total does.
			var statements, covered, untested int
			for block, count := range blocks {
				statements += count
				if coveredBlocks[block] {
					covered += count
				}
				if strings.HasPrefix(block, "fixture.invalid/coverage/untested/") {
					untested += count
					if coveredBlocks[block] {
						t.Fatalf("untested production code was reported covered: %q", block)
					}
				}
			}
			// Direct and ViaHarness must both count; two untested statements
			// remain in the denominator despite having no importing tests.
			if statements != 4 || covered != 2 || untested != 2 {
				t.Fatalf("wrong coverage scope: statements=%d covered=%d untested=%d\n%s", statements, covered, untested, raw)
			}
			cmd = exec.CommandContext(ctx, "go", "test", "./test/workflows", "-count=1")
			cmd.Dir = fixture
			log, err = cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(log), "workflow harness intentionally fails") {
				t.Fatalf("fixture workflow harness should still fail a normal test run: err=%v log=%s", err, log)
			}
		})
	}
}
