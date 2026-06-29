package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

// captureLog swaps the default slog logger for one writing JSON to a buffer,
// runs fn, restores the previous logger, and returns the parsed log record.
func captureLog(t *testing.T, fn func()) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	fn()

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("parse log line %q: %v", buf.String(), err)
	}
	return rec
}

func TestLogIncludesCoreFields(t *testing.T) {
	rec := captureLog(t, func() {
		NewLogger().Log(Event{
			Action:    "deny",
			Reason:    "image not allowlisted",
			Namespace: "default",
			Pod:       "web-0",
			Container: "app",
			Image:     "evil:latest",
		})
	})

	if rec["msg"] != "audit" {
		t.Errorf("msg = %v, want audit", rec["msg"])
	}
	for k, want := range map[string]string{
		"action":    "deny",
		"reason":    "image not allowlisted",
		"namespace": "default",
		"pod":       "web-0",
		"container": "app",
		"image":     "evil:latest",
	} {
		if rec[k] != want {
			t.Errorf("%s = %v, want %q", k, rec[k], want)
		}
	}
}

func TestLogOmitsRuleAndErrorWhenEmpty(t *testing.T) {
	rec := captureLog(t, func() {
		NewLogger().Log(Event{Action: "allow"})
	})
	if _, ok := rec["rule"]; ok {
		t.Error("rule should be omitted when empty")
	}
	if _, ok := rec["error"]; ok {
		t.Error("error should be omitted when empty")
	}
}

func TestLogIncludesRuleAndErrorWhenSet(t *testing.T) {
	rec := captureLog(t, func() {
		NewLogger().Log(Event{Action: "deny", Rule: "label-rule-1", Error: "boom"})
	})
	if rec["rule"] != "label-rule-1" {
		t.Errorf("rule = %v, want label-rule-1", rec["rule"])
	}
	if rec["error"] != "boom" {
		t.Errorf("error = %v, want boom", rec["error"])
	}
}
