//go:build linux

package rtmr3measurer

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// logLine is the subset of a JSON log record these tests decode.
type logLine struct {
	Level               string `json:"level"`
	Msg                 string `json:"msg"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
}

func decodeLogLines(t *testing.T, buf *bytes.Buffer) []logLine {
	t.Helper()
	var lines []logLine
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for dec.More() {
		var l logLine
		if err := dec.Decode(&l); err != nil {
			t.Fatalf("decode log line: %v", err)
		}
		lines = append(lines, l)
	}
	return lines
}

func linesWithMsg(lines []logLine, msg string) []logLine {
	var out []logLine
	for _, l := range lines {
		if l.Msg == msg {
			out = append(out, l)
		}
	}
	return out
}

// The cannot-read-watch-dir warning fires on the first failure and again after
// every readDirWarnEvery consecutive failures, carrying the running count.
func TestScanWarnsThrottledOnUnreadableWatchDir(t *testing.T) {
	var buf bytes.Buffer
	m := newMeasurer(slog.New(slog.NewJSONHandler(&buf, nil)))
	m.watchDir = filepath.Join(t.TempDir(), "missing")

	const msg = "cannot read watch dir"
	m.scanOnce()
	warns := linesWithMsg(decodeLogLines(t, &buf), msg)
	if len(warns) != 1 {
		t.Fatalf("warns after first failure = %d, want 1", len(warns))
	}
	if warns[0].ConsecutiveFailures != 1 {
		t.Fatalf("consecutive_failures = %d, want 1", warns[0].ConsecutiveFailures)
	}

	for range 60 {
		m.scanOnce()
	}
	warns = linesWithMsg(decodeLogLines(t, &buf), msg)
	if len(warns) != 2 {
		t.Fatalf("warns after 61 failures = %d, want 2 (throttled to one per %d scans)", len(warns), readDirWarnEvery)
	}
	if warns[1].ConsecutiveFailures != 61 {
		t.Fatalf("second warn consecutive_failures = %d, want 61", warns[1].ConsecutiveFailures)
	}
}

// A successful record appends to both the on-disk log and the in-memory order.
func TestRecordAppendsLogAndOrder(t *testing.T) {
	m := newMeasurer(slog.Default())
	m.statePath = filepath.Join(t.TempDir(), "measured")
	dA, dB := "sha256:"+hexA, "sha256:"+hexB

	if err := m.record(dA); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := m.record(dB); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(m.measuredOrder) != 2 || m.measuredOrder[0] != dA || m.measuredOrder[1] != dB {
		t.Fatalf("measuredOrder = %v, want [%s %s]", m.measuredOrder, dA, dB)
	}
	b, err := os.ReadFile(m.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := dA + "\n" + dB + "\n"; string(b) != want {
		t.Fatalf("log = %q, want %q", b, want)
	}
}

func TestUnrecordLast(t *testing.T) {
	dA, dB := "sha256:"+hexA, "sha256:"+hexB
	const failMsg = "rewrite measured-digest log failed"

	t.Run("empty order rewrites an empty log", func(t *testing.T) {
		var buf bytes.Buffer
		m := newMeasurer(slog.New(slog.NewJSONHandler(&buf, nil)))
		m.statePath = filepath.Join(t.TempDir(), "measured")

		m.unrecordLast(dA)
		if len(m.measuredOrder) != 0 {
			t.Fatalf("measuredOrder = %v, want empty", m.measuredOrder)
		}
		b, err := os.ReadFile(m.statePath)
		if err != nil || len(b) != 0 {
			t.Fatalf("log = %q, %v; want empty file", b, err)
		}
		if got := linesWithMsg(decodeLogLines(t, &buf), failMsg); len(got) != 0 {
			t.Fatalf("rewrite error logged on the happy path: %v", got)
		}
	})

	t.Run("successful trim logs no error", func(t *testing.T) {
		var buf bytes.Buffer
		m := newMeasurer(slog.New(slog.NewJSONHandler(&buf, nil)))
		m.statePath = filepath.Join(t.TempDir(), "measured")
		if err := os.WriteFile(m.statePath, []byte(dA+"\n"+dB+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		m.measuredOrder = []string{dA, dB}

		m.unrecordLast(dB)
		if len(m.measuredOrder) != 1 || m.measuredOrder[0] != dA {
			t.Fatalf("measuredOrder = %v, want [%s]", m.measuredOrder, dA)
		}
		b, err := os.ReadFile(m.statePath)
		if err != nil || string(b) != dA+"\n" {
			t.Fatalf("log = %q, %v; want %q", b, err, dA+"\n")
		}
		if got := linesWithMsg(decodeLogLines(t, &buf), failMsg); len(got) != 0 {
			t.Fatalf("rewrite error logged on the happy path: %v", got)
		}
	})
}
