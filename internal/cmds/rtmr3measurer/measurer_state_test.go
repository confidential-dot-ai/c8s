//go:build linux

package rtmr3measurer

import (
	"bytes"
	"encoding/json"
	"log/slog"
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
