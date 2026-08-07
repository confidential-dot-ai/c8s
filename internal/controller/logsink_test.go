package controller

import (
	"sync"

	"github.com/go-logr/logr"
)

// logEntry is one captured log call with its merged key/values.
type logEntry struct {
	err error
	msg string
	kv  map[string]any
}

// logRecorder collects every entry logged through logger(); entries are also
// mirrored onto ch so tests can wait for asynchronous log output.
type logRecorder struct {
	mu      sync.Mutex
	entries []logEntry
	ch      chan logEntry
}

func newLogRecorder() *logRecorder {
	return &logRecorder{ch: make(chan logEntry, 64)}
}

func (r *logRecorder) logger() logr.Logger {
	return logr.New(&captureSink{rec: r})
}

func (r *logRecorder) record(e logEntry) {
	r.mu.Lock()
	r.entries = append(r.entries, e)
	r.mu.Unlock()
	select {
	case r.ch <- e:
	default:
	}
}

// find returns the first entry with the given message.
func (r *logRecorder) find(msg string) (logEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if e.msg == msg {
			return e, true
		}
	}
	return logEntry{}, false
}

// captureSink is a logr.LogSink feeding a logRecorder.
type captureSink struct {
	rec *logRecorder
	kv  []any
}

func (c *captureSink) Init(logr.RuntimeInfo) {}

func (c *captureSink) Enabled(int) bool { return true }

func (c *captureSink) Info(_ int, msg string, kv ...any) {
	c.rec.record(logEntry{msg: msg, kv: kvMap(c.kv, kv)})
}

func (c *captureSink) Error(err error, msg string, kv ...any) {
	c.rec.record(logEntry{err: err, msg: msg, kv: kvMap(c.kv, kv)})
}

func (c *captureSink) WithValues(kv ...any) logr.LogSink {
	merged := make([]any, 0, len(c.kv)+len(kv))
	merged = append(merged, c.kv...)
	merged = append(merged, kv...)
	return &captureSink{rec: c.rec, kv: merged}
}

func (c *captureSink) WithName(string) logr.LogSink { return c }

func kvMap(base, extra []any) map[string]any {
	m := make(map[string]any, (len(base)+len(extra))/2)
	for _, pairs := range [][]any{base, extra} {
		for i := 0; i+1 < len(pairs); i += 2 {
			if k, ok := pairs[i].(string); ok {
				m[k] = pairs[i+1]
			}
		}
	}
	return m
}
