// Package audit provides structured audit logging for policy decisions.
package audit

import "log/slog"

// Event represents an audit log entry.
type Event struct {
	Action    string // allow, deny
	Reason    string
	Rule      string // label rule name, if any
	Namespace string
	Pod       string
	Container string
	Image     string
	Error     string
}

// Logger writes audit events to stdout via slog.
type Logger struct{}

// NewLogger creates a new audit logger.
func NewLogger() *Logger {
	return &Logger{}
}

// Log writes an audit event as a structured slog message.
func (l *Logger) Log(event Event) {
	attrs := []any{
		"action", event.Action,
		"reason", event.Reason,
		"namespace", event.Namespace,
		"pod", event.Pod,
		"container", event.Container,
		"image", event.Image,
	}
	if event.Rule != "" {
		attrs = append(attrs, "rule", event.Rule)
	}
	if event.Error != "" {
		attrs = append(attrs, "error", event.Error)
	}
	slog.Info("audit", attrs...)
}
