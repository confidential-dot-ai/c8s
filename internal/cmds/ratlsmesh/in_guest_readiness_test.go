//go:build linux

package ratlsmesh

import (
	"context"
	"net/http"
	"reflect"
	"strconv"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseInboundPassthroughBoundaryPorts(t *testing.T) {
	got, err := parseInboundPassthrough("tcp:1,tcp:65535")
	if err != nil {
		t.Fatalf("boundary ports rejected: %v", err)
	}
	if !reflect.DeepEqual(got, []int{1, 65535}) {
		t.Errorf("got %v, want [1 65535]", got)
	}
}

func TestParseCWPassthroughBoundaryPorts(t *testing.T) {
	got, err := parseCWPassthrough("udp:1,tcp:65535")
	if err != nil {
		t.Fatalf("boundary ports rejected: %v", err)
	}
	want := []cwPassthrough{{protocol: "udp", sourcePort: 1}, {protocol: "tcp", sourcePort: 65535}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// With retries=0 the command must return after exactly one probe, without
// waiting out --retry-wait, and report the probe status in the error.
func TestReadinessCheckExhaustedRetriesReturnsPromptly(t *testing.T) {
	srv := stubReadyServer(t, http.StatusServiceUnavailable)
	defer srv.Close()
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")

	cmd := newReadinessCheckCommand()
	cmd.SetArgs([]string{
		"--health-port", port,
		"--retries", "0",
		"--retry-wait", "30s", // long on purpose: a prompt return must not touch it
		"--timeout", "1s",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error against a 503 endpoint")
		}
		if !strings.Contains(err.Error(), "returned status "+strconv.Itoa(http.StatusServiceUnavailable)) {
			t.Fatalf("error = %v, want the probe status in the message", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("readiness-check did not return promptly after its single allowed probe")
	}
}

func TestReadinessCheckConnectionErrorMessage(t *testing.T) {
	cmd := newReadinessCheckCommand()
	cmd.SetArgs([]string{
		"--health-port", "1",
		"--retries", "0",
		"--retry-wait", "30s",
		"--timeout", "500ms",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error against a closed port")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("error = %v, want a wrapped ECONNREFUSED", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("readiness-check did not return promptly on connection error")
	}
}
