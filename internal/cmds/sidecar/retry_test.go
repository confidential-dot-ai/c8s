package sidecar

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestRetryRecoversOnceReleased(t *testing.T) {
	var calls int
	err := Retry(context.Background(), testConfig("https://cds.example"), "volume", func(context.Context) error {
		calls++
		if calls < 3 {
			return errNotYet
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if calls != 3 {
		t.Fatalf("attempted %d times, want 3", calls)
	}
}

func TestRetryGivesUp(t *testing.T) {
	cfg := testConfig("https://cds.example")
	var calls int
	err := Retry(context.Background(), cfg, "volume", func(context.Context) error {
		calls++
		return errNotYet
	})
	if err == nil {
		t.Fatal("retry never gave up")
	}
	if calls != cfg.Attempts {
		t.Fatalf("attempted %d times, want %d", calls, cfg.Attempts)
	}
}

// A Terminal error stops the loop on its first attempt, and reaches the caller
// intact through the wrapping an attempt does on the way out.
func TestRetryStopsOnATerminalError(t *testing.T) {
	cfg := testConfig("https://cds.example")
	var calls int
	err := Retry(context.Background(), cfg, "secret", func(context.Context) error {
		calls++
		return fmt.Errorf("secret /api/db: %w", Terminal(errNotYet))
	})
	if err == nil {
		t.Fatal("a terminal error was treated as success")
	}
	if !errors.Is(err, errNotYet) {
		t.Fatalf("err = %v, want the wrapped cause", err)
	}
	if calls != 1 {
		t.Fatalf("attempted %d times, want to stop after the first", calls)
	}
}

func TestRetryStopsWhenTheContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Retry(ctx, testConfig("https://cds.example"), "volume", func(context.Context) error {
		return errNotYet
	})
	if err == nil {
		t.Fatal("retry ignored a cancelled context")
	}
}

var errNotYet = &notYetError{}

type notYetError struct{}

func (*notYetError) Error() string { return "not released yet" }
