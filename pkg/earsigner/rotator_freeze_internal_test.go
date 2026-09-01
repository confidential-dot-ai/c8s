package earsigner

import (
	"context"
	"crypto/ecdsa"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestFreezeWinsAfterTimerWakeBeforeRotationLock(t *testing.T) {
	pemBytes, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRotator(RotatorConfig{
		Interval: time.Millisecond,
		Overlap:  time.Hour,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, pemBytes, func(*ecdsa.PrivateKey, string) {})
	if err != nil {
		t.Fatal(err)
	}
	woke := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	r.beforeRotateLock = func() {
		once.Do(func() {
			close(woke)
			<-release
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	<-woke
	snapshot, err := r.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	time.Sleep(10 * time.Millisecond)
	after, err := r.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if after.Active.KID != snapshot.Active.KID || len(after.Retiring) != len(snapshot.Retiring) {
		t.Fatal("EAR signer changed after the frozen snapshot")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rotation loop did not stop")
	}
}

func TestImmediateFreezeBeforeRunHasRestorableSchedule(t *testing.T) {
	pemBytes, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	cfg := RotatorConfig{Interval: time.Hour, Overlap: time.Minute, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r, err := NewRotator(cfg, pemBytes, func(*ecdsa.PrivateKey, string) {})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := r.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NextRotation.IsZero() {
		t.Fatal("immediate handoff has no next rotation time")
	}
	if _, err := NewRotatorFromSnapshot(cfg, snapshot, func(*ecdsa.PrivateKey, string) {}); err != nil {
		t.Fatalf("restore immediate handoff: %v", err)
	}
}
