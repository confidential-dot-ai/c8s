package ratls

import (
	"context"
	"time"
)

// RunRotation renews certificates independently of handshakes until ctx ends.
// Run one worker per manager, including when initial WarmUp fails.
func (m *CertManager) RunRotation(ctx context.Context) {
	s := m.state
	s.mu.Lock()
	if s.rotationChanged == nil {
		s.rotationChanged = make(chan struct{}, 1)
	}
	changed := s.rotationChanged
	s.mu.Unlock()
	defer s.stopRotation(changed)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for ctx.Err() == nil {
		s.mu.RLock()
		deadline := s.rotateAt
		if s.cert != nil && s.cert.Leaf.NotAfter.Before(deadline) {
			deadline = s.cert.Leaf.NotAfter
		}
		if s.retryAt.After(deadline) {
			deadline = s.retryAt
		}
		provider, revision := s.provider, s.revision
		s.mu.RUnlock()
		timer.Reset(time.Until(deadline))
		if s.rotating.Load() {
			timer.Stop()
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
			continue
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		rotationCtx, started := s.beginRotationLocked(ctx, revision)
		s.mu.Unlock()
		if !started {
			continue
		}
		s.backgroundProvision(rotationCtx, provider, revision)
	}
}

func (s *certState) notifyRotationLocked() {
	select {
	case s.rotationChanged <- struct{}{}:
	default:
	}
}

func (s *certState) certificateInstalledLocked() {
	s.revision++
	s.retryAt = time.Time{}
	if s.retryBackoff != nil {
		s.retryBackoff.Reset()
	}
	s.notifyRotationLocked()
}

func (s *certState) beginRotationLocked(ctx context.Context, revision uint64) (context.Context, bool) {
	if ctx.Err() != nil || s.revision != revision || time.Now().Before(s.retryAt) || !s.rotating.CompareAndSwap(false, true) {
		return nil, false
	}
	rotationCtx, cancel := context.WithCancel(ctx)
	s.rotationCancel = cancel
	return rotationCtx, true
}

func (s *certState) stopRotation(changed <-chan struct{}) {
	s.mu.Lock()
	if s.rotationCancel != nil {
		s.rotationCancel()
	}
	s.mu.Unlock()
	for s.rotating.Load() {
		<-changed
	}
}

func (s *certState) requestRotation(provider CertProvider, revision uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationChanged != nil {
		s.notifyRotationLocked()
		return
	}
	if ctx, started := s.beginRotationLocked(context.Background(), revision); started {
		go s.backgroundProvision(ctx, provider, revision)
	}
}
