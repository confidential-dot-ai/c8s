package secrets

import (
	"context"
	"strconv"
	"sync"
)

// memProvider is the in-memory Provider used by tests and the e2e lane until a
// real adapter lands. Versions are a per-path counter starting at 1.
type memProvider struct {
	mu     sync.RWMutex
	byPath map[string][]Secret // path -> versions, oldest first
}

// NewMemProvider returns a Provider seeded with the given values, each at
// version 1. The seed is copied, so a caller cannot mutate stored data.
func NewMemProvider(seed map[string][]byte) Provider {
	p := &memProvider{byPath: make(map[string][]Secret, len(seed))}
	for path, data := range seed {
		p.byPath[path] = []Secret{{Path: path, Version: "1", Data: copyOf(data)}}
	}
	return p
}

func (p *memProvider) Get(_ context.Context, path, version string) (Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.get(path, version)
}

func (p *memProvider) GetMany(_ context.Context, refs []Ref) ([]Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Secret, 0, len(refs))
	for _, r := range refs {
		s, err := p.get(r.Path, r.Version)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (p *memProvider) Put(_ context.Context, path string, data []byte) (Secret, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Secret{
		Path:    path,
		Version: strconv.Itoa(len(p.byPath[path]) + 1),
		Data:    copyOf(data),
	}
	p.byPath[path] = append(p.byPath[path], s)
	return Secret{Path: s.Path, Version: s.Version, Data: copyOf(s.Data)}, nil
}

func (p *memProvider) Close() error { return nil }

// get resolves one path/version under the caller's lock. Version "" is the
// latest.
func (p *memProvider) get(path, version string) (Secret, error) {
	versions := p.byPath[path]
	if len(versions) == 0 {
		return Secret{}, ErrNotFound
	}
	if version == "" {
		s := versions[len(versions)-1]
		return Secret{Path: s.Path, Version: s.Version, Data: copyOf(s.Data)}, nil
	}
	for _, s := range versions {
		if s.Version == version {
			return Secret{Path: s.Path, Version: s.Version, Data: copyOf(s.Data)}, nil
		}
	}
	return Secret{}, ErrNotFound
}

func copyOf(b []byte) []byte {
	return append([]byte(nil), b...)
}
