package secretstore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// jsonDoc is the test-helper dump format: entry -> path -> base64 value. It is
// used by unit and integration tests to seed and inspect a MemStore; nothing in
// the CDS runtime reads it (deposit is the operator CLI).
type jsonDoc map[string]map[string]string

// DumpJSON serializes the store for test assertions.
func (m *MemStore) DumpJSON() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc := jsonDoc{}
	for ref, v := range m.secrets {
		if doc[ref.Entry] == nil {
			doc[ref.Entry] = map[string]string{}
		}
		doc[ref.Entry][ref.Path] = base64.StdEncoding.EncodeToString(v)
	}
	return json.Marshal(doc)
}

// LoadJSON replaces the store's contents from a DumpJSON document.
func (m *MemStore) LoadJSON(data []byte) error {
	var doc jsonDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("decode secret store dump: %w", err)
	}
	next := make(map[Ref][]byte)
	for entry, paths := range doc {
		for p, b64 := range paths {
			v, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return fmt.Errorf("entry %q path %q: invalid base64: %w", entry, p, err)
			}
			next[Ref{Entry: entry, Path: p}] = v
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets = next
	return nil
}
