package policystate

import (
	"encoding/json"
	"testing"
	"time"
)

func publishedPayload(version uint64) PublishedPayload {
	return PublishedPayload{
		Version:      version,
		TargetDigest: digestOf('b'),
		AuthorizedBy: AuthorizedBySeed,
	}
}

func removalPayload(version uint64) PublishedPayload {
	return PublishedPayload{
		Version:       version,
		SourceDigest:  digestOf('b'),
		TargetDigest:  digestOf('d'),
		RequiresDrain: true,
		AuthorizedBy:  "operator",
	}
}

// testChain builds the three-entry journal the vectors pin: a first policy, a
// publication that removes permissions, and the drain that closes it.
func testChain(t *testing.T) ([]Entry, []string) {
	t.Helper()
	steps := []struct {
		typ     EventType
		payload any
		time    string
	}{
		{EventPublished, publishedPayload(1), "2026-09-14T10:00:00Z"},
		{EventPublished, removalPayload(2), "2026-09-14T10:01:00Z"},
		{EventDrained, DrainedPayload{Version: 2}, "2026-09-14T10:02:00Z"},
	}
	var entries []Entry
	var digests []string
	var prev *Entry
	prevDigest := ""
	for i, s := range steps {
		at, err := time.Parse(time.RFC3339, s.time)
		if err != nil {
			t.Fatalf("time.Parse(%q) = _, %v, want no error", s.time, err)
		}
		e, err := NewEntryAt(prev, prevDigest, testAuthority, s.typ, s.payload, at)
		if err != nil {
			t.Fatalf("NewEntryAt(prev, %q, authority, %q, payload, %s) = _, %v, want no error", prevDigest, s.typ, s.time, err)
		}
		d, err := EntryDigest(e)
		if err != nil {
			t.Fatalf("EntryDigest(entries[%d]) = _, %v, want no error", i, err)
		}
		entries = append(entries, e)
		digests = append(digests, d)
		prev, prevDigest = &entries[i], d
	}
	return entries, digests
}

func TestNewEntryChain(t *testing.T) {
	entries, digests := testChain(t)
	for i, e := range entries {
		if e.Protocol != Protocol {
			t.Errorf("entries[%d].Protocol = %q, want %q", i, e.Protocol, Protocol)
		}
		if e.Authority != testAuthority {
			t.Errorf("entries[%d].Authority = %q, want %q", i, e.Authority, testAuthority)
		}
		if got, want := e.Position, uint64(i+1); got != want {
			t.Errorf("entries[%d].Position = %d, want %d", i, got, want)
		}
		wantParent := ""
		if i > 0 {
			wantParent = digests[i-1]
		}
		if e.Parent != wantParent {
			t.Errorf("entries[%d].Parent = %q, want %q", i, e.Parent, wantParent)
		}
		if _, err := time.Parse(time.RFC3339, e.Time); err != nil {
			t.Errorf("time.Parse(entries[%d].Time = %q) = %v, want no error", i, e.Time, err)
		}
		if err := ValidateEntry(e); err != nil {
			t.Errorf("ValidateEntry(entries[%d]) = %v, want no error", i, err)
		}
	}
}

// TestNewEntryKeepsChainingAcrossAuthorities pins that a CDS restart, which
// generates a new authority key, continues the journal rather than forking it.
func TestNewEntryKeepsChainingAcrossAuthorities(t *testing.T) {
	entries, digests := testChain(t)
	head, headDigest := entries[len(entries)-1], digests[len(digests)-1]
	next, err := NewEntryAt(&head, headDigest, digestOf('9'), EventPublished, publishedPayload(3), time.Unix(0, 0))
	if err != nil {
		t.Fatalf("NewEntryAt(head, digest, otherAuthority, published, payload, t) = _, %v, want no error", err)
	}
	if next.Position != head.Position+1 {
		t.Errorf("next.Position = %d, want %d", next.Position, head.Position+1)
	}
	if next.Parent != headDigest {
		t.Errorf("next.Parent = %q, want %q", next.Parent, headDigest)
	}
	if next.Authority != digestOf('9') {
		t.Errorf("next.Authority = %q, want %q", next.Authority, digestOf('9'))
	}
}

func TestNewEntryRejects(t *testing.T) {
	entries, digests := testChain(t)
	head := entries[0]

	tests := []struct {
		name       string
		prev       *Entry
		prevDigest string
		authority  string
		typ        EventType
		payload    any
	}{
		{"a parent digest that does not match prev", &head, digests[1], testAuthority, EventPublished, publishedPayload(2)},
		{"a parent with no digest", &head, "", testAuthority, EventPublished, publishedPayload(2)},
		{"a digest with no parent", nil, digests[0], testAuthority, EventPublished, publishedPayload(1)},
		{"an authority that is not a fingerprint", nil, "", "cds", EventPublished, publishedPayload(1)},
		{"an unknown event type", &head, digests[0], testAuthority, EventType("nonsense"), publishedPayload(2)},
		{"a payload with a counter above 2^53", &head, digests[0], testAuthority, EventPublished, PublishedPayload{Version: MaxCounter, TargetDigest: digestOf('b'), AuthorizedBy: "seed"}},
		{"a payload that is not the type's struct", &head, digests[0], testAuthority, EventDrained, publishedPayload(2)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewEntryAt(tc.prev, tc.prevDigest, tc.authority, tc.typ, tc.payload, time.Unix(0, 0))
			if err == nil {
				t.Errorf("NewEntryAt(...) = %+v, nil, want an error", got)
			}
		})
	}
}

func TestValidateEntry(t *testing.T) {
	entries, digests := testChain(t)
	valid := entries[1]

	withPayload := func(p json.RawMessage) Entry {
		e := valid
		e.Payload = p
		return e
	}
	noParent := valid
	noParent.Parent = ""
	badParent := valid
	badParent.Parent = "not-a-hash"
	badProtocol := valid
	badProtocol.Protocol = "c8s.policystate/v2"
	zeroPosition := valid
	zeroPosition.Position = 0
	badAuthority := valid
	badAuthority.Authority = "cds"
	badTime := valid
	badTime.Time = "yesterday"
	badType := valid
	badType.Type = "nonsense"
	firstWithParent := entries[0]
	firstWithParent.Parent = digests[0]

	tests := []struct {
		name    string
		entry   Entry
		wantErr bool
	}{
		{"a valid entry", valid, false},
		{"an unknown protocol", badProtocol, true},
		{"a zero position", zeroPosition, true},
		{"an authority that is not a fingerprint", badAuthority, true},
		{"a later position with no parent", noParent, true},
		{"a malformed parent", badParent, true},
		{"the first entry with a parent", firstWithParent, true},
		{"a time that is not RFC3339", badTime, true},
		{"an unknown type", badType, true},
		{"a payload with an unknown field", withPayload([]byte(`{"version":1,"extra":true}`)), true},
		{"a payload that is not canonical", withPayload([]byte(`{"version": 2}`)), true},
		{"a payload with keys out of order", withPayload([]byte(`{"version":2,"target_digest":"` + digestOf('d') + `","authorized_by":"seed","requires_drain":false}`)), true},
		{"a payload that is not an object", withPayload([]byte(`7`)), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEntry(tc.entry)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateEntry(%s entry) = %v, want error: %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestDecodePayload(t *testing.T) {
	entries, _ := testChain(t)
	got, err := DecodePayload[PublishedPayload](entries[1])
	if err != nil {
		t.Fatalf("DecodePayload[PublishedPayload](entries[1]) = _, %v, want no error", err)
	}
	if want := removalPayload(2); got != want {
		t.Errorf("DecodePayload[PublishedPayload](entries[1]) = %+v, want %+v", got, want)
	}
	if _, err := DecodePayload[DrainedPayload](entries[1]); err == nil {
		t.Errorf("DecodePayload[DrainedPayload](entries[1]) = _, nil, want an error")
	}
}

func TestEntryDigestCoversEveryField(t *testing.T) {
	entries, _ := testChain(t)
	base, err := EntryDigest(entries[1])
	if err != nil {
		t.Fatalf("EntryDigest(entries[1]) = _, %v, want no error", err)
	}
	mutations := map[string]func(*Entry){
		"authority": func(e *Entry) { e.Authority = digestOf('9') },
		"position":  func(e *Entry) { e.Position = 9 },
		"parent":    func(e *Entry) { e.Parent = digestOf('9') },
		"type":      func(e *Entry) { e.Type = EventDrained },
		"time":      func(e *Entry) { e.Time = "2020-01-01T00:00:00Z" },
		"payload":   func(e *Entry) { e.Payload = []byte(`{"version":9}`) },
	}
	for field, mutate := range mutations {
		e := entries[1]
		mutate(&e)
		got, err := EntryDigest(e)
		if err != nil {
			t.Fatalf("EntryDigest(entry with changed %s) = _, %v, want no error", field, err)
		}
		if got == base {
			t.Errorf("EntryDigest(entry with changed %s) = %s, want it to differ from %s", field, got, base)
		}
	}
}
