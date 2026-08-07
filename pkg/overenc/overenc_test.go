package overenc

import (
	"bytes"
	"crypto/sha512"
	"strings"
	"testing"
)

func testTranscriptHash(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, sha512.Size384)
}

func TestHybridChannelRoundTrip(t *testing.T) {
	srv, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := srv.Public()
	if len(pub.X25519) != X25519PubBytes || len(pub.MLKEM768) != MLKEM768EKBytes {
		t.Fatalf("unexpected public key sizes: x25519=%d mlkem=%d", len(pub.X25519), len(pub.MLKEM768))
	}

	transcriptHash := testTranscriptHash(0xA5)
	clientCh, hs, err := ClientAgree(pub, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs.MLKEMCiphertext) != MLKEM768CTBytes {
		t.Fatalf("unexpected ciphertext size %d", len(hs.MLKEMCiphertext))
	}
	serverCh, err := srv.Agree(hs, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}

	aad := RequestAAD()
	rec, err := clientCh.Seal([]byte("hello pq"), aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := serverCh.Open(rec, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello pq" {
		t.Fatalf("got %q", got)
	}

	// Reverse direction (server -> client).
	rec2, _ := serverCh.Seal([]byte("pong"), ResponseAAD())
	got2, err := clientCh.Open(rec2, ResponseAAD())
	if err != nil || string(got2) != "pong" {
		t.Fatalf("reverse round-trip failed: %v %q", err, got2)
	}
}

// channelPair returns an agreed (server, client) channel pair for tests.
func channelPair(t *testing.T) (server, client *Channel) {
	t.Helper()
	srv, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	clientCh, hs, err := ClientAgree(srv.Public(), testTranscriptHash(0xA5))
	if err != nil {
		t.Fatal(err)
	}
	serverCh, err := srv.Agree(hs, testTranscriptHash(0xA5))
	if err != nil {
		t.Fatal(err)
	}
	return serverCh, clientCh
}

func TestChannelRejectsMismatchedTranscript(t *testing.T) {
	srv, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	clientCh, hs, err := ClientAgree(srv.Public(), testTranscriptHash(0xA5))
	if err != nil {
		t.Fatal(err)
	}
	serverCh, err := srv.Agree(hs, testTranscriptHash(0x5A))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := clientCh.Seal([]byte("secret"), RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCh.Open(rec, RequestAAD()); err == nil {
		t.Fatal("mismatched identity transcript derived the same channel")
	}
}

func TestOpenRejectsReplayedRecord(t *testing.T) {
	serverCh, clientCh := channelPair(t)

	rec, err := clientCh.Seal([]byte("transfer $100"), RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCh.Open(rec, RequestAAD()); err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	// Resubmitting the exact same authenticated record must not decrypt to a
	// second backend action.
	if _, err := serverCh.Open(rec, RequestAAD()); err == nil {
		t.Fatal("replayed record accepted; want rejection")
	}
	// A fresh, distinct record from the same channel still opens.
	rec2, err := clientCh.Seal([]byte("transfer $200"), RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCh.Open(rec2, RequestAAD()); err != nil {
		t.Fatalf("distinct record rejected: %v", err)
	}
}

func TestOpenRejectsTamperedAAD(t *testing.T) {
	srv, _ := GenerateServerKey()
	clientCh, _, err := ClientAgree(srv.Public(), testTranscriptHash(0xA5))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := clientCh.Seal([]byte("x"), RequestAAD())
	if _, err := clientCh.Open(rec, ResponseAAD()); err == nil {
		t.Fatal("expected AAD mismatch to fail authentication")
	}
}

func TestAgreeRejectsWrongSizes(t *testing.T) {
	srv, _ := GenerateServerKey()
	transcriptHash := testTranscriptHash(0xA5)
	if _, err := srv.Agree(Handshake{ClientX25519: make([]byte, 32), MLKEMCiphertext: make([]byte, 10)}, transcriptHash); err == nil {
		t.Fatal("expected error for short ciphertext")
	}
	if _, _, err := ClientAgree(PublicKey{X25519: make([]byte, 32), MLKEM768: make([]byte, 10)}, transcriptHash); err == nil {
		t.Fatal("expected error for short ML-KEM key")
	}
	if _, err := srv.Agree(Handshake{ClientX25519: make([]byte, 32), MLKEMCiphertext: make([]byte, MLKEM768CTBytes)}, nil); err == nil {
		t.Fatal("expected error for missing transcript hash")
	}
	if _, _, err := ClientAgree(srv.Public(), make([]byte, 32)); err == nil {
		t.Fatal("expected error for short transcript hash")
	}
}

// The anti-replay set is bounded: once maxTrackedNonces records have been
// opened, further records are refused so a hostile client cannot grow the set
// without re-establishing the session.
func TestOpenFailsClosedAtRecordLimit(t *testing.T) {
	server, client := channelPair(t)
	aad := RequestAAD()
	for i := 0; i < maxTrackedNonces; i++ {
		rec, err := client.Seal([]byte("m"), aad)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		if _, err := server.Open(rec, aad); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	rec, err := client.Seal([]byte("m"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Open(rec, aad); err == nil || !strings.Contains(err.Error(), "record limit") {
		t.Fatalf("Open after %d records = %v, want the fail-closed limit error", maxTrackedNonces, err)
	}
}
