package overenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
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
	if _, err := serverCh.Open(rec, RequestAAD()); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Open with mismatched transcript = %v, want %v", err, ErrAuthenticationFailed)
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
	if _, err := serverCh.Open(rec, RequestAAD()); !errors.Is(err, ErrReplayedRecord) {
		t.Fatalf("replayed record: Open = %v, want %v", err, ErrReplayedRecord)
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
	if _, err := clientCh.Open(rec, ResponseAAD()); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("AAD mismatch: Open = %v, want %v", err, ErrAuthenticationFailed)
	}
}

func TestAgreeRejectsWrongSizes(t *testing.T) {
	srv, _ := GenerateServerKey()
	transcriptHash := testTranscriptHash(0xA5)
	tests := []struct {
		name    string
		agree   func() error
		wantErr string
	}{
		{
			name: "server ML-KEM ciphertext short",
			agree: func() error {
				_, err := srv.Agree(Handshake{ClientX25519: make([]byte, 32), MLKEMCiphertext: make([]byte, 10)}, transcriptHash)
				return err
			},
			wantErr: "ML-KEM ciphertext must be 1088 bytes, got 10",
		},
		{
			name: "server client X25519 key short",
			agree: func() error {
				_, err := srv.Agree(Handshake{ClientX25519: make([]byte, 10), MLKEMCiphertext: make([]byte, MLKEM768CTBytes)}, transcriptHash)
				return err
			},
			wantErr: "client X25519 key must be 32 bytes, got 10",
		},
		{
			name: "client ML-KEM key short",
			agree: func() error {
				_, _, err := ClientAgree(PublicKey{X25519: make([]byte, 32), MLKEM768: make([]byte, 10)}, transcriptHash)
				return err
			},
			wantErr: "ML-KEM key must be 1184 bytes, got 10",
		},
		{
			name: "client X25519 key short",
			agree: func() error {
				_, _, err := ClientAgree(PublicKey{X25519: make([]byte, 10), MLKEM768: make([]byte, MLKEM768EKBytes)}, transcriptHash)
				return err
			},
			wantErr: "X25519 key must be 32 bytes, got 10",
		},
		{
			name: "server transcript hash missing",
			agree: func() error {
				_, err := srv.Agree(Handshake{ClientX25519: make([]byte, 32), MLKEMCiphertext: make([]byte, MLKEM768CTBytes)}, nil)
				return err
			},
			wantErr: "identity transcript hash must be 48 bytes, got 0",
		},
		{
			name: "client transcript hash short",
			agree: func() error {
				_, _, err := ClientAgree(srv.Public(), make([]byte, 32))
				return err
			},
			wantErr: "identity transcript hash must be 48 bytes, got 32",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.agree()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
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
	if _, err := server.Open(rec, aad); !errors.Is(err, ErrRecordLimit) {
		t.Fatalf("Open after %d records = %v, want %v", maxTrackedNonces, err, ErrRecordLimit)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestChannelKeyGoldenVector pins the canonical key schedule against fixed
// shared secrets and a fixed salt so the Go derivation cannot drift.
// Cross-language contract: c8s-verify-js/test/keyagreement.test.ts must
// reproduce this vector.
func TestChannelKeyGoldenVector(t *testing.T) {
	mlkemSS := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	x25519SS := mustHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	salt := mustHex(t, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f")
	const wantKey = "f631405a5e117f1ff53e36c527782a3a1b97186007f277bd494db5d825dc08ab"

	t.Run("info string", func(t *testing.T) {
		if hkdfInfo != "c8s-verify/v1/over-encryption" {
			t.Fatalf("hkdfInfo = %q, want %q", hkdfInfo, "c8s-verify/v1/over-encryption")
		}
	})

	t.Run("salt is transcript-hash-shaped and load-bearing", func(t *testing.T) {
		if len(salt) != sha512.Size384 {
			t.Fatalf("vector salt = %d bytes, want the %d-byte identity transcript hash", len(salt), sha512.Size384)
		}
		// A nonce-shaped salt derives a different key: the salt is load-bearing.
		withTranscript, err := deriveKey(mlkemSS, x25519SS, salt)
		if err != nil {
			t.Fatal(err)
		}
		withNonce, err := deriveKey(mlkemSS, x25519SS, bytes.Repeat([]byte{0x42}, identityNonceBytes))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(withTranscript, withNonce) {
			t.Fatal("derived key ignored the salt")
		}
	})

	t.Run("key", func(t *testing.T) {
		key, err := deriveKey(mlkemSS, x25519SS, salt)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(key); got != wantKey {
			t.Fatalf("channel key = %s, want %s", got, wantKey)
		}
	})

	// The vector must hold through the production funnel, not only deriveKey.
	t.Run("key through deriveChannel", func(t *testing.T) {
		ch, err := deriveChannel(mlkemSS, x25519SS, salt)
		if err != nil {
			t.Fatal(err)
		}
		aad := RequestAAD()
		rec, err := ch.Seal([]byte("m"), aad)
		if err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(mustHex(t, wantKey))
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := aead.Open(nil, rec.IV, rec.CT, aad); err != nil {
			t.Fatalf("golden key cannot open a record sealed through deriveChannel: %v", err)
		}
	})
}

// openNoPanic converts an Open panic into an error so a missing IV guard fails the subtest.
func openNoPanic(ch *Channel, rec Record, aad []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("overenc test: Open panicked: %v", r)
		}
	}()
	_, err = ch.Open(rec, aad)
	return err
}

func TestOpenRejectsMalformedRecord(t *testing.T) {
	server, client := channelPair(t)
	aad := RequestAAD()
	valid, err := client.Seal([]byte("payload"), aad)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		rec  Record
		want error
	}{
		{name: "IV length 0", rec: Record{IV: []byte{}, CT: valid.CT}, want: ErrInvalidIV},
		{name: "IV length 11", rec: Record{IV: make([]byte, 11), CT: valid.CT}, want: ErrInvalidIV},
		{name: "IV length 13", rec: Record{IV: make([]byte, 13), CT: valid.CT}, want: ErrInvalidIV},
		{name: "IV length 16", rec: Record{IV: make([]byte, 16), CT: valid.CT}, want: ErrInvalidIV},
		{name: "ciphertext nil", rec: Record{IV: valid.IV, CT: nil}, want: ErrAuthenticationFailed},
		{name: "ciphertext 1 byte", rec: Record{IV: valid.IV, CT: []byte{0x00}}, want: ErrAuthenticationFailed},
		{name: "ciphertext truncated", rec: Record{IV: valid.IV, CT: valid.CT[:len(valid.CT)-1]}, want: ErrAuthenticationFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := openNoPanic(server, tt.rec, aad); !errors.Is(err, tt.want) {
				t.Fatalf("Open = %v, want %v", err, tt.want)
			}
		})
	}

	// A forgery reusing the genuine record's IV must not poison the anti-replay
	// set: the genuine record still opens.
	forged := Record{IV: valid.IV, CT: bytes.Clone(valid.CT)}
	forged.CT[0] ^= 0xff
	if _, err := server.Open(forged, aad); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Open(forged) = %v, want %v", err, ErrAuthenticationFailed)
	}
	if _, err := server.Open(valid, aad); err != nil {
		t.Fatalf("genuine record rejected after a forgery reused its IV: %v", err)
	}
}

func TestSealUsesAFreshIV(t *testing.T) {
	server, client := channelPair(t)
	// Both ends share one key, so IVs must be unique across the union of both
	// ends' records.
	ends := []struct {
		name string
		ch   *Channel
	}{
		{"server", server},
		{"client", client},
	}
	const seals = 1024
	seen := make(map[string]struct{}, 2*seals)
	for i := 0; i < seals; i++ {
		for _, end := range ends {
			rec, err := end.ch.Seal([]byte("m"), RequestAAD())
			if err != nil {
				t.Fatalf("%s seal %d: %v", end.name, i, err)
			}
			if len(rec.IV) != ivBytes {
				t.Fatalf("%s seal %d: IV = %d bytes, want %d", end.name, i, len(rec.IV), ivBytes)
			}
			if _, dup := seen[string(rec.IV)]; dup {
				t.Fatalf("%s seal %d reused an IV", end.name, i)
			}
			seen[string(rec.IV)] = struct{}{}
		}
	}
}
