// Package overenc implements the c8s-verify post-quantum over-encryption channel
// that terminates inside the Load Balancer's TEE. This package's key schedule and
// record layer are the canonical contract (pinned by the golden vectors under
// testdata/); the c8s-verify-js client and its PROTOCOL.md follow it.
//
// Key agreement is X-Wing (draft-connolly-cfrg-xwing-kem-10): X25519 + ML-KEM-768
// under the draft's SHA3-256 combiner, so the channel stays secure as long as
// EITHER primitive holds. The flow is client-first — the client sends its
// encapsulation key with its nonce, the server encapsulates once and binds both
// key-exchange messages, the session id, and the mesh identity into the hardware
// report — so the evidence covers the complete exchange.
//
// The record layer derives one AES-256-GCM key and IV prefix per direction and
// binds each record's direction, session id, and sequence number into its nonce
// and AAD. A response must echo its request's sequence, so the untrusted TLS
// terminator can neither replay a record nor cross the responses of two
// concurrent requests.
package overenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"filippo.io/mlkem768/xwing"
)

const (
	hkdfInfoC2SKey   = "c8s-verify/v1/c2s-key"
	hkdfInfoS2CKey   = "c8s-verify/v1/s2c-key"
	hkdfInfoC2SIV    = "c8s-verify/v1/c2s-iv"
	hkdfInfoS2CIV    = "c8s-verify/v1/s2c-iv"
	hkdfInfoExporter = "c8s-verify/v1/exporter"

	keyBytes      = 32
	ivPrefixBytes = 4
	seqBytes      = 8

	// XWingEKBytes is the X-Wing encapsulation-key length (ML-KEM-768 key ||
	// X25519 key).
	XWingEKBytes = xwing.EncapsulationKeySize
	// XWingCTBytes is the X-Wing ciphertext length (ML-KEM-768 ciphertext ||
	// X25519 ephemeral key).
	XWingCTBytes = xwing.CiphertextSize
	// SessionIDBytes is the session identifier length; the transcript and every
	// record AAD frame exactly this many bytes.
	SessionIDBytes = 16
	// ExporterBytes is the channel-binding exporter length.
	ExporterBytes = 32

	// replayWindow is how far behind the highest accepted sequence a reordered
	// request may arrive. The client keeps fewer requests outstanding, so a
	// legitimate reordering never leaves the window.
	replayWindow = 64
)

// Sentinel errors for the record-opening rejection paths, matchable via
// [errors.Is].
var (
	// ErrAuthenticationFailed: the record failed AEAD authentication (wrong
	// key, tampered ciphertext, wrong sequence, or wrong AAD).
	ErrAuthenticationFailed = errors.New("overenc: authentication failed")
	// ErrReplayedRecord: a record with this sequence was already accepted, or
	// the sequence fell behind the replay window.
	ErrReplayedRecord = errors.New("overenc: replayed or out-of-window record rejected")
	// ErrSequenceInvalid: the record's sequence number is outside the valid
	// range (zero, or the response does not echo its request).
	ErrSequenceInvalid = errors.New("overenc: invalid record sequence")
)

// ClientKey is the client-side X-Wing decapsulation key for one session.
type ClientKey struct {
	dk *xwing.DecapsulationKey
	ek []byte
}

// GenerateClientKey creates a fresh X-Wing keypair for one session.
func GenerateClientKey() (*ClientKey, error) {
	dk, err := xwing.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("overenc: generate X-Wing key: %w", err)
	}
	return &ClientKey{dk: dk, ek: dk.EncapsulationKey()}, nil
}

// NewClientKeyFromSeed rebuilds a client key from its 32-byte seed, for tests
// and golden vectors.
func NewClientKeyFromSeed(seed []byte) (*ClientKey, error) {
	dk, err := xwing.NewKeyFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("overenc: X-Wing key from seed: %w", err)
	}
	return &ClientKey{dk: dk, ek: dk.EncapsulationKey()}, nil
}

// EncapsulationKey returns the public encapsulation key the client sends in
// its attestation request.
func (c *ClientKey) EncapsulationKey() []byte { return c.ek }

// Decapsulate recovers the shared secret from the server's ciphertext. An
// invalid ciphertext yields the draft's implicit-rejection secret rather than
// an error, so a tampered handshake surfaces as an authentication failure on
// the first record, never as a decapsulation oracle.
func (c *ClientKey) Decapsulate(ct []byte) ([]byte, error) {
	if len(ct) != XWingCTBytes {
		return nil, fmt.Errorf("overenc: X-Wing ciphertext must be %d bytes, got %d", XWingCTBytes, len(ct))
	}
	ss, err := xwing.Decapsulate(c.dk, ct)
	if err != nil {
		return nil, fmt.Errorf("overenc: X-Wing decapsulate: %w", err)
	}
	return ss, nil
}

// Encapsulate is the server side of the key exchange: encapsulate a fresh
// shared secret to the client's encapsulation key.
func Encapsulate(ek []byte) (ct, sharedSecret []byte, err error) {
	if len(ek) != XWingEKBytes {
		return nil, nil, fmt.Errorf("overenc: X-Wing encapsulation key must be %d bytes, got %d", XWingEKBytes, len(ek))
	}
	ct, ss, err := xwing.Encapsulate(ek)
	if err != nil {
		return nil, nil, fmt.Errorf("overenc: X-Wing encapsulate: %w", err)
	}
	return ct, ss, nil
}

// channelKeys is the full HKDF-SHA256 key schedule: salt is the identity
// transcript hash, which binds every output — including the exporter — to the
// attested identity.
type channelKeys struct {
	c2sKey, s2cKey []byte
	c2sIV, s2cIV   []byte
	exporter       []byte
}

func deriveKeys(sharedSecret, transcriptHash []byte) (*channelKeys, error) {
	if len(sharedSecret) != xwing.SharedKeySize {
		return nil, fmt.Errorf("overenc: shared secret must be %d bytes, got %d", xwing.SharedKeySize, len(sharedSecret))
	}
	if len(transcriptHash) != sha512.Size384 {
		return nil, fmt.Errorf("overenc: identity transcript hash must be %d bytes, got %d", sha512.Size384, len(transcriptHash))
	}
	var keys channelKeys
	for _, output := range []struct {
		dst  *[]byte
		info string
		size int
	}{
		{&keys.c2sKey, hkdfInfoC2SKey, keyBytes},
		{&keys.s2cKey, hkdfInfoS2CKey, keyBytes},
		{&keys.c2sIV, hkdfInfoC2SIV, ivPrefixBytes},
		{&keys.s2cIV, hkdfInfoS2CIV, ivPrefixBytes},
		{&keys.exporter, hkdfInfoExporter, ExporterBytes},
	} {
		derived, err := hkdf.Key(sha256.New, sharedSecret, transcriptHash, output.info, output.size)
		if err != nil {
			return nil, fmt.Errorf("overenc: HKDF: %w", err)
		}
		*output.dst = derived
	}
	return &keys, nil
}

// Record is one AES-256-GCM record on the wire, carried as CBOR by the tunnel
// transport. Seq is the client-allocated sequence number; a response record
// echoes its request's.
type Record struct {
	Seq uint64 `cbor:"seq" json:"seq"`
	CT  []byte `cbor:"ct" json:"ct"`
}

// Channel is one end of the over-encryption channel. The client end seals
// requests and opens responses; the server end opens requests and seals
// responses. Directional keys and sequence-framing AADs make the two ends
// asymmetric, so each end only constructs the operations of its role.
type Channel struct {
	sessionID []byte
	send      cipher.AEAD // this end's sealing direction
	recv      cipher.AEAD // this end's opening direction
	sendIV    []byte
	recvIV    []byte
	sendAAD   string // AAD domain tag for sealed records
	recvAAD   string // AAD domain tag for opened records
	exporter  []byte

	mu sync.Mutex
	// nextSeq is the client end's next request sequence (starts at 1).
	nextSeq uint64
	// seqHigh/seqMask are the server end's sliding replay window: seqHigh is
	// the highest accepted sequence, bit i of seqMask records seqHigh-i.
	seqHigh uint64
	seqMask uint64
}

// NewClientChannel derives the client end of the channel from the X-Wing
// shared secret and the verified identity transcript hash.
func NewClientChannel(sharedSecret, transcriptHash, sessionID []byte) (*Channel, error) {
	keys, err := deriveKeys(sharedSecret, transcriptHash)
	if err != nil {
		return nil, err
	}
	return newChannel(keys.c2sKey, keys.s2cKey, keys.c2sIV, keys.s2cIV,
		requestAADTag, responseAADTag, keys.exporter, sessionID)
}

// NewServerChannel derives the server end of the channel.
func NewServerChannel(sharedSecret, transcriptHash, sessionID []byte) (*Channel, error) {
	keys, err := deriveKeys(sharedSecret, transcriptHash)
	if err != nil {
		return nil, err
	}
	return newChannel(keys.s2cKey, keys.c2sKey, keys.s2cIV, keys.c2sIV,
		responseAADTag, requestAADTag, keys.exporter, sessionID)
}

func newChannel(sendKey, recvKey, sendIV, recvIV []byte, sendAAD, recvAAD string, exporter, sessionID []byte) (*Channel, error) {
	if len(sessionID) != SessionIDBytes {
		return nil, fmt.Errorf("overenc: session id must be %d bytes, got %d", SessionIDBytes, len(sessionID))
	}
	send, err := newAEAD(sendKey)
	if err != nil {
		return nil, err
	}
	recv, err := newAEAD(recvKey)
	if err != nil {
		return nil, err
	}
	return &Channel{
		sessionID: append([]byte(nil), sessionID...),
		send:      send,
		recv:      recv,
		sendIV:    sendIV,
		recvIV:    recvIV,
		sendAAD:   sendAAD,
		recvAAD:   recvAAD,
		exporter:  exporter,
		nextSeq:   1,
	}, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("overenc: AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("overenc: GCM: %w", err)
	}
	return aead, nil
}

// Exporter returns the channel-binding exporter: a value both ends derive from
// the shared secret under the identity transcript, never sent on the wire. An
// application binds bearer credentials to it so a token exfiltrated from one
// channel is useless on any other. The sidecar forwards it to the backend as
// the X-C8s-Exporter header.
func (c *Channel) Exporter() []byte { return append([]byte(nil), c.exporter...) }

const (
	requestAADTag  = "c8s-verify/v1/tunnel-request"
	responseAADTag = "c8s-verify/v1/tunnel-response"
)

// aad frames tag || session_id || be64(seq): every record authenticates its
// direction, session, and position.
func (c *Channel) aad(tag string, seq uint64) []byte {
	buf := make([]byte, 0, len(tag)+SessionIDBytes+seqBytes)
	buf = append(buf, tag...)
	buf = append(buf, c.sessionID...)
	return binary.BigEndian.AppendUint64(buf, seq)
}

// nonce frames ivPrefix || be64(seq): deterministic, unique per (direction,
// sequence) under one key schedule.
func nonce(ivPrefix []byte, seq uint64) []byte {
	buf := make([]byte, 0, ivPrefixBytes+seqBytes)
	buf = append(buf, ivPrefix...)
	return binary.BigEndian.AppendUint64(buf, seq)
}

// SealRequest seals a request record under this end's next sequence number
// (client role).
func (c *Channel) SealRequest(plaintext []byte) (Record, error) {
	c.mu.Lock()
	seq := c.nextSeq
	c.nextSeq++
	c.mu.Unlock()
	return c.seal(plaintext, seq)
}

// SealResponse seals a response record echoing the request's sequence (server
// role).
func (c *Channel) SealResponse(plaintext []byte, seq uint64) (Record, error) {
	return c.seal(plaintext, seq)
}

func (c *Channel) seal(plaintext []byte, seq uint64) (Record, error) {
	if seq == 0 {
		return Record{}, ErrSequenceInvalid
	}
	ct := c.send.Seal(nil, nonce(c.sendIV, seq), plaintext, c.aad(c.sendAAD, seq))
	return Record{Seq: seq, CT: ct}, nil
}

// OpenRequest authenticates and decrypts a request record (server role),
// enforcing the sliding replay window: a record replayed by the untrusted TLS
// terminator, or reordered further than replayWindow behind the newest
// accepted request, is rejected. Only authenticated records advance the
// window, so forged traffic cannot disturb it.
func (c *Channel) OpenRequest(rec Record) ([]byte, error) {
	if rec.Seq == 0 {
		return nil, ErrSequenceInvalid
	}
	pt, err := c.open(rec)
	if err != nil {
		return nil, err
	}
	if err := c.acceptSeq(rec.Seq); err != nil {
		return nil, err
	}
	return pt, nil
}

// OpenResponse authenticates and decrypts a response record (client role). The
// record must echo requestSeq — the sequence of the request it answers — which
// is what stops the terminator crossing the responses of two concurrent
// requests.
func (c *Channel) OpenResponse(rec Record, requestSeq uint64) ([]byte, error) {
	if rec.Seq == 0 || rec.Seq != requestSeq {
		return nil, fmt.Errorf("%w: response sequence %d does not echo request sequence %d", ErrSequenceInvalid, rec.Seq, requestSeq)
	}
	return c.open(rec)
}

func (c *Channel) open(rec Record) ([]byte, error) {
	pt, err := c.recv.Open(nil, nonce(c.recvIV, rec.Seq), rec.CT, c.aad(c.recvAAD, rec.Seq))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthenticationFailed, err)
	}
	return pt, nil
}

// acceptSeq applies the sliding replay window to an authenticated sequence.
func (c *Channel) acceptSeq(seq uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case seq > c.seqHigh:
		shift := seq - c.seqHigh
		if shift >= replayWindow {
			c.seqMask = 0
		} else {
			c.seqMask <<= shift
		}
		c.seqMask |= 1
		c.seqHigh = seq
		return nil
	case c.seqHigh-seq >= replayWindow:
		return ErrReplayedRecord
	default:
		bit := uint64(1) << (c.seqHigh - seq)
		if c.seqMask&bit != 0 {
			return ErrReplayedRecord
		}
		c.seqMask |= bit
		return nil
	}
}

// GenerateSessionID mints a fresh random session identifier.
func GenerateSessionID() ([]byte, error) {
	id := make([]byte, SessionIDBytes)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("overenc: generate session id: %w", err)
	}
	return id, nil
}
