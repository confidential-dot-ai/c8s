// Package policystate defines the wire format of the dynamic allowlist: the
// content-addressed objects, the append-only journal, the signed state
// statement CDS serves, and the messages participants send back.
//
// The package is pure. It has no I/O, no HTTP, no storage and no clock. CDS,
// the NRI enforcer, the router and the verifiers all import it so that one
// definition of "the same bytes" exists.
//
// # Canonical encoding
//
// Every hash and every signature covers Canonical bytes, never the bytes a
// peer happened to send. Canonical re-emits a value as JSON with object keys
// sorted bytewise, no insignificant whitespace, no HTML escaping (<, > and &
// are verbatim) and only the escapes JSON requires, so an independent
// implementation can reproduce it from the parse tree alone. Numbers are
// integers below 2^53, which keeps every counter exactly representable in a
// JavaScript verifier. Hashes and digests are "sha256:<64 lowercase hex>";
// signatures, nonces and boot keys are unpadded base64url.
//
// Parsing is strict: Decode rejects unknown fields and trailing data, and
// every protocol string is checked against a known constant. A verifier must
// never hash a lossy parse.
//
// # Objects and domain separation
//
// A public object — a canonical allowlist document or a journal entry — is
// named by ContentDigest, a plain sha256 over its exact bytes: whoever fetched
// it can rehash it without knowing the protocol.
//
// Hash and Sign instead prefix the payload with a domain string and a 0x00
// byte, so a state statement can never be replayed as a challenge or an ack.
// The domains are the Domain* constants.
//
// The protocol version lives in the domain strings and in Protocol, so a
// future revision changes every hash rather than silently reinterpreting one.
package policystate
