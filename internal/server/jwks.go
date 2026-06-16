package server

import (
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/pkg/jwks"
)

// HandleJWKS returns a handler that serves a JWKS document.
// If jwksFunc is provided, it returns the pre-serialized JSON on each request
// (for rotation mode with multiple keys). Otherwise it serves a static JWKS
// built from the Issuer's current key.
func HandleJWKS(iss ear.Issuer, jwksFunc func() []byte) http.HandlerFunc {
	if jwksFunc != nil {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.Write(jwksFunc())
		}
	}

	// Static mode — single key from the Issuer.
	pub := iss.PublicKey()
	if pub == nil {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys":[]}`))
		}
	}

	jwk, err := jwks.FromPublicKey(pub)
	if err != nil {
		panic("jwks: " + err.Error())
	}
	body, err := jwks.MarshalSet(jwk)
	if err != nil {
		panic("jwks: " + err.Error())
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write(body)
	}
}
