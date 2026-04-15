package ktoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/jwks"
)

const certField = "token-signer.crt"

// RotatorConfig configures the key rotation loop.
type RotatorConfig struct {
	Client    kubernetes.Interface
	Namespace string
	Secret    string
	Interval  time.Duration // rotation interval (default 720h)
	Overlap   time.Duration // how long retiring keys stay in JWKS (default 25h)
	Jitter    float64       // fraction of Interval to jitter first tick (default 0.1)
	Logger    *slog.Logger
}

// managedKey is a key with lifecycle metadata.
type managedKey struct {
	Kid       string `json:"kid"`
	KeyPEM    string `json:"private_key_pem"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Status    string `json:"status"` // "active" | "retiring"
	key       *ecdsa.PrivateKey
	notAfterT time.Time
}

type keysJSON struct {
	Keys []managedKey `json:"keys"`
}

// SwapKeyFunc is called when the active signing key changes.
type SwapKeyFunc func(key *ecdsa.PrivateKey, kid string)

// Rotator manages the token-signer key lifecycle with overlap-based
// rotation and persistence to a Kubernetes Secret.
type Rotator struct {
	cfg     RotatorConfig
	swapKey SwapKeyFunc

	mu       sync.RWMutex
	active   *managedKey
	retiring []*managedKey

	jwksBody atomic.Pointer[[]byte]
}

// NewRotator creates a rotator from an initial key PEM.
func NewRotator(cfg RotatorConfig, initialKeyPEM []byte, swapKey SwapKeyFunc) (*Rotator, error) {
	key, err := certutil.ParseECPrivateKey(initialKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse initial key: %w", err)
	}
	kid, err := jwks.Thumbprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	r := &Rotator{
		cfg:     cfg,
		swapKey: swapKey,
		active: &managedKey{
			Kid:       kid,
			KeyPEM:    string(initialKeyPEM),
			NotBefore: now.Format(time.RFC3339),
			NotAfter:  now.Add(cfg.Interval + cfg.Overlap).Format(time.RFC3339),
			Status:    "active",
			key:       key,
			notAfterT: now.Add(cfg.Interval + cfg.Overlap),
		},
	}
	r.rebuildJWKS()

	// Try loading persisted state from Secret (may have retiring keys from before restart).
	r.loadFromSecret()

	return r, nil
}

// JWKSetJSON returns the current pre-serialized JWKS response body.
func (r *Rotator) JWKSetJSON() []byte {
	p := r.jwksBody.Load()
	if p == nil {
		return []byte(`{"keys":[]}`)
	}
	return *p
}

// Run starts the rotation loop. Blocks until ctx is cancelled.
func (r *Rotator) Run(ctx context.Context) {
	// Jitter the first tick to avoid thundering-herd after fleet restarts.
	jitter := time.Duration(float64(r.cfg.Interval) * r.cfg.Jitter * mathrand.Float64())
	first := r.cfg.Interval + jitter
	r.cfg.Logger.Info("rotation loop starting", "interval", r.cfg.Interval, "first_tick_in", first)

	timer := time.NewTimer(first)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.rotate(ctx)
			timer.Reset(r.cfg.Interval)
		}
	}
}

func (r *Rotator) rotate(ctx context.Context) {
	r.cfg.Logger.Info("rotating token-signer key")

	keyPEM, _, err := generateKeypair()
	if err != nil {
		r.cfg.Logger.Error("key generation failed", "error", err)
		return
	}
	newKey, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		r.cfg.Logger.Error("parse new key failed", "error", err)
		return
	}
	newKid, err := jwks.Thumbprint(&newKey.PublicKey)
	if err != nil {
		r.cfg.Logger.Error("thumbprint failed", "error", err)
		return
	}

	now := time.Now()

	r.mu.Lock()
	if old := r.active; old != nil {
		old.Status = "retiring"
		old.NotAfter = now.Add(r.cfg.Overlap).Format(time.RFC3339)
		old.notAfterT = now.Add(r.cfg.Overlap)
		r.retiring = append(r.retiring, old)
	}

	r.active = &managedKey{
		Kid:       newKid,
		KeyPEM:    string(keyPEM),
		NotBefore: now.Format(time.RFC3339),
		NotAfter:  now.Add(r.cfg.Interval + r.cfg.Overlap).Format(time.RFC3339),
		Status:    "active",
		key:       newKey,
		notAfterT: now.Add(r.cfg.Interval + r.cfg.Overlap),
	}

	// Evict expired retiring keys.
	live := r.retiring[:0]
	for _, k := range r.retiring {
		if k.notAfterT.After(now) {
			live = append(live, k)
		} else {
			r.cfg.Logger.Info("evicted expired key", "kid", k.Kid)
		}
	}
	r.retiring = live
	r.mu.Unlock()

	// Swap the signing key in the Issuer.
	r.swapKey(newKey, newKid)

	r.rebuildJWKS()

	if err := r.persistToSecret(ctx); err != nil {
		r.cfg.Logger.Error("failed to persist keys to Secret", "error", err)
	}

	r.cfg.Logger.Info("rotation complete", "new_kid", newKid, "retiring_keys", len(r.retiring))
}

func (r *Rotator) rebuildJWKS() {
	r.mu.RLock()
	var keys []jose.JSONWebKey

	// Active key first.
	if r.active != nil {
		if jwk, err := jwks.FromPublicKey(&r.active.key.PublicKey); err == nil {
			keys = append(keys, jwk)
		}
	}
	for _, k := range r.retiring {
		if jwk, err := jwks.FromPublicKey(&k.key.PublicKey); err == nil {
			keys = append(keys, jwk)
		}
	}
	r.mu.RUnlock()

	body, err := jwks.MarshalSet(keys...)
	if err != nil {
		r.cfg.Logger.Error("failed to marshal JWKS", "error", err)
		return
	}
	r.jwksBody.Store(&body)
}

func (r *Rotator) persistToSecret(ctx context.Context) error {
	r.mu.RLock()
	var allKeys []managedKey
	if r.active != nil {
		allKeys = append(allKeys, *r.active)
	}
	for _, k := range r.retiring {
		allKeys = append(allKeys, *k)
	}
	r.mu.RUnlock()

	data, err := json.Marshal(keysJSON{Keys: allKeys})
	if err != nil {
		return fmt.Errorf("marshal keys.json: %w", err)
	}

	secrets := r.cfg.Client.CoreV1().Secrets(r.cfg.Namespace)
	secret, err := secrets.Get(ctx, r.cfg.Secret, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get Secret: %w", err)
	}

	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data["keys.json"] = data

	// Keep legacy fields populated with the active key for backward compat.
	r.mu.RLock()
	if r.active != nil {
		secret.Data[keyField] = []byte(r.active.KeyPEM)
		if certPEM, err := selfSignCert(r.active.key); err == nil {
			secret.Data[certField] = certPEM
		}
	}
	r.mu.RUnlock()

	if _, err := secrets.Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update Secret: %w", err)
	}
	return nil
}

// loadFromSecret tries to restore retiring keys from a persisted keys.json.
func (r *Rotator) loadFromSecret() {
	ctx := context.Background()
	secrets := r.cfg.Client.CoreV1().Secrets(r.cfg.Namespace)
	secret, err := secrets.Get(ctx, r.cfg.Secret, metav1.GetOptions{})
	if err != nil {
		return // Secret may not exist yet; that's fine.
	}

	raw, ok := secret.Data["keys.json"]
	if !ok || len(raw) == 0 {
		return
	}

	var stored keysJSON
	if err := json.Unmarshal(raw, &stored); err != nil {
		r.cfg.Logger.Warn("failed to parse keys.json from Secret, starting fresh", "error", err)
		return
	}

	now := time.Now()
	r.mu.Lock()
	for i := range stored.Keys {
		mk := &stored.Keys[i]
		if mk.Status != "retiring" {
			continue
		}
		t, err := time.Parse(time.RFC3339, mk.NotAfter)
		if err != nil || t.Before(now) {
			continue
		}
		key, err := certutil.ParseECPrivateKey([]byte(mk.KeyPEM))
		if err != nil {
			continue
		}
		mk.key = key
		mk.notAfterT = t
		r.retiring = append(r.retiring, mk)
	}
	count := len(r.retiring)
	r.mu.Unlock()

	if count > 0 {
		r.cfg.Logger.Info("restored retiring keys from Secret", "count", count)
		r.rebuildJWKS()
	}
}

func generateKeypair() (keyPEM []byte, certPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	keyPEM, err = certutil.MarshalECKeyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM, err = selfSignCert(key)
	if err != nil {
		return nil, nil, err
	}
	return keyPEM, certPEM, nil
}

func selfSignCert(key *ecdsa.PrivateKey) ([]byte, error) {
	serial, err := certutil.GenerateSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "EAR Token Signer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 365),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return certutil.EncodeCertPEM(certDER), nil
}
