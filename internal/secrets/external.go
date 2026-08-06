package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// ExternalRoute is the operator endpoint for the external-KMS config. Chi
// routes the static segment ahead of the "/secrets/*" wildcard, which makes
// "/external" a reserved store path: nothing under it is reachable as a
// store path, and validation refuses it as a mapping key.
const ExternalRoute = "/secrets/external"

// externalSchema versions the document, following the allowlist's
// c8s.allowlist/v1 convention.
const externalSchema = "c8s.secrets-external/v1"

// BackendAzureKeyVault is the only external backend. One backend is
// configured at a time; the document names it so future backends share this
// route and document shape.
const BackendAzureKeyVault = "azure-keyvault"

// ExternalDocument is the PUT body: the backend, its credential, and the full
// mapping set, applied atomically. An empty document (no credential, no
// mappings) disconnects the backend.
type ExternalDocument struct {
	Schema     string                  `json:"schema"`
	Backend    string                  `json:"backend"`
	Credential AzureCredential         `json:"credential"`
	Mappings   map[string]AzureMapping `json:"mappings"`
}

// externalDocumentRaw decodes with Mappings deferred: duplicate keys in a JSON
// object decode last-wins, silently applying whichever binding appeared last,
// so the mapping set is parsed as an ordered stream that rejects them.
type externalDocumentRaw struct {
	Schema     string          `json:"schema"`
	Backend    string          `json:"backend"`
	Credential AzureCredential `json:"credential"`
	Mappings   json.RawMessage `json:"mappings"`
}

// parseExternalDocument decodes and validates a document. Trailing data after
// the top-level value is rejected: a whole-backend config document should be
// exactly one JSON value.
func parseExternalDocument(body []byte) (*ExternalDocument, error) {
	var raw externalDocumentRaw
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("unexpected data after the document")
	}
	mappings, err := parseMappings(raw.Mappings)
	if err != nil {
		return nil, err
	}
	doc := &ExternalDocument{Schema: raw.Schema, Backend: raw.Backend, Credential: raw.Credential, Mappings: mappings}
	if err := validateExternalDocument(doc); err != nil {
		return nil, err
	}
	normalizeExternalDocument(doc)
	return doc, nil
}

// parseMappings decodes the mappings object, rejecting a duplicate key rather
// than letting it last-win.
func parseMappings(raw json.RawMessage) (map[string]AzureMapping, error) {
	out := map[string]AzureMapping{}
	if len(raw) == 0 {
		return out, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("mappings must be an object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := keyTok.(string)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate mapping %q", key)
		}
		var m AzureMapping
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("mapping %q: %w", key, err)
		}
		out[key] = m
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("unexpected data after the mappings object")
	}
	return out, nil
}

// azureNameRe is the Key Vault secret-name charset.
var azureNameRe = regexp.MustCompile(`^[0-9a-zA-Z-]+$`)

// validateExternalDocument checks a decoded document. Every mapping key must
// be canonical — the request side rejects non-canonical paths, so a key that
// cannot match a request is a path the operator believes vault-backed that
// actually mints. The vault URL is validated because CDS sends a bearer token
// to it.
func validateExternalDocument(doc *ExternalDocument) error {
	if doc.Schema != externalSchema {
		return fmt.Errorf("unknown schema %q (expected %q)", doc.Schema, externalSchema)
	}
	if doc.Backend != BackendAzureKeyVault {
		return fmt.Errorf("unknown backend %q (expected %q)", doc.Backend, BackendAzureKeyVault)
	}
	if len(doc.Mappings) == 0 {
		if doc.Credential != (AzureCredential{}) {
			return fmt.Errorf("credential without mappings: apply a non-empty mapping set or an empty document")
		}
		return nil
	}
	if doc.Credential.TenantID == "" || doc.Credential.ClientID == "" || doc.Credential.ClientSecret == "" {
		return fmt.Errorf("credential requires tenantId, clientId and clientSecret")
	}
	if strings.ContainsAny(doc.Credential.TenantID, "/?#") {
		return fmt.Errorf("tenantId must not contain URL separators")
	}
	for p, m := range doc.Mappings {
		if _, err := pkgallowlist.CanonicalSecretPath(p); err != nil {
			return fmt.Errorf("mapping %q: %w", p, err)
		}
		if p == "/external" {
			return fmt.Errorf("mapping %q: the path is reserved for the external-KMS config endpoint", p)
		}
		if !azureNameRe.MatchString(m.Name) {
			return fmt.Errorf("mapping %q: vault secret name must match %s", p, azureNameRe)
		}
		if strings.ContainsAny(m.Vault, "?#") {
			return fmt.Errorf("mapping %q: vault must be a bare https URL", p)
		}
		u, err := url.Parse(m.Vault)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return fmt.Errorf("mapping %q: vault must be a bare https URL", p)
		}
		// CDS sends a bearer token to this host, so it must be exactly one
		// vault-name label on the global-cloud suffix — no port, no extra
		// labels, no lookalikes.
		label, ok := strings.CutSuffix(u.Host, ".vault.azure.net")
		if !ok || !azureNameRe.MatchString(label) {
			return fmt.Errorf("mapping %q: vault host must be <name>.vault.azure.net (global cloud only)", p)
		}
	}
	return nil
}

// normalizeExternalDocument canonicalizes a validated document in place:
// vault URLs drop a trailing slash so fetch URL construction cannot produce
// "//secrets/".
func normalizeExternalDocument(doc *ExternalDocument) {
	for p, m := range doc.Mappings {
		m.Vault = strings.TrimSuffix(m.Vault, "/")
		doc.Mappings[p] = m
	}
}

// ExternalConfigHandler serves PUT and GET on ExternalRoute. PUT replaces the
// whole backend state; GET reports it. Authorization is the operator key, via
// the same verifier the allowlist writes use.
type ExternalConfigHandler struct {
	Backend *ExternalBackend
	Mem     *MemoryStore
	// Authorize is operatorauth.Verifier.Authorize. Nil rejects every request.
	Authorize func(r *http.Request, body []byte) error
	// MaxBodyBytes caps the request body; zero means DefaultMaxOperatorBodyBytes.
	MaxBodyBytes int64

	Logger *slog.Logger
}

func (h ExternalConfigHandler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h ExternalConfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodPut:
		h.put(w, r, body)
	case http.MethodGet:
		h.get(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h ExternalConfigHandler) put(w http.ResponseWriter, r *http.Request, body []byte) {
	doc, err := parseExternalDocument(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	if len(doc.Mappings) == 0 {
		if err := h.Backend.Clear(); err != nil {
			h.logger().Error("external KMS config clear failed", "error", err)
			http.Error(w, "config clear failed", http.StatusInternalServerError)
			return
		}
		h.logger().Info("external KMS config cleared")
		writeExternalStatus(w, h.Backend.Status(h.Mem))
		return
	}
	if err := h.Backend.Apply(doc.Credential, doc.Mappings); err != nil {
		h.logger().Error("external KMS config apply failed", "error", err)
		http.Error(w, "config apply failed", http.StatusInternalServerError)
		return
	}
	h.logger().Info("external KMS config applied", "backend", doc.Backend, "mappings", len(doc.Mappings))
	writeExternalStatus(w, h.Backend.Status(h.Mem))
}

func (h ExternalConfigHandler) get(w http.ResponseWriter, _ *http.Request) {
	writeExternalStatus(w, h.Backend.Status(h.Mem))
}

func writeExternalStatus(w http.ResponseWriter, st ExternalStatus) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(st)
}

func (h ExternalConfigHandler) authorize(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	return authorizeOperator(w, r, h.Authorize, h.MaxBodyBytes, h.logger(), "external KMS config request")
}

// externalMappingsFile is the persisted mapping set's filename, placed beside
// the allowlist database so it inherits the same durability class.
const externalMappingsFile = "external-mappings.json"

// LoadExternalMappings reads the mapping set an earlier run persisted beside
// the allowlist DB and returns it with the backend's persist hook. The file
// holds paths, vaults and secret names only — never the credential. An empty
// allowlist DB path disables persistence rather than writing beside the
// process's working directory.
func LoadExternalMappings(allowlistDBPath string) (map[string]AzureMapping, func(map[string]AzureMapping) error, error) {
	if allowlistDBPath == "" {
		return nil, nil, nil
	}
	path := filepath.Join(filepath.Dir(allowlistDBPath), externalMappingsFile)
	persist := func(m map[string]AzureMapping) error {
		data, err := json.Marshal(m)
		if err != nil {
			return err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, persist, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m map[string]AzureMapping
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, persist, nil
}
