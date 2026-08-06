package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Azure direct brokering: CDS fetches a Key Vault secret at release time and
// forwards it to the attested workload. The credential arrives over the
// operator channel (PUT on ExternalRoute) and lives in process memory only; the
// non-secret mapping set is persisted so a restarted CDS fails closed rather
// than minting over a path the operator believes vault-backed.

// azureAPIVersion is the pinned Key Vault data-plane version. 7.4 is the
// legacy scheme's last stable; the surface used here (GET secret, token
// client-credentials) is identical in every later version.
const azureAPIVersion = "7.4"

// azureScope is the Entra token audience for Key Vault data plane. Global
// cloud only: sovereign clouds use a different login host and scope and are
// rejected at config validation.
const azureScope = "https://vault.azure.net/.default"

// azureLoginHost is the global-cloud Entra token endpoint host.
const azureLoginHost = "https://login.microsoftonline.com"

// azureTimeout bounds one Entra or vault round trip.
const azureTimeout = 10 * time.Second

// azureMaxBodyBytes bounds a response from Entra or the vault before decode.
// A token is ~2 KiB; a secret bundle is the value plus a small envelope, and
// the value itself is capped again against the store limit after decode.
const azureMaxBodyBytes = 1 << 20

// errAzureUnauthorized marks a vault 401 so the fetch can drop its cached
// token and try once more: the credential may have been rotated at Entra
// out from under a token that has not yet expired.
var errAzureUnauthorized = errors.New("secrets: azure rejected the token")

// AzureCredential is the Entra app registration the operator provisioned.
// ClientSecret is write-only: it is accepted over the operator channel and
// never served back, logged, or persisted.
type AzureCredential struct {
	TenantID     string `json:"tenantId"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// AzureMapping binds one canonical store path to one vault secret. Versionless
// by design: the fetch resolves latest, so vault-side rotation takes effect on
// the next pod start.
type AzureMapping struct {
	Vault string `json:"vault"`
	Name  string `json:"name"`
}

// FetchRecord is the per-path outcome of the last fetch, for status. It never
// carries a value.
type FetchRecord struct {
	At  time.Time `json:"at"`
	Err string    `json:"err,omitempty"`
}

// azureConfig is one applied document: credential, mappings, and the token
// cache that belongs to exactly this credential. It is immutable after
// construction; a replace builds a new one.
type azureConfig struct {
	cred     AzureCredential
	mappings map[string]AzureMapping
	tokens   *tokenCache
	client   *http.Client
	loginURL string // Entra token endpoint prefix; a field so tests can fake it

	mu   sync.Mutex
	last map[string]FetchRecord
}

// newAzureConfig builds a config from a validated document.
func newAzureConfig(cred AzureCredential, mappings map[string]AzureMapping) *azureConfig {
	return &azureConfig{
		cred:     cred,
		mappings: mappings,
		tokens:   &tokenCache{},
		client: &http.Client{
			Timeout: azureTimeout,
			// A redirect from Entra or the vault is an error, never a hint:
			// following it would carry the bearer token to a host the
			// operator did not name.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		loginURL: azureLoginHost,
		last:     make(map[string]FetchRecord),
	}
}

// fetch returns the vault value for a mapped path.
func (c *azureConfig) fetch(ctx context.Context, path string) ([]byte, error) {
	m := c.mappings[path]
	value, err := c.fetchOnce(ctx, m)
	if errors.Is(err, errAzureUnauthorized) {
		c.tokens.invalidate()
		value, err = c.fetchOnce(ctx, m)
	}
	c.mu.Lock()
	c.last[path] = FetchRecord{At: time.Now(), Err: errString(err)}
	c.mu.Unlock()
	return value, err
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// transportErr strips the request URL from a transport error: a *url.Error
// carries method and full URL — query string included — and these errors reach
// the CDS log and the operator status, where the contract is status only.
func transportErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// fetchOnce performs one token + GET round trip.
func (c *azureConfig) fetchOnce(ctx context.Context, m AzureMapping) ([]byte, error) {
	token, err := c.tokens.get(func() (string, time.Time, error) {
		return fetchToken(ctx, c.client, c.loginURL, c.cred)
	})
	if err != nil {
		return nil, err
	}

	u := m.Vault + "/secrets/" + url.PathEscape(m.Name) + "?api-version=" + azureAPIVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets: build vault request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secrets: vault request failed: %w", transportErr(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errAzureUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		// The body is not read: the status alone is reported, and the workload
		// gets the same opaque failure as every other fetch error.
		return nil, fmt.Errorf("secrets: vault answered %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, azureMaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("secrets: read vault response: %w", err)
	}
	var bundle struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &bundle); err != nil {
		return nil, fmt.Errorf("secrets: decode vault response: %w", err)
	}
	// The string is delivered verbatim: encoding is part of the vault-side
	// value contract, unlike `c8s secrets put`, where base64 is the wire
	// envelope CDS strips.
	return []byte(bundle.Value), nil
}

// tokenCache holds the Entra access token for one credential. The mutex makes
// a refresh single-flight; it is never held by the config swap path, so a slow
// Entra call stalls only other fetches, never an apply.
type tokenCache struct {
	mu     sync.Mutex
	token  string
	expiry time.Time
}

// get returns a usable token, calling fetch to refresh when the cache is
// empty or inside the expiry margin. fetch is a callback so the cache holds no
// Azure knowledge of its own.
func (c *tokenCache) get(fetch func() (string, time.Time, error)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiry) {
		return c.token, nil
	}
	token, expiry, err := fetch()
	if err != nil {
		return "", err
	}
	c.token, c.expiry = token, expiry
	return token, nil
}

func (c *tokenCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
	c.expiry = time.Time{}
}

// fetchToken runs the client-credentials grant against Entra.
func fetchToken(ctx context.Context, client *http.Client, loginURL string, cred AzureCredential) (string, time.Time, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cred.ClientID},
		"client_secret": {cred.ClientSecret},
		"scope":         {azureScope},
	}
	u := loginURL + "/" + url.PathEscape(cred.TenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("secrets: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("secrets: token request failed: %w", transportErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("secrets: entra answered %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, azureMaxBodyBytes))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("secrets: read token response: %w", err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", time.Time{}, fmt.Errorf("secrets: decode token response: %w", err)
	}
	if tok.AccessToken == "" || tok.ExpiresIn <= 0 {
		return "", time.Time{}, fmt.Errorf("secrets: token response missing access_token or expires_in")
	}
	// Refresh at 80% of the stated lifetime so a fetch never starts with a
	// token that expires mid-flight.
	return tok.AccessToken, time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second * 4 / 5), nil
}
