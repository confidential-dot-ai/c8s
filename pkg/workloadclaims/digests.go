// The sandbox-digests callback: CDS asks the inventory that admitted a pod
// what that pod is actually running, at issuance time, over mutually-attested
// RA-TLS (docs/ratls.md, "Sandbox identity").
//
// Direction matters. The requester never reports its own images — it only
// proves, via the inventory-signed sandbox token, which sandbox it is in. CDS
// then asks the inventory directly, so the answer is live at issuance and
// comes from the component that made the admission decision.

package workloadclaims

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// ValidateInventoryAddr reports whether addr is a dialable inventory address.
// See parseInventoryAddr for the rules.
func ValidateInventoryAddr(addr string) error {
	_, err := parseInventoryAddr(addr)
	return err
}

// parseInventoryAddr validates addr and returns it rebuilt from its parsed
// parts, so what gets dialed is derived from a checked IP and port rather than
// from the caller's bytes.
//
// SECURITY: this bounds a request-forgery primitive. The address rides a sandbox
// token, and a token is mintable by anything holding a CDS /attest-key EAR —
// which on node-CVM is every pod, since they all share the node's launch
// measurement. Without these rules any workload could steer CDS's callback at an
// address of its choosing. Hence:
//
//   - an IP literal, never a name: a resolvable name lets DNS decide the
//     destination after the check (rebinding), and every real deployment
//     advertises an IP already (downward-API hostIP/podIP, or the outbound-route
//     inference in ResolveAdvertiseAddr);
//   - global unicast only: loopback, link-local (169.254.0.0/16 and fe80::/10 —
//     the cloud metadata service), multicast, and the unspecified address are all
//     rejected. An inventory has no legitimate reason to advertise any of them,
//     so this costs nothing real.
//
// What remains is a connection to a routable address on the requester's chosen
// port. RA-TLS makes it useless for talking to anything that is not an attested
// peer, and Fetch's caller must not echo the outcome back — see
// docs/THREAT_MODEL.md.
func parseInventoryAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("workloadclaims: inventory address %q is not host:port: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("workloadclaims: inventory address %q must use an IP literal, not a name", addr)
	}
	if !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
		return "", fmt.Errorf("workloadclaims: inventory address %q is not a routable unicast address", addr)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("workloadclaims: inventory address %q has an invalid port", addr)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(p)), nil
}

// ResolveAdvertiseAddr returns the host:port an inventory signs into its
// sandbox tokens for CDS to dial back. host wins when set (the chart supplies
// it from the downward API — status.hostIP on node-CVM, status.podIP in a kata
// guest). Otherwise it is inferred as the local address the kernel would use
// to reach cdsHost, which is the interface CDS's replies already traverse.
//
// A wrong answer here fails closed and loudly: CDS cannot reach the endpoint,
// so issuance is refused rather than silently unverified.
func ResolveAdvertiseAddr(host string, port int, cdsHost string) (string, error) {
	if host == "" {
		var err error
		if host, err = outboundHost(cdsHost); err != nil {
			return "", fmt.Errorf("workloadclaims: infer the inventory advertise address (set it explicitly): %w", err)
		}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if err := ValidateInventoryAddr(addr); err != nil {
		return "", err
	}
	return addr, nil
}

// outboundHost reports the local IP the kernel would source from when talking
// to target. The UDP socket is unconnected on the wire — no packet is sent —
// so this is a routing-table lookup, not a reachability test.
func outboundHost(target string) (string, error) {
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "443")
	}
	conn, err := net.Dial("udp", target)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return "", err
	}
	return host, nil
}

// DigestsServerTLSConfig builds the inventory's listener config for
// ServeDigests: it presents an RA-TLS certificate proving the inventory runs in
// a TEE, and requires the caller to present a hardware-attested one too. With
// cdsMeasurements set the caller's launch measurement must be in it, so the
// endpoint discloses what a node runs only to a CDS on an expected measurement;
// empty pins no measurement, and any TEE on the network can then read it.
// UNSAFE outside development; callers warn.
func DigestsServerTLSConfig(platform string, attestFunc func(ctx context.Context, customData string) (string, error), attestationApiURL string, cdsMeasurements [][]byte, certTTL time.Duration) (*tls.Config, *ratls.CertManager, error) {
	if err := requireAttestationApi(attestationApiURL); err != nil {
		return nil, nil, err
	}
	return ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   ratls.NormalizePlatform(platform),
		AttestFunc: attestFunc,
		CertTTL:    certTTL,
		ClientPolicy: &ratls.VerifyPolicy{
			Measurements:      cdsMeasurements,
			AttestationApiURL: attestationApiURL,
		},
	})
}

// requireAttestationApi rejects an empty attestation-api URL at construction.
// Both sides feed it to a ratls.VerifyPolicy, which fails closed without one —
// catching it here makes a missing URL a startup error instead of a handshake
// failure inside the first pod's issuance deadline.
func requireAttestationApi(url string) error {
	if url == "" {
		return fmt.Errorf("workloadclaims: the sandbox-digests callback requires an attestation-api URL to verify its peer against")
	}
	return nil
}

// DigestsClient is CDS's side of the callback: an RA-TLS client that verifies
// the inventory's attestation — pinning its launch measurement when one is
// configured — and presents CDS's own RA-TLS certificate, so the inventory can
// pin CDS in turn.
type DigestsClient struct {
	http    *http.Client
	timeout time.Duration
}

// NewDigestsClient builds the client. measurements are the launch digests an
// inventory may present — the same allowlist CDS pins for the inventory's
// /attest-key EAR, so a sandbox token and the callback that follows it are
// held to one standard. Empty accepts any RA-TLS-attested inventory, matching
// what an empty allowlist already means for the EAR: UNSAFE outside
// development; callers warn.
//
// It warms its own RA-TLS certificate before returning: provisioning costs an
// attestation round-trip, and paying it lazily would put it inside the first
// pod's issuance deadline.
func NewDigestsClient(ctx context.Context, platform string, attestFunc func(ctx context.Context, customData string) (string, error), attestationApiURL string, measurements [][]byte, timeout time.Duration) (*DigestsClient, error) {
	if err := requireAttestationApi(attestationApiURL); err != nil {
		return nil, err
	}
	tlsCfg, certMgr, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy: &ratls.VerifyPolicy{
			Measurements:      measurements,
			AttestationApiURL: attestationApiURL,
		},
		Platform:   ratls.NormalizePlatform(platform),
		AttestFunc: attestFunc,
	})
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: build sandbox-digests client: %w", err)
	}
	warmupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := certMgr.WarmUp(warmupCtx); err != nil {
		return nil, fmt.Errorf("workloadclaims: warm up sandbox-digests client cert: %w", err)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &DigestsClient{
		http: &http.Client{
			Timeout: timeout,
			// Fresh Transport, so Proxy stays nil: no HTTP_PROXY can interpose
			// on a call whose whole point is to reach one attested peer.
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		timeout: timeout,
	}, nil
}

// ErrSandboxUnknown reports that the inventory does not know the sandbox — it
// never admitted it, or the pod is already gone. Distinguished from a
// transport or policy failure so the caller can say which happened; both are
// fail-closed for issuance.
var ErrSandboxUnknown = fmt.Errorf("workloadclaims: inventory does not know this sandbox")

// Fetch asks the inventory at addr which image digests sandboxID is running.
// addr comes from the verified sandbox token, so it names the inventory that
// vouched for the sandbox; the RA-TLS handshake then proves whatever answers
// there is a TEE on an allowed measurement.
//
// Both inputs are rebuilt from validated parts before they reach the URL
// (parseInventoryAddr, ratls.ValidateSandboxID), because both originate in a
// token a workload can mint.
func (c *DigestsClient) Fetch(ctx context.Context, addr, sandboxID string) ([]string, error) {
	dialAddr, err := parseInventoryAddr(addr)
	if err != nil {
		return nil, err
	}
	if err := ratls.ValidateSandboxID(sandboxID); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	url := "https://" + dialAddr + SandboxDigestsPrefix + sandboxID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: reach inventory %s: %w", dialAddr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrSandboxUnknown
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("workloadclaims: inventory %s returned %d: %s", dialAddr, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out SandboxDigestsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("workloadclaims: decode inventory response: %w", err)
	}
	return out.Digests, nil
}
