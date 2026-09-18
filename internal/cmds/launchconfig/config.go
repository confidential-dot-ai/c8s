// Package launchconfig authenticates and stages the boot configuration of a
// measured node image. It is the only source of server/agent selection.
// Each cluster needs its own distinct server/agent launch keys: ClusterID
// names a cluster, while the launch keys establish its remote trust boundary.
package launchconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	SchemaVersion            = "c8s-launch/v1"
	DefaultAttestationAPIURL = "http://127.0.0.1:8400"
	// Dir holds the root-only artifacts Stage writes for the node services.
	Dir               = "/run/confos/launch"
	DefaultStagedPath = Dir + "/config.json"
	MaxDocumentSize   = 1024 * 1024
	maxSignatureSize  = 4096
	maxAgentKeys      = 128
	defaultTLSSAN     = "c8s.local"
)

// Role selects the services started for this boot, without changing its image.
type Role string

const (
	Server Role = "server"
	Agent  Role = "agent"
)

// Document is the signed launch.yaml wire contract. All secrets are boot
// inputs; agent documents must never carry the control-plane server token.
type Document struct {
	SchemaVersion           string       `yaml:"schemaVersion" json:"schemaVersion"`
	ClusterID               string       `yaml:"clusterID" json:"clusterID"`
	Role                    Role         `yaml:"role" json:"role"`
	Image                   Image        `yaml:"image" json:"image"`
	Node                    Node         `yaml:"node" json:"node"`
	RKE2                    RKE2         `yaml:"rke2" json:"rke2"`
	Server                  ServerConfig `yaml:"server" json:"server"`
	AgentOperatorPublicKeys []string     `yaml:"agentOperatorPublicKeys" json:"agentOperatorPublicKeys"`
	TLSSAN                  string       `yaml:"tlsSAN,omitempty" json:"tlsSAN"`
	// Workloads is an optional strict c8s.allowlist/v1 JSON document. Keeping
	// its existing wire schema avoids an independent YAML policy language.
	Workloads          string `yaml:"workloads,omitempty" json:"workloads,omitempty"`
	serverTokenPresent bool
}

// Image pins this boot's complete software identity; RTMR[0] varies by VM
// shape and RTMR[3] binds its launch key, so neither belongs in these pins.
type Image struct {
	Platform    string         `yaml:"platform" json:"platform"`
	Measurement string         `yaml:"measurement" json:"measurement"`
	RTMRs       map[int]string `yaml:"rtmrs,omitempty" json:"rtmrs,omitempty"`
}

type Node struct {
	Name       string `yaml:"name" json:"name"`
	IP         string `yaml:"ip,omitempty" json:"ip,omitempty"`
	ExternalIP string `yaml:"externalIP,omitempty" json:"externalIP,omitempty"`
}

type RKE2 struct {
	ServerToken string `yaml:"serverToken,omitempty" json:"serverToken,omitempty"`
	AgentToken  string `yaml:"agentToken" json:"agentToken"`
}

type ServerConfig struct {
	// Address may be omitted only for a server; Stage resolves its own IP.
	Address string `yaml:"address,omitempty" json:"address"`
	// Exact PEM bytes are hardware-bound. Equivalent PEM encodings of one
	// key are still one authorization identity, not two different roles.
	OperatorPublicKey string `yaml:"operatorPublicKey" json:"operatorPublicKey"`
}

// Config selects trusted local facilities and launch files. RootDir rebases
// fixed output paths for tests; it is not exposed as a command-line flag.
type Config struct {
	Platform          string
	AttestationAPIURL string
	DocumentPath      string
	SignaturePath     string
	RootDir           string
}

var loadMeasuredIdentity = credrelease.LoadMeasuredIdentity

// Verified is created only after signature, image and role authorization pass.
// Its fields are private so staging cannot accidentally consume an unverified
// Document supplied by a caller.
type Verified struct {
	document    Document
	operatorPub []byte
	pins        refvalues.ReferenceValues
	cdsPins     refvalues.ReferenceValues
}

// Verify checks the signature before parsing host input and compares all image
// pins against one verified, fresh self-report. A keyless boot fails closed.
func Verify(ctx context.Context, cfg Config) (*Verified, error) {
	platform := teetypes.NormalizePlatform(cfg.Platform)
	if platform != teetypes.PlatformTDX && platform != teetypes.PlatformSNP {
		return nil, fmt.Errorf("platform must be tdx or snp")
	}
	if cfg.DocumentPath == "" || cfg.SignaturePath == "" {
		return nil, fmt.Errorf("both --config and --signature are required")
	}
	data, err := readBounded(cfg.DocumentPath, MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	signature, err := readBounded(cfg.SignaturePath, maxSignatureSize)
	if err != nil {
		return nil, err
	}
	api := cfg.AttestationAPIURL
	if api == "" {
		api = DefaultAttestationAPIURL
	}
	// credrelease compares against the verified report's family ("sev-snp",
	// "tdx"), not the launch tag ("snp", "tdx").
	measured, err := loadMeasuredIdentity(ctx, string(platform.Family()), api)
	if err != nil {
		return nil, fmt.Errorf("verify this boot's identity: %w", err)
	}
	if measured.OperatorKeyErr != nil {
		return nil, fmt.Errorf("launch configuration requires a measured operator key: %w", measured.OperatorKeyErr)
	}
	pub := measured.OperatorKey
	key, err := parseLaunchKey(string(pub))
	if err != nil {
		return nil, fmt.Errorf("measured launch key: %w", err)
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{key}, data, string(signature)); err != nil {
		return nil, fmt.Errorf("launch configuration signature: %w", err)
	}
	doc, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if teetypes.NormalizePlatform(doc.Image.Platform) != platform {
		return nil, fmt.Errorf("launch image platform does not match this boot")
	}
	digest := measured.Image.LaunchDigests()[0].Digest
	if !bytes.Equal(mustDecodeHex(doc.Image.Measurement), digest[:]) {
		return nil, fmt.Errorf("launch image measurement does not match this boot")
	}
	rtmrs := measured.Image.RTMRs()
	for i, value := range doc.Image.RTMRs {
		observed, ok := rtmrs[i]
		if !ok || !bytes.Equal(mustDecodeHex(value), observed[:]) {
			return nil, fmt.Errorf("launch image RTMR[%d] does not match this boot", i)
		}
	}
	if err := doc.authorizeKey(pub, key); err != nil {
		return nil, err
	}
	pins, err := doc.referenceValues()
	if err != nil {
		return nil, err
	}
	return &Verified{
		document: *doc, operatorPub: pub, pins: pins,
		cdsPins: refvalues.ReferenceValues{Family: pins.Family, Images: pins.Images[:1]},
	}, nil
}

// Parse strictly validates the offline launch document. Guest callers must
// use Verify first; Parse alone provides no authentication.
func Parse(data []byte) (*Document, error) {
	if len(data) == 0 || len(data) > MaxDocumentSize {
		return nil, fmt.Errorf("launch configuration must contain 1..%d bytes", MaxDocumentSize)
	}
	var tree yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("parse launch YAML: %w", err)
	}
	if err := singleDocument(dec); err != nil {
		return nil, err
	}
	if err := checkYAML(&tree, 0); err != nil {
		return nil, err
	}
	dec = yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode launch configuration: %w", err)
	}
	doc.serverTokenPresent = yamlPathPresent(&tree, "rke2", "serverToken")
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

func yamlPathPresent(n *yaml.Node, path ...string) bool {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return yamlPathPresent(n.Content[0], path...)
	}
	if len(path) == 0 {
		return true
	}
	if n.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == path[0] {
			return yamlPathPresent(n.Content[i+1], path[1:]...)
		}
	}
	return false
}

func singleDocument(dec *yaml.Decoder) error {
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("launch configuration must contain exactly one YAML document")
	}
	return nil
}

func checkYAML(n *yaml.Node, depth int) error {
	if depth > 32 {
		return fmt.Errorf("launch YAML nesting exceeds 32 levels")
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("launch YAML anchors and aliases are forbidden")
	}
	if n.Kind == yaml.MappingNode {
		seen := make(map[string]bool)
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Value == "<<" {
				return fmt.Errorf("invalid launch YAML mapping key")
			}
			// Integer keys occur only in the RTMR map. Alternative spellings
			// such as 01 and 1 must not collapse to one int after review.
			if k.Tag != "!!str" && (k.Tag != "!!int" || (k.Value != "1" && k.Value != "2")) {
				return fmt.Errorf("noncanonical launch YAML mapping key")
			}
			if seen[k.Value] {
				return fmt.Errorf("duplicate launch YAML key %q", k.Value)
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := checkYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

var tokenRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (d *Document) validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", SchemaVersion)
	}
	if !dnsLabel(d.ClusterID) {
		return fmt.Errorf("clusterID must be an RFC1123 label")
	}
	if !dnsLabel(d.Node.Name) {
		return fmt.Errorf("node.name must be an RFC1123 label")
	}
	if d.Role != Server && d.Role != Agent {
		return fmt.Errorf("role must be server or agent")
	}
	if d.Image.Platform != "tdx" && d.Image.Platform != "snp" {
		return fmt.Errorf("image.platform must be tdx or snp")
	}
	if !registerHex(d.Image.Measurement) {
		return fmt.Errorf("image.measurement must be 96 lowercase hex characters")
	}
	if d.Image.Platform == "tdx" {
		if len(d.Image.RTMRs) != 2 || !registerHex(d.Image.RTMRs[1]) || !registerHex(d.Image.RTMRs[2]) {
			return fmt.Errorf("TDX image must pin exactly RTMR[1] and RTMR[2]")
		}
	} else if len(d.Image.RTMRs) != 0 {
		return fmt.Errorf("SNP image cannot carry RTMR pins")
	}
	if d.Server.Address != "" || d.Role == Agent {
		if err := ValidateIPv4(d.Server.Address, true); err != nil {
			return fmt.Errorf("server.address: %w", err)
		}
	}
	if d.Node.IP != "" {
		if err := ValidateIPv4(d.Node.IP, false); err != nil {
			return fmt.Errorf("node.ip: %w", err)
		}
		if d.Node.IP == "0.0.0.0" {
			d.Node.IP = ""
		}
	}
	if d.Node.ExternalIP != "" {
		if err := ValidateIPv4(d.Node.ExternalIP, true); err != nil {
			return fmt.Errorf("node.externalIP: %w", err)
		}
	}
	if !tokenRE.MatchString(d.RKE2.AgentToken) {
		return fmt.Errorf("rke2.agentToken must be 64 lowercase hex characters")
	}
	if d.Role == Server {
		if !tokenRE.MatchString(d.RKE2.ServerToken) {
			return fmt.Errorf("server requires a 64-character lowercase hex rke2.serverToken")
		}
		if d.RKE2.ServerToken == d.RKE2.AgentToken {
			return fmt.Errorf("server and agent tokens must differ")
		}
	} else if d.RKE2.ServerToken != "" || d.serverTokenPresent {
		return fmt.Errorf("agent must not carry rke2.serverToken")
	}
	server, err := parseLaunchKey(d.Server.OperatorPublicKey)
	if err != nil {
		return fmt.Errorf("server.operatorPublicKey: %w", err)
	}
	if len(d.AgentOperatorPublicKeys) > maxAgentKeys {
		return fmt.Errorf("too many agent operator keys")
	}
	if d.Role == Agent && len(d.AgentOperatorPublicKeys) == 0 {
		return fmt.Errorf("agent requires agentOperatorPublicKeys")
	}
	seen := []*ecdsa.PublicKey{server}
	for _, raw := range d.AgentOperatorPublicKeys {
		key, err := parseLaunchKey(raw)
		if err != nil {
			return fmt.Errorf("agentOperatorPublicKeys: %w", err)
		}
		for _, previous := range seen {
			if key.Equal(previous) {
				return fmt.Errorf("server and agent public keys must be distinct and nonduplicated")
			}
		}
		seen = append(seen, key)
	}
	if d.TLSSAN == "" {
		d.TLSSAN = defaultTLSSAN
	}
	if len(d.TLSSAN) > 253 {
		return fmt.Errorf("tlsSAN exceeds DNS name length")
	}
	for _, label := range strings.Split(d.TLSSAN, ".") {
		if !dnsLabel(label) {
			return fmt.Errorf("tlsSAN must be a lowercase DNS hostname")
		}
	}
	if d.Workloads != "" {
		if !json.Valid([]byte(d.Workloads)) {
			return fmt.Errorf("workloads must contain one valid JSON document")
		}
		if _, err := allowlist.ParseJSON([]byte(d.Workloads)); err != nil {
			return fmt.Errorf("workloads: %w", err)
		}
	}
	return nil
}

func (d *Document) authorizeKey(pub []byte, key *ecdsa.PublicKey) error {
	server, _ := parseLaunchKey(d.Server.OperatorPublicKey) // validated above
	if d.Role == Server {
		if !bytes.Equal(pub, []byte(d.Server.OperatorPublicKey)) {
			return fmt.Errorf("server launch key does not match server.operatorPublicKey bytes")
		}
		return nil
	}
	if key.Equal(server) {
		return fmt.Errorf("agent must use a different launch key from its server")
	}
	for _, agent := range d.AgentOperatorPublicKeys {
		if bytes.Equal(pub, []byte(agent)) {
			return nil
		}
	}
	return fmt.Errorf("this agent's measured launch key is not in agentOperatorPublicKeys")
}

func parseLaunchKey(raw string) (*ecdsa.PublicKey, error) {
	if len(raw) > 8192 {
		return nil, fmt.Errorf("launch public key is too large")
	}
	return runtimemeasure.ParsePublicKeyPEM([]byte(raw))
}

func dnsLabel(s string) bool { return len(validation.IsDNS1123Label(s)) == 0 }

func registerHex(s string) bool {
	if len(s) != sha512.Size384*2 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func mustDecodeHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

// ValidateIPv4 accepts an IPv4 address; routable additionally requires
// global unicast, so loopback and unspecified addresses cannot be published.
func ValidateIPv4(raw string, routable bool) error {
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("must be an IPv4 address")
	}
	if routable && !addr.IsGlobalUnicast() {
		return fmt.Errorf("must be a unicast IPv4 address")
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("%s must be a regular file containing 1..%d bytes", path, limit)
	}
	data, err := readutil.ReadAll(f, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s exceeded the bounded read", path)
	}
	return data, nil
}

func (d *Document) referenceValues() (refvalues.ReferenceValues, error) {
	tee := teetypes.FamilySNP
	if d.Image.Platform == "tdx" {
		tee = teetypes.FamilyTDX
	}
	pins := refvalues.ReferenceValues{Family: tee}
	keys := append([]string{d.Server.OperatorPublicKey}, d.AgentOperatorPublicKeys...)
	for i, pub := range keys {
		name := "server"
		if i > 0 {
			name = fmt.Sprintf("agent-%d", i)
		}
		entry := remote.ImagePin{Name: name, Digest: mustDecodeHex(d.Image.Measurement), Anchor: []byte(pub)}
		if len(d.Image.RTMRs) > 0 {
			entry.RTMRs = make(map[int][]byte, len(d.Image.RTMRs))
			for idx, digest := range d.Image.RTMRs {
				entry.RTMRs[idx] = mustDecodeHex(digest)
			}
		}
		pins.Images = append(pins.Images, entry)
	}
	// Use the shared parser as a final schema check on the emitted policy.
	data, err := refvalues.Format(pins)
	if err != nil {
		return refvalues.ReferenceValues{}, err
	}
	return refvalues.Parse(data)
}

// CDSURL is derived from the signed server address and the image's fixed port.
func (d *Document) CDSURL() string { return "https://" + d.Server.Address + ":30808" }

// LoadStaged reads a root-owned boot artifact produced by Stage. It is not an
// authentication API for host input; only the fixed staged path is trusted.
func LoadStaged(path string) (*Document, error) {
	// JSON may expand a YAML string byte to a six-byte Unicode escape.
	data, err := readBounded(path, 6*MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode staged launch configuration: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("staged launch configuration contains trailing data")
	}
	if err := doc.validate(); err != nil {
		return nil, err
	}
	if doc.Server.Address == "" {
		return nil, fmt.Errorf("staged configuration must contain a resolved server address")
	}
	return &doc, nil
}
