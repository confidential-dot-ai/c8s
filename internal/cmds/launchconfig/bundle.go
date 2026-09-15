package launchconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// A bundle is one cluster's complete launch input, laid out so each node's
// opkeydata disk is one directory and the operator's private material sits
// beside it, never inside it:
//
//	<dir>/leader.key      leader launch key; also the operator key that
//	                      get-kubeconfig and signed CDS writes use
//	<dir>/follower.key    the one follower launch key this cluster trusts
//	<dir>/leader.json     client policy pinning the leader (C8S_MEASUREMENTS_CONFIG)
//	<dir>/leader/         pubkey, launch.yaml, launch.yaml.sig
//	<dir>/<follower>/     pubkey, launch.yaml, launch.yaml.sig, one per follower
const (
	leaderKeyFile   = "leader.key"
	followerKeyFile = "follower.key"
	leaderPolicy    = "leader.json"
	leaderDir       = "leader"
	pubkeyFile      = "pubkey"
	documentFile    = "launch.yaml"
	signatureFile   = documentFile + ".sig"
)

// BundleOptions describes a new cluster's launch bundle.
type BundleOptions struct {
	Dir           string
	ClusterID     string
	ManifestPath  string
	VCPUs         int
	LeaderName    string
	LeaderAddress string
	Followers     []string
	TLSSAN        string
	WorkloadsPath string
}

// NewBundle generates the cluster's two launch keys and join tokens, writes
// and signs the leader document plus one follower document per name, and
// emits the client policy. Dir must not exist; a failed run removes it so a
// half-written bundle can never be attached.
func NewBundle(opts BundleOptions) (err error) {
	if opts.Dir == "" || opts.ClusterID == "" || opts.ManifestPath == "" {
		return errors.New("--out, --cluster-id and --image-manifest are required")
	}
	if opts.LeaderName == "" {
		opts.LeaderName = opts.ClusterID + "-leader"
	}
	if opts.TLSSAN == "" {
		opts.TLSSAN = defaultTLSSAN
	}
	if len(opts.Followers) > 0 && opts.LeaderAddress == "" {
		return errors.New("--leader-address is required when the bundle has followers: a follower must be told where its leader is")
	}
	image, err := imageFromManifest(opts.ManifestPath, opts.VCPUs)
	if err != nil {
		return err
	}
	var workloads string
	if opts.WorkloadsPath != "" {
		data, err := readBounded(opts.WorkloadsPath, MaxDocumentSize)
		if err != nil {
			return err
		}
		workloads = string(data)
	}
	if err := os.Mkdir(opts.Dir, 0o700); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(opts.Dir)
		}
	}()
	leaderKey, leaderPub, err := newLaunchKey(filepath.Join(opts.Dir, leaderKeyFile))
	if err != nil {
		return err
	}
	_, followerPub, err := newLaunchKey(filepath.Join(opts.Dir, followerKeyFile))
	if err != nil {
		return err
	}
	serverToken, err := newToken()
	if err != nil {
		return err
	}
	agentToken, err := newToken()
	if err != nil {
		return err
	}
	leader := Document{
		SchemaVersion:              SchemaVersion,
		ClusterID:                  opts.ClusterID,
		Role:                       Leader,
		Image:                      image,
		Node:                       Node{Name: opts.LeaderName},
		RKE2:                       RKE2{ServerToken: serverToken, AgentToken: agentToken},
		Leader:                     LeaderConfig{Address: opts.LeaderAddress, OperatorPublicKey: leaderPub},
		FollowerOperatorPublicKeys: []string{followerPub},
		TLSSAN:                     opts.TLSSAN,
		Workloads:                  workloads,
	}
	if err := writeSignedDocument(filepath.Join(opts.Dir, leaderDir), leader, leaderKey, leaderPub); err != nil {
		return err
	}
	pins, err := leader.referenceValues()
	if err != nil {
		return err
	}
	policy, err := measurements.Format(measurements.ReferenceValues{TEE: pins.TEE, Entries: pins.Entries[:1]})
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(opts.Dir, leaderPolicy), policy, 0o644); err != nil {
		return err
	}
	for _, name := range opts.Followers {
		if err := AddFollower(opts.Dir, name, opts.LeaderAddress); err != nil {
			return err
		}
	}
	return nil
}

// AddFollower derives a follower document from the bundle's leader document
// (same cluster, image, agent token, keys and SAN; never the server token),
// signs it with the bundle's follower key and writes <dir>/<name>. It works
// on a bundle created earlier, so a cluster can grow without regenerating or
// re-signing anything the leader already booted with.
func AddFollower(dir, name, leaderAddress string) (err error) {
	if !dnsLabel(name) {
		return fmt.Errorf("follower name %q must be an RFC1123 label", name)
	}
	if name == leaderDir {
		return fmt.Errorf("follower name %q is reserved for the leader", name)
	}
	leaderData, err := readBounded(filepath.Join(dir, leaderDir, documentFile), MaxDocumentSize)
	if err != nil {
		return fmt.Errorf("bundle has no leader document: %w", err)
	}
	leader, err := Parse(leaderData)
	if err != nil {
		return fmt.Errorf("bundle leader document: %w", err)
	}
	if leader.Role != Leader {
		return errors.New("bundle leader document does not carry the leader role")
	}
	if name == leader.Node.Name {
		return fmt.Errorf("follower name %q is the leader's node name", name)
	}
	key, err := certutil.LoadECPrivateKeyFile(filepath.Join(dir, followerKeyFile))
	if err != nil {
		return fmt.Errorf("bundle follower key: %w", err)
	}
	pub, err := publicKeyPEM(key)
	if err != nil {
		return err
	}
	if leaderAddress == "" {
		leaderAddress = leader.Leader.Address
	}
	if leaderAddress == "" {
		return errors.New("--leader-address is required: the leader document leaves its address to autodetection, and a follower must be told where its leader is")
	}
	follower := *leader
	follower.Role = Follower
	follower.Node = Node{Name: name}
	follower.RKE2 = RKE2{AgentToken: leader.RKE2.AgentToken}
	follower.Leader.Address = leaderAddress
	return writeSignedDocument(filepath.Join(dir, name), follower, key, pub)
}

// imageFromManifest turns the build's provenanced manifest into the launch
// document's image pins. The manifest's shape names the platform; an SNP
// manifest carries one launch digest per vCPU count, so vcpus selects one
// unless the manifest has only one.
func imageFromManifest(path string, vcpus int) (Image, error) {
	identity, err := runtimemeasure.LoadImageManifest(path)
	if err != nil {
		return Image{}, fmt.Errorf("--image-manifest: %w", err)
	}
	variants := identity.LaunchDigests()
	var image Image
	switch identity.Family() {
	case teetypes.FamilyTDX:
		if vcpus != 0 {
			return Image{}, errors.New("--vcpus applies to SNP manifests only: a TDX image has one measurement for every VM shape")
		}
		image = Image{Platform: "tdx", Measurement: hex.EncodeToString(variants[0].Digest[:]), RTMRs: map[int]string{}}
		for idx, value := range identity.RTMRs() {
			image.RTMRs[idx] = hex.EncodeToString(value[:])
		}
	case teetypes.FamilySNP:
		if vcpus == 0 && len(variants) > 1 {
			return Image{}, fmt.Errorf("--vcpus is required: %s pins %d SNP launch digests, one per vCPU count", path, len(variants))
		}
		label := ""
		if vcpus != 0 {
			label = fmt.Sprintf("smp%d", vcpus)
		}
		for _, v := range variants {
			if label == "" || v.Label == label {
				image = Image{Platform: "snp", Measurement: hex.EncodeToString(v.Digest[:])}
			}
		}
		if image.Platform == "" {
			return Image{}, fmt.Errorf("--vcpus %d: %s pins no SNP launch digest for that vCPU count", vcpus, path)
		}
	default:
		return Image{}, fmt.Errorf("--image-manifest: %s pins TEE family %q, want tdx or sev-snp", path, identity.Family())
	}
	return image, nil
}

// writeSignedDocument renders doc, proves the rendering parses under the
// same strict rules the guest applies, signs it with key and writes the
// three opkeydata files into dir, which must not exist yet.
func writeSignedDocument(dir string, doc Document, key *ecdsa.PrivateKey, pub string) (err error) {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("render launch document: %w", err)
	}
	if _, err := Parse(data); err != nil {
		return fmt.Errorf("rendered launch document for %s: %w", doc.Node.Name, err)
	}
	signature, err := operatorauth.SignDetached(key, data)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{pubkeyFile, []byte(pub), 0o644}, {documentFile, data, 0o600}, {signatureFile, []byte(signature + "\n"), 0o600}} {
		// The document carries the join tokens: operator-readable only.
		if err := writeNew(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

func newLaunchKey(path string) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate launch key: %w", err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return nil, "", err
	}
	if err := writeNew(path, keyPEM, 0o600); err != nil {
		return nil, "", err
	}
	pub, err := publicKeyPEM(key)
	if err != nil {
		return nil, "", err
	}
	return key, pub, nil
}

func publicKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("encode launch public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate join token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}
