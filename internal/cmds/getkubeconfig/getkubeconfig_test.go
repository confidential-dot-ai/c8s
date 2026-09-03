package getkubeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
)

// TestPolicyForSeedMatchesGuestConvention checks the client computes the same
// value the guest measures on a dynamic operator-key boot, re-derived here by
// hand: seed = SHA384(0x00*48 || SHA384(pubkey)) from the initrd, then
// RTMR[3] = SHA384(seed || SHA384("c8s/rtmr3/mode/dynamic/v1")) from the
// node image's mode event.
func TestPolicyForSeedMatchesGuestConvention(t *testing.T) {
	pub := []byte("-----BEGIN PUBLIC KEY-----\nMFk...\n-----END PUBLIC KEY-----\n")
	exp, err := policyFor(writeTestManifest(t, tdxManifest()), pub, nil)
	if err != nil {
		t.Fatal(err)
	}

	keyDigest := sha512.Sum384(pub)
	seed := sha512.Sum384(append(make([]byte, 48), keyDigest[:]...))
	modeDynamic := sha512.Sum384([]byte("c8s/rtmr3/mode/dynamic/v1"))
	want := sha512.Sum384(append(seed[:], modeDynamic[:]...))
	if hex.EncodeToString(exp.rtmr3[:]) != hex.EncodeToString(want[:]) {
		t.Errorf("expected RTMR[3] = %x, want %x", exp.rtmr3, want)
	}
}

// TestPublicKeyPEMFromPrivateMatchesMarshal confirms deriving the pubkey from a
// private key yields the PKIX PEM the launcher put on the opkeydata disk (the
// same encoding openssl ec -pubout / x509.MarshalPKIXPublicKey produce), so the
// RTMR[3] expected value matches. Both SEC1 and PKCS#8 private-key PEMs work.
func TestPublicKeyPEMFromPrivate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	want := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wantDER})

	// SEC1 "EC PRIVATE KEY"
	sec1, _ := x509.MarshalECPrivateKey(key)
	sec1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})
	got, err := publicKeyPEMFromPrivate(sec1PEM)
	if err != nil {
		t.Fatalf("SEC1: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("SEC1 derived pubkey != MarshalPKIXPublicKey")
	}

	// PKCS#8 "PRIVATE KEY"
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	got, err = publicKeyPEMFromPrivate(pkcs8PEM)
	if err != nil {
		t.Fatalf("PKCS8: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("PKCS8 derived pubkey != MarshalPKIXPublicKey")
	}
}

// TestBuildKubeconfig checks the assembled kubeconfig is well-formed: the
// context/cluster/user names, the server URL, and base64 of the cert/key/CA.
func TestBuildKubeconfig(t *testing.T) {
	cert := []byte("CERTPEM")
	key := []byte("KEYPEM")
	ca := []byte("CAPEM")
	kc := string(buildKubeconfig("https://node:6443", "c8s", "c8s-cvm", cert, key, ca))

	for _, want := range []string{
		"current-context: c8s",
		"server: https://node:6443",
		"tls-server-name: c8s-cvm",
		"certificate-authority-data: " + base64.StdEncoding.EncodeToString(ca),
		"client-certificate-data: " + base64.StdEncoding.EncodeToString(cert),
		"client-key-data: " + base64.StdEncoding.EncodeToString(key),
	} {
		if !strings.Contains(kc, want) {
			t.Errorf("kubeconfig missing %q\n%s", want, kc)
		}
	}

	// Empty tls-server-name omits the line entirely.
	kc2 := string(buildKubeconfig("https://node:6443", "c8s", "", cert, key, ca))
	if strings.Contains(kc2, "tls-server-name") {
		t.Errorf("empty tlsServerName should omit the line\n%s", kc2)
	}
}
