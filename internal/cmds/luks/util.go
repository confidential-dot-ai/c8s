package luks

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/devmapper"
)

// runtimeMapperClose removes the pod-runtime dm-crypt mapper (c8s-<name>) if
// one is still active. Returns nil when the mapper is already gone
// (idempotent). Kept in destroy's util so create.go's transient
// c8s-luks-<workload>-<name> mapper (a separate lifecycle) stays untouched.
func runtimeMapperClose(name string) error {
	if err := devmapper.Remove(name); err != nil && !errors.Is(err, devmapper.ErrNotFound) {
		return err
	}
	return nil
}

func jsonEncoder() *json.Encoder {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc
}

func bytesReader(b []byte) *strings.Reader { return strings.NewReader(string(b)) }

func trimNewline(s string) string { return strings.TrimRight(s, "\r\n") }

func cutColon(s string) (a, b string, ok bool) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func runOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
