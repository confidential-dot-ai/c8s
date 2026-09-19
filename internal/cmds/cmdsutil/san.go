package cmdsutil

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// ReadSANFile reads one fixed identity name from a regular, bounded file.
// Callers apply the same SAN validation as their corresponding inline flag.
func ReadSANFile(flag, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", flag, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("%s: %w", flag, err)
	}
	const maxSize = 1024
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxSize {
		return "", fmt.Errorf("%s must be a regular file containing 1..%d bytes", flag, maxSize)
	}
	data, err := readutil.ReadAll(f, maxSize)
	if err != nil {
		return "", fmt.Errorf("%s: %w", flag, err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s must contain a SAN", flag)
	}
	return value, nil
}

// hostnameLabelRe accepts RFC 1123 labels: 1–63 alphanumeric characters,
// with hyphens allowed in the middle.
var hostnameLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateDNSName checks a literal RFC 1123 hostname, excluding wildcards,
// URLs, regular expressions, and lists of names.
func ValidateDNSName(s string) error {
	if len(s) > 253 {
		return fmt.Errorf("'%s' exceeds maximum hostname length of 253 characters", s)
	}
	for label := range strings.SplitSeq(s, ".") {
		if !hostnameLabelRe.MatchString(label) {
			return fmt.Errorf("'%s' is not a valid RFC 1123 hostname", s)
		}
	}
	return nil
}
