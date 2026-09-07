package launchvalues

import (
	"encoding/base64"
	"fmt"
)

// decodeSignatureLine decodes the single base64 line c8s keys sign-values
// writes into <values.yaml>.sig back into the ASN.1 DER signature bytes.
func decodeSignatureLine(line string) ([]byte, error) {
	if line == "" {
		return nil, fmt.Errorf("empty signature file")
	}
	der, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	return der, nil
}
