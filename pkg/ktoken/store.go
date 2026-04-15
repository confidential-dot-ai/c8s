// Package ktoken loads the EAR token-signer key from a Kubernetes Secret.
package ktoken

import (
	"context"
	"fmt"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/lunal-dev/c8s/pkg/certutil"
)

const keyField = "token-signer.key"

// Load reads the token-signer private key PEM from the named Secret.
// Returns an error if the Secret doesn't exist or the key field is
// empty/invalid. Callers are responsible for creating the Secret
// upfront (e.g. via SOPS in the fleet repo).
func Load(ctx context.Context, client kubernetes.Interface, namespace, name string, logger *slog.Logger) ([]byte, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get Secret %s/%s: %w", namespace, name, err)
	}

	keyPEM := secret.Data[keyField]
	if len(keyPEM) == 0 {
		return nil, fmt.Errorf("Secret %s/%s exists but %q field is empty", namespace, name, keyField)
	}

	if _, err := certutil.ParseECPrivateKey(keyPEM); err != nil {
		return nil, fmt.Errorf("key in Secret %s/%s is invalid: %w", namespace, name, err)
	}

	logger.Info("loaded token-signer key from Secret", "name", name)
	return keyPEM, nil
}
