package launchconfig

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// Tests replace only the filesystem probe; the production path always checks
// the opened directory handle before reading or writing a credential.
var requireTokenRAM = fileutil.RequireRAMBackedRoot

// initializeAgentToken creates a separate agent password before the first
// leader RKE2 start. The serialized role oneshot preserves it across restarts;
// omitting this credential would let RKE2 reuse its privileged server token.
func initializeAgentToken(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create agent token directory: %w", err)
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open agent token directory: %w", err)
	}
	defer root.Close()
	if err := requireTokenRAM(root); err != nil {
		return fmt.Errorf("agent token storage: %w", err)
	}
	name := filepath.Base(path)
	if err := validateExistingAgentToken(root, name); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate agent token: %w", err)
	}
	defer clear(secret[:])
	return fileutil.WriteAtomicRoot(root, name, []byte(hex.EncodeToString(secret[:])), 0600)
}

func validateExistingAgentToken(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 64 {
		return fmt.Errorf("existing agent token must be a private 64-byte regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("open existing agent token: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil {
		return fmt.Errorf("read existing agent token: %w", err)
	}
	defer clear(data)
	secret, err := hex.DecodeString(string(data))
	defer clear(secret)
	if err != nil || len(data) != 64 || len(secret) != 32 {
		return fmt.Errorf("existing agent token is malformed")
	}
	return nil
}
