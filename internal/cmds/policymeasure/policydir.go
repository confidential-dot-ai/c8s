package policymeasure

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
)

// writeFile publishes data at dir/name, 0444, through a rename so a
// consumer never reads a partial file. A member name never starts with a
// dot, so the temp name cannot collide with one.
func writeFile(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := tmp.Chmod(0o444); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, name)); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// writeMode publishes the verdict; it is the last write of a run.
func writeMode(dir, mode string) error {
	return writeFile(dir, policybundle.ModeFile, []byte(mode+"\n"))
}

// refuseMeasured fails when dir already carries a verdict: a second run in
// the same boot would extend the register again and leave a mode that no
// longer matches it.
func refuseMeasured(dir string) error {
	_, err := os.Stat(filepath.Join(dir, policybundle.ModeFile))
	if err == nil {
		return fmt.Errorf("%s already exists: the policy mode was measured earlier this boot", filepath.Join(dir, policybundle.ModeFile))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("policy dir: %w", err)
	}
	return nil
}

// readBundleDisk mounts the policydata ISO read-only under mountRoot, reads
// every member once, and unmounts. Entries starting with ".." are the
// KubeVirt AtomicWriter's versioned directory and its ..data link (the same
// skip rke2-role.sh applies to joindata); everything else must be a regular
// file within the bundle bounds.
func readBundleDisk(dev, mountRoot string) (members map[string][]byte, err error) {
	target, err := os.MkdirTemp(mountRoot, "policydata-*")
	if err != nil {
		return nil, fmt.Errorf("policydata mountpoint: %w", err)
	}
	defer os.Remove(target)
	if err := mountISO(dev, target); err != nil {
		return nil, fmt.Errorf("mount %s: %w", dev, err)
	}
	defer func() {
		if uerr := unmountISO(target); uerr != nil && err == nil {
			err = fmt.Errorf("unmount %s: %w", dev, uerr)
		}
	}()

	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, fmt.Errorf("policydata: %w", err)
	}
	members = make(map[string][]byte)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "..") {
			continue
		}
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("policydata: %s is not a regular file; a bundle is a flat set of files", name)
		}
		if len(members) == policybundle.MaxMembers {
			return nil, fmt.Errorf("policydata has more than %d members", policybundle.MaxMembers)
		}
		data, err := policybundle.ReadMember(filepath.Join(target, name))
		if err != nil {
			return nil, err
		}
		members[name] = data
	}
	return members, nil
}

// exists reports whether path is present; any other stat failure is an
// error so a disk that cannot be examined is never taken for an absent one.
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat %s: %w", path, err)
}
