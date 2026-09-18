package allowlist

import (
	"fmt"
	"strings"
)

type mountRuleBehavior interface {
	validate() error
	admits(ObservedMount) bool
	hostIndependent() bool
}

func (r MountRule) behavior() mountRuleBehavior {
	switch r.Kind {
	case MountEmptyDir:
		return emptyDirRule{r}
	case MountData:
		return dataRule{emptyDirRule{r}}
	case MountHost:
		return hostRule{r}
	default:
		return nil
	}
}

type emptyDirRule struct {
	MountRule
}

func (r emptyDirRule) validate() error {
	if r.Source != "" || r.ReadOnly {
		return fmt.Errorf("mount kind %q does not support source or readOnly", r.Kind)
	}
	return nil
}

func (emptyDirRule) admits(m ObservedMount) bool {
	return m.Storage == MountMemory || m.Storage == MountEncrypted
}

func (emptyDirRule) hostIndependent() bool {
	return true
}

type dataRule struct {
	emptyDirRule
}

func (r dataRule) validate() error {
	if err := r.emptyDirRule.validate(); err != nil {
		return err
	}
	if !strings.HasPrefix(r.Destination, DataMountPrefix) {
		return fmt.Errorf("data destination %q must be below %s", r.Destination, DataMountPrefix)
	}
	return nil
}

type hostRule struct {
	MountRule
}

func (r hostRule) validate() error {
	if HostSourceDigest(r.Source) == "" {
		return fmt.Errorf("host source %q must be a clean absolute path", r.Source)
	}
	return nil
}

func (r hostRule) admits(m ObservedMount) bool {
	digest := HostSourceDigest(r.Source)
	return digest != "" && m.HostSourceDigest == digest && m.ReadOnly == r.ReadOnly
}

func (hostRule) hostIndependent() bool {
	return false
}
