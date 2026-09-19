package cmdsutil

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// ImagePolicySource selects one complete refvalues JSON document. File and JSON
// use the same format; neither is a newline-separated digest list.
type ImagePolicySource struct {
	File string
	JSON string
}

// IsSet reports whether a complete policy was supplied.
func (s ImagePolicySource) IsSet() bool { return s.File != "" || s.JSON != "" }

// MeasurementPins holds the independent digest/register inputs. Prefix is "cds-"
// for commands whose flags name CDS explicitly; otherwise it is empty.
type MeasurementPins struct {
	Measurements     []string
	MeasurementsFile string
	RTMRs            []string
	Prefix           string
}

// MeasurementPinsFromStrings adapts commands that accept comma-separated strings.
func MeasurementPinsFromStrings(measurements, rtmrs, prefix string) MeasurementPins {
	pins := MeasurementPins{Prefix: prefix}
	if measurements != "" {
		pins.Measurements = strings.Split(measurements, ",")
	}
	if rtmrs != "" {
		pins.RTMRs = strings.Split(rtmrs, ",")
	}
	return pins
}

func (p MeasurementPins) flags() []string {
	var flags []string
	if len(p.Measurements) > 0 {
		flags = append(flags, "--"+p.Prefix+"measurements")
	}
	if p.MeasurementsFile != "" {
		flags = append(flags, "--measurements-file")
	}
	if len(p.RTMRs) > 0 {
		flags = append(flags, "--"+p.Prefix+"rtmrs")
	}
	return flags
}

// LoadValues loads complete image identities, rejecting independent pin inputs
// before reading a policy. Without a source it returns an empty set.
func (s ImagePolicySource) LoadValues(pins MeasurementPins) (refvalues.ReferenceValues, error) {
	if !s.IsSet() {
		return refvalues.ReferenceValues{}, nil
	}
	if s.File != "" && s.JSON != "" {
		return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-file cannot be combined with --image-policy-json")
	}
	if flags := pins.flags(); len(flags) != 0 {
		return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-file/--image-policy-json cannot be combined with %s", strings.Join(flags, " or "))
	}
	if s.JSON != "" {
		set, err := refvalues.Parse([]byte(s.JSON))
		if err != nil {
			return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-json: %w", err)
		}
		return set, nil
	}
	set, err := refvalues.Load(s.File)
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-file: %w", err)
	}
	return set, nil
}

// ImagePolicyValuesConfig supplies a complete policy and optional platform check.
// PlatformFlag names the caller's platform flag in validation errors.
type ImagePolicyValuesConfig struct {
	Source       ImagePolicySource
	Pins         MeasurementPins
	Platform     string
	PlatformFlag string
}

// LoadImagePolicyValues loads complete identities and checks their TEE against
// the configured platform when one is supplied.
func LoadImagePolicyValues(cfg ImagePolicyValuesConfig) (refvalues.ReferenceValues, error) {
	values, err := cfg.Source.LoadValues(cfg.Pins)
	if err != nil || !cfg.Source.IsSet() {
		return values, err
	}
	if cfg.Platform != "" {
		flag := cfg.PlatformFlag
		if flag == "" {
			flag = "--platform"
		}
		family, err := teetypes.ParseFamily(cfg.Platform)
		if err != nil {
			return refvalues.ReferenceValues{}, fmt.Errorf("%s: %w", flag, err)
		}
		if family != values.Family {
			return refvalues.ReferenceValues{}, fmt.Errorf("image policy declares tee %q but %s is %q", values.Family, flag, family)
		}
	}
	return values, nil
}

// Load returns complete image identities or independent digest/register pins.
// Complete identities are never flattened into independent lists.
func (s ImagePolicySource) Load(pins MeasurementPins) (remote.Policy, error) {
	if s.IsSet() {
		values, err := s.LoadValues(pins)
		return values.Policy(), err
	}
	measurements, err := LoadMeasurements(pins.Measurements, pins.MeasurementsFile)
	if err != nil {
		return remote.Policy{}, fmt.Errorf("--%smeasurements: %w", pins.Prefix, err)
	}
	rtmrs, err := refvalues.ParseRTMRPins(pins.RTMRs)
	if err != nil {
		return remote.Policy{}, fmt.Errorf("--%srtmrs: %w", pins.Prefix, err)
	}
	return remote.Policy{Measurements: measurements, RTMRs: rtmrs}, nil
}

// LoadMeasurements combines digest flags and a newline-separated digest
// file. JSON image policies belong to ImagePolicySource instead.
func LoadMeasurements(values []string, path string) ([][]byte, error) {
	values = append([]string(nil), values...)
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read --measurements-file: %w", err)
		}
		values = append(values, strings.Split(string(data), "\n")...)
	}
	return refvalues.ParseHexMeasurementsList(values)
}

// BindImagePolicyFlags registers canonical JSON sources. A nil inline pointer
// exposes only file input; prefix is "cds-" for the mesh's independent CDS policy.
// Only one source may be used.
func BindImagePolicyFlags(fs *pflag.FlagSet, file, inline *string, prefix, purpose string) {
	selected := ""
	bind := func(target *string, name, usage string) {
		fs.Var(&policySourceFlag{target: target, selected: &selected, name: name}, name, usage)
	}
	fileName := prefix + "image-policy-file"
	jsonName := prefix + "image-policy-json"
	*file = ""
	bind(file, fileName, "path to a complete JSON image policy (image, RTMR and launch-key pins); "+purpose)
	if inline != nil {
		*inline = ""
		bind(inline, jsonName, "inline complete JSON image policy, in the same format as --"+fileName+"; "+purpose)
	}
}

type policySourceFlag struct {
	target   *string
	selected *string
	name     string
}

func (v *policySourceFlag) String() string { return *v.target }
func (v *policySourceFlag) Type() string   { return "string" }
func (v *policySourceFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("--%s requires a non-empty JSON policy source", v.name)
	}
	if *v.selected != "" && *v.selected != v.name {
		return fmt.Errorf("--%s cannot be combined with --%s: select one JSON policy source", *v.selected, v.name)
	}
	*v.selected = v.name
	*v.target = value
	return nil
}
