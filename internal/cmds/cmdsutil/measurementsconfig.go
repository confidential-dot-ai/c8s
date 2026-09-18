package cmdsutil

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// ImagePolicySource selects one complete refvalues JSON document. File and JSON
// use the same format; neither is a newline-separated legacy digest list.
type ImagePolicySource struct {
	File string
	JSON string
}

// Set reports whether a complete policy was supplied.
func (s ImagePolicySource) Set() bool { return s.File != "" || s.JSON != "" }

// LegacyPins holds the separate digest/register flags. Prefix is "cds-" for
// commands whose legacy flags name CDS explicitly; otherwise it is empty.
type LegacyPins struct {
	Measurements     []string
	MeasurementsFile string
	RTMRs            []string
	Prefix           string
}

// LegacyPinsFromStrings adapts commands that accept comma-separated strings.
func LegacyPinsFromStrings(measurements, rtmrs, prefix string) LegacyPins {
	pins := LegacyPins{Prefix: prefix}
	if measurements != "" {
		pins.Measurements = strings.Split(measurements, ",")
	}
	if rtmrs != "" {
		pins.RTMRs = strings.Split(rtmrs, ",")
	}
	return pins
}

func (p LegacyPins) flags() []string {
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

// LoadValues loads a whole policy, refusing legacy flags beside it before any
// input is read. Without a source it returns an empty set and leaves legacy
// pins to the caller, including register-only policies with no image form.
func (s ImagePolicySource) LoadValues(legacy LegacyPins) (refvalues.ReferenceValues, error) {
	if !s.Set() {
		return refvalues.ReferenceValues{}, nil
	}
	if s.File != "" && s.JSON != "" {
		return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-file cannot be combined with --image-policy-json (including their --measurements-config aliases)")
	}
	if flags := legacy.flags(); len(flags) != 0 {
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

// Load returns either whole image/anchor pins or the original flat policy.
// It never converts a complete image policy into independent digest/register
// lists, and retains legacy RTMR-only policies without inventing image pins.
func (s ImagePolicySource) Load(legacy LegacyPins) (remote.Policy, error) {
	if s.Set() {
		values, err := s.LoadValues(legacy)
		return values.Policy(), err
	}
	measurements, err := LoadLegacyMeasurements(legacy.Measurements, legacy.MeasurementsFile)
	if err != nil {
		return remote.Policy{}, fmt.Errorf("--%smeasurements: %w", legacy.Prefix, err)
	}
	rtmrs, err := refvalues.ParseRTMRPins(legacy.RTMRs)
	if err != nil {
		return remote.Policy{}, fmt.Errorf("--%srtmrs: %w", legacy.Prefix, err)
	}
	return remote.Policy{Measurements: measurements, RTMRs: rtmrs}, nil
}

// LoadLegacyMeasurements combines digest flags and a newline-separated digest
// file. JSON image policies belong to ImagePolicySource instead.
func LoadLegacyMeasurements(values []string, path string) ([][]byte, error) {
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

// BindImagePolicyFlags registers explicit JSON sources and compatibility
// aliases. A nil inline pointer exposes only file input; prefix is "cds-" for
// the mesh's independent CDS policy. Only one source spelling may be used.
func BindImagePolicyFlags(fs *pflag.FlagSet, file, inline *string, prefix, purpose string) {
	selected := ""
	bind := func(target *string, name, usage string) {
		fs.Var(&policySourceFlag{target: target, selected: &selected, name: name}, name, usage)
	}
	fileName := prefix + "image-policy-file"
	jsonName := prefix + "image-policy-json"
	*file = ""
	bind(file, fileName, "path to a complete JSON image policy (image, RTMR and launch-key pins); "+purpose)
	bind(file, prefix+"measurements-config", "compatibility alias for --"+fileName+"; a JSON policy file, not a newline digest file")
	if inline != nil {
		*inline = ""
		bind(inline, jsonName, "inline complete JSON image policy, in the same format as --"+fileName+"; "+purpose)
		bind(inline, prefix+"measurements-config-json", "compatibility alias for --"+jsonName+"; inline JSON, not a file path")
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
