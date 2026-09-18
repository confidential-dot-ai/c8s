package cmdsutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

const identityPolicyFile = "../../../internal/testdata/node-identities.json"

func TestImagePolicySourceKeepsCompleteIdentities(t *testing.T) {
	doc, err := os.ReadFile(identityPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	var previous any
	for _, source := range []ImagePolicySource{{File: identityPolicyFile}, {JSON: string(doc)}} {
		policy, err := source.Load(LegacyPins{})
		if err != nil {
			t.Fatal(err)
		}
		if len(policy.Measurements) != 0 || len(policy.RTMRs) != 0 || len(policy.Images) != 2 {
			t.Fatalf("complete identities were flattened: %+v", policy)
		}
		for _, pin := range policy.Images {
			if len(pin.Digest) != 48 || len(pin.RTMRs[1]) != 48 || len(pin.RTMRs[2]) != 48 || len(pin.Anchor) == 0 {
				t.Fatalf("incomplete image tuple: %+v", pin)
			}
		}
		if bytes.Equal(policy.Images[0].Anchor, policy.Images[1].Anchor) {
			t.Fatal("server and agent keys collapsed into one identity")
		}
		if previous != nil && !reflect.DeepEqual(previous, policy) {
			t.Fatal("file and inline JSON formats produced different policies")
		}
		previous = policy
	}
}

func TestImagePolicySourceRejectsConflictingInputsBeforeReading(t *testing.T) {
	for _, source := range []ImagePolicySource{{File: "missing"}, {JSON: "invalid"}} {
		for _, legacy := range []LegacyPins{
			{Measurements: []string{"invalid"}},
			{MeasurementsFile: "missing"},
			{RTMRs: []string{"invalid"}},
			{Measurements: []string{"invalid"}, Prefix: "cds-"},
			{RTMRs: []string{"invalid"}, Prefix: "cds-"},
		} {
			_, err := source.Load(legacy)
			if err == nil || !strings.Contains(err.Error(), "cannot be combined") || errors.Is(err, os.ErrNotExist) {
				t.Fatalf("source %+v with %+v: expected usage error before I/O, got %v", source, legacy, err)
			}
		}
	}
	_, err := (ImagePolicySource{File: "missing", JSON: "invalid"}).LoadValues(LegacyPins{})
	if err == nil || !strings.Contains(err.Error(), "--image-policy-file cannot be combined with --image-policy-json") {
		t.Fatalf("file plus inline: %v", err)
	}
}

func TestImagePolicySourceErrorsDoNotFallBack(t *testing.T) {
	_, err := (ImagePolicySource{File: filepath.Join(t.TempDir(), "missing")}).Load(LegacyPins{})
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "--image-policy-file") {
		t.Fatalf("missing policy lost its path error: %v", err)
	}
	for _, inline := range []string{"{}", "not JSON", identityPolicyFile, strings.Repeat("ab", 48)} {
		if _, err := (ImagePolicySource{JSON: inline}).Load(LegacyPins{}); err == nil || !strings.Contains(err.Error(), "--image-policy-json") {
			t.Fatalf("invalid inline policy accepted or mislabeled: %q: %v", inline, err)
		}
	}
	legacy := filepath.Join(t.TempDir(), "digests.txt")
	if err := os.WriteFile(legacy, []byte(strings.Repeat("ab", 48)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (ImagePolicySource{File: legacy}).Load(LegacyPins{}); err == nil {
		t.Fatal("newline digest file accepted as a complete JSON policy")
	}
	if _, err := LoadLegacyMeasurements(nil, identityPolicyFile); err == nil {
		t.Fatal("complete JSON policy accepted as a legacy digest list")
	}
}

func TestLegacyPolicyPreservesDigestFileAndRegisterOnlyPins(t *testing.T) {
	digest := strings.Repeat("ab", 48)
	register := strings.Repeat("cd", 48)
	path := filepath.Join(t.TempDir(), "digests.txt")
	if err := os.WriteFile(path, []byte("\n"+digest+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := ImagePolicySource{}
	policy, err := source.Load(LegacyPins{Measurements: []string{register}, MeasurementsFile: path, RTMRs: []string{"1=" + register}})
	if err != nil || len(policy.Measurements) != 2 || len(policy.RTMRs[1]) != 48 || len(policy.Images) != 0 {
		t.Fatalf("legacy union/register policy changed: %+v, %v", policy, err)
	}
	policy, err = source.Load(LegacyPinsFromStrings("", "1="+register, "cds-"))
	if err != nil || len(policy.Measurements) != 0 || len(policy.RTMRs[1]) != 48 || len(policy.Images) != 0 {
		t.Fatalf("register-only legacy policy was dropped: %+v, %v", policy, err)
	}
	policy, err = source.Load(LegacyPinsFromStrings("", "", ""))
	if err != nil || len(policy.Measurements) != 0 || len(policy.RTMRs) != 0 || len(policy.Images) != 0 {
		t.Fatalf("empty legacy policy changed: %+v, %v", policy, err)
	}
	for _, tc := range []struct{ measurements, rtmrs, flag string }{
		{"bad", "", "--cds-measurements"},
		{"", "bad", "--cds-rtmrs"},
	} {
		if _, err := source.Load(LegacyPinsFromStrings(tc.measurements, tc.rtmrs, "cds-")); err == nil || !strings.Contains(err.Error(), tc.flag) {
			t.Fatalf("invalid legacy flag %s: %v", tc.flag, err)
		}
	}
}

func TestImagePolicyFlagsCanonicalAndAliases(t *testing.T) {
	doc, err := os.ReadFile(identityPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"image-policy-file", "measurements-config", "image-policy-json", "measurements-config-json"} {
		t.Run(flag, func(t *testing.T) {
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			var source ImagePolicySource
			BindImagePolicyFlags(fs, &source.File, &source.JSON, "", "test identity policy")
			value := identityPolicyFile
			if strings.HasSuffix(flag, "json") {
				value = string(doc)
			}
			if err := fs.Parse([]string{"--" + flag, value}); err != nil {
				t.Fatal(err)
			}
			policy, err := source.Load(LegacyPins{})
			if err != nil || len(policy.Images) != 2 || len(policy.Images[0].Anchor) == 0 {
				t.Fatalf("flag lost identity policy: %+v, %v", policy, err)
			}
			if fs.Lookup(flag).Value.String() != value || fs.Lookup(flag).Value.Type() != "string" {
				t.Fatal("flag did not retain its source value")
			}
		})
	}
}

func TestImagePolicyFlagsRejectMixedSpellings(t *testing.T) {
	names := []string{"image-policy-file", "measurements-config", "image-policy-json", "measurements-config-json"}
	for _, first := range names {
		for _, second := range names {
			if first == second {
				continue
			}
			t.Run(first+"+"+second, func(t *testing.T) {
				fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
				var source ImagePolicySource
				BindImagePolicyFlags(fs, &source.File, &source.JSON, "", "test")
				err := fs.Parse([]string{"--" + first, "first", "--" + second, "second"})
				if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
					t.Fatalf("ambiguous policy flags accepted: %v", err)
				}
			})
		}
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		var source ImagePolicySource
		BindImagePolicyFlags(fs, &source.File, &source.JSON, "", "test")
		if err := fs.Parse([]string{"--" + first, ""}); err == nil {
			t.Fatalf("explicit empty %s silently disabled pinning", first)
		}
	}
}

func TestImagePolicyFileFlagsKeepIndependentCDSSelection(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	var peers, cds string
	BindImagePolicyFlags(fs, &peers, nil, "", "mesh peers")
	BindImagePolicyFlags(fs, &cds, nil, "cds-", "CDS")
	if fs.Lookup("image-policy-json") != nil || fs.Lookup("measurements-config-json") != nil {
		t.Fatal("file-only command unexpectedly exposed inline JSON")
	}
	if err := fs.Parse([]string{"--image-policy-file", "peers.json", "--cds-measurements-config", "cds.json"}); err != nil {
		t.Fatal(err)
	}
	if peers != "peers.json" || cds != "cds.json" {
		t.Fatal("separate CDS policy replaced the peer policy")
	}
}
