package policy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// EmbeddedPolicyYAML holds build-time injected YAML. Empty when not provided.
// Set via: -ldflags "-X 'file-crypto/pkg/policy.EmbeddedPolicyYAML=...'"
var EmbeddedPolicyYAML string

// SimulationSpec describes optional simulation-specific behavior for red-team drills.
type SimulationSpec struct {
	Enabled            bool   `yaml:"enabled"`
	DropOnDesktop      bool   `yaml:"drop_on_desktop"`
	DropFolder         string `yaml:"drop_folder"`
	NoteFilename       string `yaml:"note_filename"`
	NoteTemplate       string `yaml:"note"`
	DecryptorFilename  string `yaml:"decryptor_filename"`
	PrivateKeyFilename string `yaml:"private_key_filename"`
	AutoRevealKey      bool   `yaml:"auto_reveal_key"`
}

// Policy represents a policy-driven configuration for encryption scope and simulation metadata.
type Policy struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	TargetDir   string         `yaml:"target_dir"`
	Include     []string       `yaml:"include"`
	Exclude     []string       `yaml:"exclude"`
	MinSize     int64          `yaml:"min_size_bytes"`
	MaxSize     int64          `yaml:"max_size_bytes"`
	SystemExcl  *bool          `yaml:"system_exclusions"`
	Unsafe      *bool          `yaml:"unsafe"`
	Compression *bool          `yaml:"compression"`
	DryRun      *bool          `yaml:"dry_run"`
	AssumeYes   *bool          `yaml:"assume_yes"`
	Simulation  SimulationSpec `yaml:"simulation"`

	Source string `yaml:"-"`
}

// FromYAML parses a raw YAML policy definition.
func FromYAML(data string) (*Policy, error) {
	trimmed := strings.TrimSpace(data)
	if trimmed == "" {
		return nil, errors.New("policy YAML is empty")
	}
	var pol Policy
	if err := yaml.Unmarshal([]byte(trimmed), &pol); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}
	if pol.Name == "" {
		return nil, errors.New("policy missing required field 'name'")
	}
	return &pol, nil
}

// LoadFile loads a policy from a YAML file path.
func LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}
	pol, err := FromYAML(string(data))
	if err != nil {
		return nil, err
	}
	pol.Source = path
	return pol, nil
}

// LoadEmbedded parses the embedded policy definition if present.
func LoadEmbedded() (*Policy, error) {
	if !HasEmbedded() {
		return nil, errors.New("no embedded policy available")
	}
	raw := strings.TrimSpace(EmbeddedPolicyYAML)
	pol, err := FromYAML(raw)
	if err == nil {
		pol.Source = "embedded"
		return pol, nil
	}

	// Allow base64 encoded payloads for ease of ldflags embedding
	decoded, decodeErr := base64.StdEncoding.DecodeString(raw)
	if decodeErr != nil {
		return nil, err
	}
	pol, err = FromYAML(string(decoded))
	if err != nil {
		return nil, err
	}
	pol.Source = "embedded"
	return pol, nil
}

// HasEmbedded reports whether a build-time policy is embedded.
func HasEmbedded() bool {
	return strings.TrimSpace(EmbeddedPolicyYAML) != ""
}
