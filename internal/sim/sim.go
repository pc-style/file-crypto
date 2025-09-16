package sim

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"file-crypto/internal/crypto"
	"file-crypto/internal/system"
	"file-crypto/pkg/config"
	"file-crypto/pkg/policy"
)

// EmbeddedDecryptorBase64 holds the optional decryptor binary payload, base64 encoded.
// Set via: -ldflags "-X 'file-crypto/internal/sim.EmbeddedDecryptorBase64=...'"
var EmbeddedDecryptorBase64 string

const (
	defaultDropDirName    = "FileCrypto-Sim"
	defaultDecryptorName  = "file-crypto-decryptor"
	defaultPrivateKeyName = "private-simulation-key.pem"
	defaultNoteFilename   = "HOW_TO_DECRYPT_SIMULATION.txt"
	placeholderPolicyName = "Controlled Simulation"
)

// DropResult captures artifact locations created during simulation runs.
type DropResult struct {
	Directory      string
	DecryptorPath  string
	PrivateKeyPath string
	NotePath       string
}

// Enabled reports whether simulation droppers should run for the provided config.
func Enabled(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.Simulation {
		return true
	}
	if cfg.ActivePolicy != nil {
		return cfg.ActivePolicy.Simulation.Enabled
	}
	return false
}

// DropArtifacts writes decryptor/key/note assets for simulation builds.
func DropArtifacts(cfg *config.Config) (*DropResult, error) {
	if !Enabled(cfg) {
		return nil, nil
	}

	dropRoot, err := system.DesktopPath()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve desktop directory: %w", err)
	}

	simSpec := newConfigSimulation(cfg)

	folderName := simSpec.dropFolder()
	if folderName == "" {
		folderName = fmt.Sprintf("%s-%s", defaultDropDirName, time.Now().Format("20060102-1504"))
	}
	dropDir := filepath.Join(dropRoot, folderName)
	if err := os.MkdirAll(dropDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create simulation drop directory: %w", err)
	}

	result := &DropResult{Directory: dropDir}
	var dropErrs []string

	// Private key
	if crypto.HasEmbeddedPrivateKey() || simSpec.autoRevealKey() {
		keyData, keyErr := crypto.GetEmbeddedPrivateKey()
		if keyErr != nil {
			if simSpec.autoRevealKey() {
				dropErrs = append(dropErrs, keyErr.Error())
			}
		} else {
			keyName := simSpec.privateKeyFilename()
			keyPath := filepath.Join(dropDir, keyName)
			if err := os.WriteFile(keyPath, keyData, 0o600); err != nil {
				dropErrs = append(dropErrs, fmt.Sprintf("write private key: %v", err))
			} else {
				result.PrivateKeyPath = keyPath
			}
		}
	}

	// Decryptor binary
	if EmbeddedDecryptorBase64 != "" {
		decryptorBytes, decErr := decodeDecryptor()
		if decErr != nil {
			dropErrs = append(dropErrs, decErr.Error())
		} else {
			name := simSpec.decryptorFilename()
			fullPath := filepath.Join(dropDir, name)
			if err := os.WriteFile(fullPath, decryptorBytes, 0o755); err != nil {
				dropErrs = append(dropErrs, fmt.Sprintf("write decryptor: %v", err))
			} else {
				if runtime.GOOS != "windows" {
					_ = os.Chmod(fullPath, 0o755)
				}
				result.DecryptorPath = fullPath
			}
		}
	}

	noteContent := simSpec.noteTemplate()
	if noteContent == "" {
		noteContent = defaultNoteTemplate(cfg, result)
	} else {
		noteContent = renderTemplate(noteContent, map[string]string{
			"POLICY_NAME": policyOrDefault(cfg),
			"TARGET_DIR":  cfg.TargetDir,
			"DROP_DIR":    dropDir,
			"DECRYPTOR":   safePath(result.DecryptorPath),
			"PRIVATE_KEY": safePath(result.PrivateKeyPath),
		})
	}

	if noteContent != "" {
		noteName := simSpec.noteFilename()
		notePath := filepath.Join(dropDir, noteName)
		if err := os.WriteFile(notePath, []byte(noteContent), 0o644); err != nil {
			dropErrs = append(dropErrs, fmt.Sprintf("write note: %v", err))
		} else {
			result.NotePath = notePath
		}
	}

	if len(dropErrs) > 0 {
		return result, errors.New(strings.Join(dropErrs, "; "))
	}
	return result, nil
}

func decodeDecryptor() ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(EmbeddedDecryptorBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode embedded decryptor: %w", err)
	}
	return data, nil
}

type configSimulation struct {
	spec *policy.SimulationSpec
}

func newConfigSimulation(cfg *config.Config) configSimulation {
	if cfg != nil && cfg.ActivePolicy != nil {
		return configSimulation{spec: &cfg.ActivePolicy.Simulation}
	}
	return configSimulation{}
}

func (c configSimulation) simulationSpec() policy.SimulationSpec {
	if c.spec != nil {
		return *c.spec
	}
	return policy.SimulationSpec{}
}

func (c configSimulation) dropFolder() string {
	spec := c.simulationSpec()
	if spec.DropOnDesktop {
		if spec.DropFolder != "" {
			return spec.DropFolder
		}
		return defaultDropDirName
	}
	return ""
}

func (c configSimulation) decryptorFilename() string {
	spec := c.simulationSpec()
	name := spec.DecryptorFilename
	if name == "" {
		name = defaultDecryptorName
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		name += ".exe"
	}
	return name
}

func (c configSimulation) privateKeyFilename() string {
	spec := c.simulationSpec()
	if spec.PrivateKeyFilename != "" {
		return spec.PrivateKeyFilename
	}
	return defaultPrivateKeyName
}

func (c configSimulation) noteFilename() string {
	spec := c.simulationSpec()
	if spec.NoteFilename != "" {
		return spec.NoteFilename
	}
	return defaultNoteFilename
}

func (c configSimulation) noteTemplate() string {
	return c.simulationSpec().NoteTemplate
}

func (c configSimulation) autoRevealKey() bool {
	return c.simulationSpec().AutoRevealKey
}

func defaultNoteTemplate(cfg *config.Config, res *DropResult) string {
	lines := []string{
		"This is a controlled File Crypto ransomware simulation.",
		fmt.Sprintf("Policy: %s", policyOrDefault(cfg)),
		fmt.Sprintf("Encrypted target: %s", cfg.TargetDir),
	}
	if res != nil {
		if res.DecryptorPath != "" {
			lines = append(lines, fmt.Sprintf("Decryptor: %s", res.DecryptorPath))
		}
		if res.PrivateKeyPath != "" {
			lines = append(lines, fmt.Sprintf("Private key: %s", res.PrivateKeyPath))
		}
	}
	lines = append(lines,
		"",
		"To restore files, run the decryptor with the private key above.",
		"Example:",
		fmt.Sprintf("  %s -dir %s -key %s -verbose", defaultDecryptorInvocation(res), cfg.TargetDir, safePath(res.PrivateKeyPath)),
		"",
		"This note exists to guarantee defenders can recover immediately after the drill.")
	return strings.Join(lines, "\n")
}

func defaultDecryptorInvocation(res *DropResult) string {
	if res == nil || res.DecryptorPath == "" {
		if runtime.GOOS == "windows" {
			return ".\\decrypt.exe"
		}
		return "./decrypt"
	}
	return safePath(res.DecryptorPath)
}

func renderTemplate(input string, values map[string]string) string {
	output := input
	for key, val := range values {
		output = strings.ReplaceAll(output, "{{"+key+"}}", val)
	}
	return output
}

func policyOrDefault(cfg *config.Config) string {
	if cfg != nil && cfg.PolicyName != "" {
		return cfg.PolicyName
	}
	return placeholderPolicyName
}

func safePath(path string) string {
	if path == "" {
		return "(not generated)"
	}
	return path
}
