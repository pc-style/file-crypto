package system

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DesktopPath returns the best-effort desktop directory for the current user.
// It creates the directory when missing to guarantee a drop location for simulations.
func DesktopPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}

	candidates := candidateDesktops(home)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
	}

	fallback := filepath.Join(home, "Desktop")
	if err := os.MkdirAll(fallback, 0o755); err != nil {
		return "", fmt.Errorf("create desktop directory: %w", err)
	}
	return fallback, nil
}

func candidateDesktops(home string) []string {
	var candidates []string

	if runtime.GOOS == "windows" {
		if profile := os.Getenv("USERPROFILE"); profile != "" {
			candidates = append(candidates, filepath.Join(profile, "Desktop"))
		}
		if home != "" {
			candidates = append(candidates, filepath.Join(home, "Desktop"))
		}
		if public := os.Getenv("PUBLIC"); public != "" {
			candidates = append(candidates, filepath.Join(public, "Desktop"))
		}
		return candidates
	}

	if xdg := os.Getenv("XDG_DESKTOP_DIR"); xdg != "" {
		candidates = append(candidates, expandXDGPath(xdg, home))
	}
	if home != "" {
		candidates = append(candidates, filepath.Join(home, "Desktop"))
	}
	return candidates
}

func expandXDGPath(path, home string) string {
	trimmed := strings.TrimSpace(path)
	trimmed = strings.Trim(trimmed, "\"")
	if strings.HasPrefix(trimmed, "${HOME}") {
		return filepath.Join(home, strings.TrimPrefix(trimmed, "${HOME}"))
	}
	if strings.HasPrefix(trimmed, "$HOME") {
		return filepath.Join(home, strings.TrimPrefix(trimmed, "$HOME"))
	}
	return trimmed
}
