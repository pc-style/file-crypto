package main

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type target struct {
	GOOS   string
	GOARCH string
	Label  string
}

var allTargets = []target{
	{GOOS: "darwin", GOARCH: "arm64", Label: "macOS arm64"},
	{GOOS: "darwin", GOARCH: "amd64", Label: "macOS amd64"},
	{GOOS: "linux", GOARCH: "amd64", Label: "Linux amd64"},
	{GOOS: "linux", GOARCH: "arm64", Label: "Linux arm64"},
	{GOOS: "windows", GOARCH: "amd64", Label: "Windows amd64"},
}

type components struct {
	encrypt bool
	decrypt bool
	genkey  bool
}

type defaults struct {
	dir             string
	keyFile         string
	workers         int
	enableComp      bool
	benchmark       bool
	sysExcl         bool
	optIO           bool
	dynWorkers      bool
	bufferSize      int
	verbose         bool
	unsafeMode      bool
	assumeYes       bool
	includeGlobs    string
	excludeGlobs    string
	minSize         int
	maxSize         int
	dryRun          bool
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("File Crypto - Interactive Builder")
	fmt.Println(strings.Repeat("=", 40))

	// Choose components
	comps := components{
		encrypt: askYesNo(reader, "Build encrypt binary?", true),
		decrypt: askYesNo(reader, "Build decrypt binary?", true),
		genkey:  askYesNo(reader, "Build genkey helper?", false),
	}
	if !comps.encrypt && !comps.decrypt && !comps.genkey {
		fmt.Println("Nothing to build. Exiting.")
		return
	}

	// Targets
	selected := askTargets(reader)
	if len(selected) == 0 {
		fmt.Println("No targets selected. Exiting.")
		return
	}

	// Output dir
	outDir := askString(reader, "Output directory", "build")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatalf("failed to create output dir: %v", err)
	}

	// v5 public key embedding (ask before defaults to avoid confusion)
	var (
		pubKeyB64 string
		embedV5   bool
	)
	if comps.encrypt {
		embedV5 = askYesNo(reader, "Embed RSA public key for encrypt (v5 hybrid mode)?", false)
		if embedV5 {
			pubKeyB64 = askPublicKey(reader)
			fmt.Println("ℹ️  Note: Encrypt (v5) ignores -key. Decrypt requires -key pointing to the RSA PRIVATE key.")
		}
	}

	// Defaults
	def := gatherDefaults(reader, embedV5)

	// Build
	fmt.Println()
	fmt.Println("Starting builds...")

	ldflags := buildLdflags(def, pubKeyB64)

	var built []string
	for _, t := range selected {
		if comps.encrypt {
			out := outputName(outDir, "encrypt", t)
			if err := runBuild(t, ldflags, "./cmd/encrypt", out); err != nil {
				fatalf("encrypt build failed for %s/%s: %v", t.GOOS, t.GOARCH, err)
			}
			built = append(built, out)
		}
		if comps.decrypt {
			out := outputName(outDir, "decrypt", t)
			if err := runBuild(t, ldflags, "./cmd/decrypt", out); err != nil {
				fatalf("decrypt build failed for %s/%s: %v", t.GOOS, t.GOARCH, err)
			}
			built = append(built, out)
		}
		if comps.genkey {
			out := outputName(outDir, "genkey", t)
			if err := runBuild(t, ldflags, "./cmd/genkey", out); err != nil {
				fatalf("genkey build failed for %s/%s: %v", t.GOOS, t.GOARCH, err)
			}
			built = append(built, out)
		}
	}

	sort.Strings(built)
	fmt.Println("\n✅ Build complete. Artifacts:")
	for _, b := range built {
		fmt.Printf("  • %s\n", b)
	}
}

func askTargets(reader *bufio.Reader) []target {
	fmt.Println("Select targets (comma-separated numbers):")
	for i, t := range allTargets {
		cur := ""
		if t.GOOS == runtime.GOOS && t.GOARCH == runtime.GOARCH {
			cur = " (current)"
		}
		fmt.Printf("  %d) %s/%s%s\n", i+1, t.GOOS, t.GOARCH, cur)
	}
	fmt.Println("  a) All")
	ans := askString(reader, "Choice", "1")
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans == "a" || ans == "all" {
		return append([]target(nil), allTargets...)
	}
	parts := strings.Split(ans, ",")
	var sel []target
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idx := parseInt(p)
		if idx <= 0 || idx > len(allTargets) {
			fmt.Printf("Skipping invalid choice: %q\n", p)
			continue
		}
		sel = append(sel, allTargets[idx-1])
	}
	return sel
}

func gatherDefaults(reader *bufio.Reader, embedV5 bool) defaults {
	def := defaults{}
	def.dir = askString(reader, "Default target directory (-dir)", "./test")
	keyDefault := "decryption_key.txt"
	keyPrompt := "Default key file path (-key)"
	if embedV5 {
		keyDefault = "private-key.pem"
		keyPrompt = "Default RSA PRIVATE key path for decrypt (-key)"
	}
	def.keyFile = askString(reader, keyPrompt, keyDefault)
	def.workers = askInt(reader, "Default max workers (-workers)", fmt.Sprintf("%d", runtime.NumCPU()))
	def.enableComp = askYesNo(reader, "Enable compression by default?", true)
	def.benchmark = askYesNo(reader, "Enable benchmark mode by default?", false)
	def.sysExcl = askYesNo(reader, "Enable system exclusions by default?", true)
	def.optIO = askYesNo(reader, "Enable optimized I/O by default?", true)
	def.dynWorkers = askYesNo(reader, "Enable dynamic workers by default?", true)
	def.bufferSize = askInt(reader, "Default buffer size (bytes, -buffer-size)", "65536")
	def.verbose = askYesNo(reader, "Enable verbose output by default?", false)
	def.unsafeMode = askYesNo(reader, "Enable UNSAFE mode by default?", false)
	def.assumeYes = askYesNo(reader, "Default assume-yes (-y/--yes)?", false)
	def.includeGlobs = askString(reader, "Include globs (comma-separated, empty=all)", "")
	def.excludeGlobs = askString(reader, "Exclude globs (comma-separated)", "")
	def.minSize = askInt(reader, "Minimum size in bytes (0=none)", "0")
	def.maxSize = askInt(reader, "Maximum size in bytes (0=unlimited)", "0")
	def.dryRun = askYesNo(reader, "Default dry-run mode?", false)
	return def
}

func askPublicKey(reader *bufio.Reader) string {
	fmt.Println("Provide RSA public key for embedding:")
	fmt.Println("- Paste Base64 DER (single line), or")
	fmt.Println("- Enter path to PEM/DER public key file")
	for {
		in := strings.TrimSpace(askString(reader, "Public key (or path)", ""))
		if in == "" {
			fmt.Println("Public key is required when embedding. Try again.")
			continue
		}
		// If file exists, read and parse
		if fileExists(in) {
			data, err := os.ReadFile(in)
			if err != nil {
				fmt.Printf("Failed to read %s: %v\n", in, err)
				continue
			}
			b64, err := toPublicKeyBase64(data)
			if err != nil {
				fmt.Printf("Invalid public key in %s: %v\n", in, err)
				continue
			}
			return b64
		}
		// Otherwise treat input as base64
		b64 := strings.TrimSpace(in)
		if _, err := base64.StdEncoding.DecodeString(b64); err != nil {
			fmt.Printf("Not valid Base64. If this is a file path, ensure it exists. Error: %v\n", err)
			continue
		}
		// Validate parses
		if _, err := parseRSAPublicFromB64(b64); err != nil {
			fmt.Printf("Base64 isn't a supported RSA public key (PKIX/PKCS1 DER): %v\n", err)
			continue
		}
		return b64
	}
}

func toPublicKeyBase64(input []byte) (string, error) {
	// Try PEM first
	if block, _ := pem.Decode(input); block != nil {
		if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" {
			if _, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
				return base64.StdEncoding.EncodeToString(block.Bytes), nil
			}
			if _, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
				return base64.StdEncoding.EncodeToString(block.Bytes), nil
			}
			return "", errors.New("unsupported PEM public key content; expected PKIX or PKCS1 RSA")
		}
		return "", errors.New("PEM file is not a public key")
	}
	// Try DER directly (PKIX or PKCS1)
	if _, err := x509.ParsePKIXPublicKey(input); err == nil {
		return base64.StdEncoding.EncodeToString(input), nil
	}
	if _, err := x509.ParsePKCS1PublicKey(input); err == nil {
		return base64.StdEncoding.EncodeToString(input), nil
	}
	return "", errors.New("file is not a valid RSA public key (PKIX/PKCS1 DER or PEM)")
}

func parseRSAPublicFromB64(b64 string) (any, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		return pub, nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return pub, nil
	}
	return nil, errors.New("not RSA PKIX/PKCS1 public key")
}

func buildLdflags(def defaults, pubKeyB64 string) string {
	var parts []string
	appendX := func(sym, val string) {
		parts = append(parts, fmt.Sprintf("-X %s=%s", sym, val))
	}
	appendX("main.version", "custom")
	// Config defaults (string-encoded)
	appendX("file-crypto/pkg/config.DefaultTargetDirStr", shellQuote(def.dir))
	appendX("file-crypto/pkg/config.DefaultKeyFileStr", shellQuote(def.keyFile))
	appendX("file-crypto/pkg/config.DefaultMaxWorkersStr", fmt.Sprintf("%d", def.workers))
	appendX("file-crypto/pkg/config.DefaultEnableCompressionStr", boolStr(def.enableComp))
	appendX("file-crypto/pkg/config.DefaultBenchmarkStr", boolStr(def.benchmark))
	appendX("file-crypto/pkg/config.DefaultSystemExclusionsStr", boolStr(def.sysExcl))
	appendX("file-crypto/pkg/config.DefaultOptimizedIOStr", boolStr(def.optIO))
	appendX("file-crypto/pkg/config.DefaultDynamicWorkersStr", boolStr(def.dynWorkers))
	appendX("file-crypto/pkg/config.DefaultBufferSizeStr", fmt.Sprintf("%d", def.bufferSize))
	appendX("file-crypto/pkg/config.DefaultShowHelpStr", boolStr(false))
	appendX("file-crypto/pkg/config.DefaultVerboseStr", boolStr(def.verbose))
	appendX("file-crypto/pkg/config.DefaultUnsafeModeStr", boolStr(def.unsafeMode))
	appendX("file-crypto/pkg/config.DefaultAssumeYesStr", boolStr(def.assumeYes))
	appendX("file-crypto/pkg/config.DefaultIncludeGlobsStr", shellQuote(def.includeGlobs))
	appendX("file-crypto/pkg/config.DefaultExcludeGlobsStr", shellQuote(def.excludeGlobs))
	appendX("file-crypto/pkg/config.DefaultMinSizeBytesStr", fmt.Sprintf("%d", def.minSize))
	appendX("file-crypto/pkg/config.DefaultMaxSizeBytesStr", fmt.Sprintf("%d", def.maxSize))
	appendX("file-crypto/pkg/config.DefaultDryRunStr", boolStr(def.dryRun))

	// Embedded public key for encryptor (optional)
	if strings.TrimSpace(pubKeyB64) != "" {
		appendX("file-crypto/internal/crypto.EmbeddedPublicKeyBase64", shellQuote(pubKeyB64))
	}

	return strings.Join(parts, " ")
}

func runBuild(t target, ldflags, pkg, out string) error {
	args := []string{"build", "-ldflags", ldflags, "-o", out, pkg}
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOOS="+t.GOOS, "GOARCH="+t.GOARCH)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func outputName(outDir, name string, t target) string {
	file := fmt.Sprintf("%s-%s-%s", name, t.GOOS, t.GOARCH)
	if t.GOOS == "windows" {
		file += ".exe"
	}
	return filepath.Join(outDir, file)
}

func askString(r *bufio.Reader, prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	text, _ := r.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return def
	}
	return text
}

func askYesNo(r *bufio.Reader, prompt string, def bool) bool {
	defStr := "y/N"
	if def {
		defStr = "Y/n"
	}
	for {
		fmt.Printf("%s (%s): ", prompt, defStr)
		text, _ := r.ReadString('\n')
		text = strings.TrimSpace(strings.ToLower(text))
		if text == "" {
			return def
		}
		switch text {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		default:
			fmt.Println("Please answer 'y' or 'n'.")
		}
	}
}

func askInt(r *bufio.Reader, prompt, def string) int {
	for {
		ans := askString(r, prompt, def)
		if n := parseInt(ans); n != 0 || ans == "0" {
			return n
		}
		fmt.Println("Enter a valid integer.")
	}
}

func parseInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	sign := 1
	idx := 0
	if s[0] == '-' {
		sign = -1
		idx = 1
	}
	n := 0
	for ; idx < len(s); idx++ {
		ch := s[idx]
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return sign * n
}

func boolStr(b bool) string { if b { return "true" } ; return "false" }

func shellQuote(s string) string {
	// As value for -X, spaces are problematic; recommend no spaces.
	// We'll escape any spaces by replacing with \x20 to be safe.
	s = strings.ReplaceAll(s, " ", "\\x20")
	return s
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "❌ "+format+"\n", a...)
	os.Exit(1)
}



