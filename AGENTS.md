# AGENTS.md - File Crypto (Go Implementation)

This document provides comprehensive guidance for AI coding assistants and human developers working with the File Crypto Go project.

## Project Overview

**File Crypto** is a portable command-line utility for encrypting and decrypting files in bulk, written in Go. It's designed for backup automation and blue-team exercises where you need to understand, rehearse, or harden recovery procedures. The tool supports fast symmetric encryption with optional public-key wrapping, optional LZ4 compression, secure wiping of originals, and multi-platform builds.

### Key Capabilities

- **ChaCha20-Poly1305 content encryption** with per-file random material
- **Optional RSA-4096 public key embedding** so encryptors can run without distributing key files
- **Secure file wiping and `.encrypted` suffix outputs** so encrypted and original files never coexist
- **Configurable worker pool, buffering, and compression** for fast throughput on large datasets
- **Built-in system directory guard rails and file-extension allow lists** that reduce accidental OS damage
- **Cross-platform builds** via Makefile (Linux, macOS, Windows, amd64/arm64)

### Architecture

```
file-crypto/
├── cmd/
│   ├── encrypt/main.go          # Encryption CLI with ChaCha20-Poly1305 + compression
│   ├── decrypt/main.go          # Decryption CLI with concurrent processing
│   ├── genkey/main.go           # Key generation utility (RSA-4096)
│   └── builder/main.go          # Interactive configuration builder
├── internal/
│   ├── crypto/
│   │   ├── crypto.go           # Core encryption/decryption logic
│   │   └── compression.go      # LZ4 compression handling
│   ├── fs/
│   │   └── operations.go       # File system operations and secure deletion
│   └── system/
│       └── exclusions.go       # Multi-OS system file exclusions
├── pkg/
│   └── config/
│       └── config.go          # CLI flag parsing and shared configuration
├── docs/                      # Comprehensive documentation
├── Makefile                   # Build and development automation
└── go.mod/go.sum             # Go module dependencies
```

## Setup Instructions

### Prerequisites

- **Go 1.25.0+** (required)
- **golangci-lint** (for code quality checks, auto-installed by Makefile if missing)
- **make** (build system)

### Installation

```bash
# Clone and enter the project directory
cd go/

# Download dependencies
make deps

# Build all core binaries
make build
```

### Development Environment

```bash
# Install development tools and run quality checks
make check

# Set up demo environment for testing
make demo-setup
```

## Build & Run Commands

### Building

```bash
# Build core binaries (encrypt/decrypt)
make build

# Build individual components
make build-encrypt      # Build encrypt binary
make build-decrypt      # Build decrypt binary
make build-genkey       # Build key generation utility
make build-builder      # Build interactive builder

# Cross-platform builds
make build-all         # Build for all platforms (Windows/Linux/macOS)
make build-linux       # Build Linux binaries (amd64)
make build-windows     # Build Windows binaries (amd64)

# Embedded public key builds (no external key file needed)
make build-encrypt-pub PUBKEY_B64="$(cat public-key-file)"
make build-all-pub PUBKEY_B64="$(cat public-key-file)"
```

### Running

```bash
# Generate encryption keys
./build/genkey -name backup-key

# Encrypt files (safe mode - user data only)
./build/encrypt -dir ./testdata -key private-backup-key -verbose

# Encrypt with embedded public key (no key file distribution needed)
make build-encrypt-pub PUBKEY_B64="$(cat public-backup-key)"
./build/encrypt -dir ./testdata -verbose

# Decrypt files
./build/decrypt -dir ./testdata -key private-backup-key -verbose

# Interactive builder for complex configurations
./build/builder
```

### Development Commands

```bash
# Quality checks
make fmt         # Format code
make vet         # Static analysis
make lint        # Advanced linting with golangci-lint
make check       # Run all quality checks (fmt + vet + lint + test)

# Testing
make test        # Run unit tests
make test-race   # Run tests with race detection
make bench       # Run performance benchmarks

# Demo workflows
make demo-setup  # Create test files and demo key
make demo-encrypt # Run encryption demo
make demo-decrypt # Run decryption demo
make demo-clean  # Clean demo files

# Maintenance
make deps        # Download and tidy dependencies
make deps-update # Update dependencies to latest versions
make clean       # Remove build artifacts
```

## Testing Instructions

### Unit Tests

```bash
# Run all tests
make test

# Run tests with race detection
make test-race

# Run specific package tests
go test ./internal/crypto/...
go test ./pkg/config/...

# Run tests with verbose output
go test -v ./...
```

### Integration Testing

```bash
# Full demo workflow (creates test data, encrypts, decrypts, verifies)
make demo-setup
make demo-encrypt
make demo-decrypt
make demo-clean

# Manual integration testing
./build/genkey -name test
./build/encrypt -dir ./testdata -key private-test -benchmark -verbose
./build/decrypt -dir ./testdata -key private-test -benchmark -verbose
```

### Performance Testing

```bash
# Benchmark encryption/decryption throughput
./build/encrypt -dir ./large-dataset -benchmark -workers 8 -verbose
./build/decrypt -dir ./large-dataset -benchmark -workers 8 -verbose

# Run Go benchmarks
make bench
```

### Dry Run Testing

```bash
# Test what would be encrypted without making changes
./build/encrypt -dir ./testdata -dry-run -verbose

# Validate decryption scope
./build/decrypt -dir ./testdata -dry-run -verbose
```

## Code Style & Conventions

### Go Standards

- **Formatting**: Uses standard `go fmt` formatting
- **Imports**: Grouped standard library, then third-party, then internal
- **Naming**: Follows Go conventions (PascalCase for exported, camelCase for internal)
- **Error Handling**: Explicit error returns, no panics in production code
- **Concurrency**: Goroutines with proper synchronization using `sync.WaitGroup` and channels

### Project-Specific Conventions

```go
// Function signatures follow this pattern
func functionName(param Type) (result Type, err error)

// Error handling pattern
if err != nil {
    return fmt.Errorf("descriptive error: %w", err)
}

// Logging uses consistent emoji prefixes
fmt.Printf("✅ Success message\n")
fmt.Printf("❌ Error message\n")
fmt.Printf("⚠️  Warning message\n")
```

### Code Quality Tools

- **`go fmt`**: Automatic code formatting
- **`go vet`**: Static analysis for common mistakes
- **`golangci-lint`**: Comprehensive linting (installed automatically by Makefile)

### File Extensions and Processing

The encryptor processes files with these extensions by default:

- Documents: `.docx`, `.xlsx`, `.pptx`, `.pdf`, `.txt`
- Archives: `.zip`, `.tar`, `.gz`, `.rar`
- Media: `.jpg`, `.png`, `.mp4`, `.avi`
- Code: `.go`, `.py`, `.js`, `.html`, `.css`
- Databases: `.db`, `.sqlite`, `.sql`

## File/Folder Guide

### Source Code Structure

- **`cmd/`**: CLI applications

  - `encrypt/`: File encryption utility
  - `decrypt/`: File decryption utility
  - `genkey/`: RSA key pair generation
  - `builder/`: Interactive configuration tool

- **`internal/`**: Private application code (not importable by other projects)

  - `crypto/`: Encryption primitives and compression
  - `fs/`: File system operations and secure deletion
  - `system/`: OS-specific path exclusions and detection

- **`pkg/`**: Public library code (potentially importable by other projects)

  - `config/`: CLI flag parsing and configuration structs

- **`docs/`**: Documentation
  - `overview.md`: Encryption flow and binary outputs
  - `usage.md`: Everyday CLI usage patterns
  - `configuration.md`: Flag reference and build-time options
  - `troubleshooting.md`: Common issues and solutions
  - `safety.md`: Security practices and legal considerations

### Build Artifacts

- **`build/`**: Compiled binaries (created by `make build*` targets)
- **`test`**: Demo/test directory (created by `make demo-setup`)

### Configuration Files

- **`Makefile`**: Build automation and development tasks
- **`go.mod`**: Go module definition and dependencies
- **`go.sum`**: Dependency checksums

## Best Practices for Agents

### ✅ DO

- **Run quality checks before committing**: Always execute `make check`
- **Use the Makefile targets**: Prefer `make build` over manual `go build` commands
- **Test with demo environment**: Use `make demo-*` targets for safe testing
- **Handle errors explicitly**: Follow Go's error handling patterns
- **Use dry-run mode**: Test destructive operations with `-dry-run` first
- **Document security decisions**: Explain why certain security measures are implemented
- **Follow the existing architecture**: Keep new code in appropriate internal/pkg directories

### ❌ DON'T

- **Modify security-critical code without review**: Encryption, key handling, and secure deletion logic
- **Remove system exclusions**: The safety guard rails prevent OS damage
- **Use unsafe mode in production**: `--unsafe` is for testing only
- **Commit build artifacts**: The `build/` directory should not be versioned
- **Import internal packages**: Respect Go's internal package visibility rules
- **Panic in production code**: Use proper error returns instead
- **Modify auto-generated files**: Let build processes regenerate them

### Security Considerations

- **Key Management**: Never commit private keys or key files
- **Memory Security**: Sensitive data is cleared with `SecureClear()` methods
- **File Security**: Original files are securely deleted after successful encryption
- **Path Safety**: System directories are automatically excluded to prevent OS damage

### Examples

#### Good Practice: Safe Error Handling

```go
func processFile(filePath string) error {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return fmt.Errorf("failed to read file %s: %w", filePath, err)
    }

    encrypted, err := encryptData(data)
    if err != nil {
        return fmt.Errorf("encryption failed for %s: %w", filePath, err)
    }

    if err := secureDelete(filePath); err != nil {
        // Log warning but don't fail the operation
        log.Printf("⚠️  Secure deletion failed for %s: %v", filePath, err)
    }

    return os.WriteFile(filePath+".encrypted", encrypted, 0644)
}
```

#### Bad Practice: Unsafe Error Handling

```go
func processFile(filePath string) {
    data := os.ReadFile(filePath) // Ignores error!

    encrypted := encryptData(data) // Assumes success

    os.Remove(filePath) // No secure deletion!

    os.WriteFile(filePath+".encrypted", encrypted, 0644) // Ignores error!
}
```

## Security / Permissions

### Sensitive Files

- **Private Keys**: Files starting with `private-` contain decryption keys
- **Key Files**: Any file specified with `-key` flag contains sensitive material
- **Embedded Keys**: Binaries built with `PUBKEY_B64` contain public key material

### Handling Secrets

```bash
# Generate keys (keep private-* files secure)
./build/genkey -name sensitive-project

# Set proper permissions on key files
chmod 600 private-sensitive-project

# Never commit key files to version control
echo "private-*" >> .gitignore
```

### Safe Development Practices

- Use demo keys for development testing
- Store production keys in secure key management systems
- Use embedded public key builds to avoid distributing private keys
- Always test decryption workflows before deploying encryption operations

## Contribution Guidelines

### Code Changes

1. **Branch**: Create feature branches from `main`
2. **Quality**: Run `make check` before committing
3. **Tests**: Add unit tests for new functionality
4. **Documentation**: Update relevant docs in `docs/` directory
5. **Security**: Review security implications of changes

### Pull Request Process

1. **Description**: Clearly describe what changes and why
2. **Testing**: Include test results and demo validation
3. **Security Review**: Highlight any security-related changes
4. **Documentation**: Update AGENTS.md if development practices change

### Commit Messages

```
feat: add support for custom compression levels
fix: resolve race condition in worker pool
docs: update encryption algorithm documentation
security: improve key clearing in memory
```

### Release Process

1. **Version**: Update version in `Makefile` (uses git tags)
2. **Build**: Run `make build-all` for cross-platform binaries
3. **Test**: Validate on all target platforms
4. **Document**: Update changelog and release notes

---

**Legal Notice**: This tool is intended for educational, defensive security, and backup automation scenarios. Review local laws before using it in production environments, and never distribute it for malicious purposes.
