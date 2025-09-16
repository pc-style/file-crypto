# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based file encryption/decryption utility that provides high-performance, secure file processing capabilities with multi-OS support. The project consists of two main components:

- `cmd/encrypt/` - Advanced file encryption using ChaCha20-Poly1305 with compression and metadata protection
- `cmd/decrypt/` - Corresponding decryption utility with concurrent processing

## Common Commands

### Building the Applications
```bash
make build                    # Build both encrypt and decrypt binaries
make build-encrypt           # Build only encrypt binary
make build-decrypt           # Build only decrypt binary
make build-all               # Build for all platforms (Windows, Linux, macOS)
```

### Running the Tools
```bash
# Encryption
./build/encrypt -dir ./test -benchmark -verbose
./build/encrypt -help                             # Show all options
./build/encrypt -no-compression -workers 8       # Disable compression, use 8 workers
./build/encrypt -max-performance                 # Maximum speed mode

# Decryption
./build/decrypt -dir ./test -benchmark -verbose
./build/decrypt -help                            # Show all options
./build/decrypt -no-system-exclusions           # Process system files
./build/decrypt -buffer-size 131072             # Use 128KB buffer
```

### Development Commands
```bash
make test                    # Run tests
make check                   # Run all quality checks (fmt, vet, lint, test)
make deps                    # Download and tidy dependencies
make clean                   # Clean build artifacts
```

### Demo Commands
```bash
make demo-setup              # Create test files and demo key
make demo-encrypt            # Run encryption demo
make demo-decrypt            # Run decryption demo
make demo-clean              # Clean demo files
```

## Architecture

### Project Structure
```
file-crypto/
├── cmd/
│   ├── encrypt/main.go          # Encryption CLI application
│   └── decrypt/main.go          # Decryption CLI application
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
│       └── config.go          # Configuration and CLI flag parsing
├── Makefile                   # Build and development commands
└── go.mod                    # Go module dependencies
```

### Core Security Features
- **Encryption**: ChaCha20-Poly1305 authenticated encryption (version 4)
- **Key Derivation**: PBKDF2 with SHA256 (100,000 iterations)
- **Metadata Protection**: Fixed-size padding (1MB chunks) to hide file sizes
- **Anti-Forensics**: Secure file deletion with 3-pass random + zero overwrite
- **Perfect Forward Secrecy**: Per-session keys with unique salt/session IDs

### Performance Optimizations
- **Concurrency**: Goroutine worker pools with configurable sizing
- **I/O Optimization**: Buffered file operations with configurable buffer sizes
- **Compression**: LZ4 block compression before encryption
- **System Exclusions**: Skip OS-specific system files and directories
- **Cross-Platform**: Native builds for Windows, Linux, macOS (amd64/arm64)

### File Processing Pipeline
1. **File Discovery**: Concurrent directory traversal with system file filtering
2. **Compression**: Optional LZ4 block compression for size reduction
3. **Padding**: Fixed-chunk padding (1MB) for metadata protection
4. **Encryption**: ChaCha20-Poly1305 with random nonce and authentication tag
5. **Header Creation**: Version, salt, session ID, nonce, tag, and size metadata
6. **Secure Deletion**: Multi-pass overwrite of original files

### Multi-OS Support
- **macOS**: .DS_Store, .fseventsd, system bundles, application frameworks
- **Linux**: /proc, /sys, /dev, package managers, system directories
- **Windows**: System32, Program Files, registry files, temporary directories

## Dependencies

- `golang.org/x/crypto` - ChaCha20-Poly1305 cipher and PBKDF2 key derivation
- `github.com/pierrec/lz4/v4` - LZ4 compression library

## Development Notes

- Default target directory: `./test` (configurable via `-dir` flag)
- Encryption key file: `decryption_key.txt` (configurable via `-key` flag)
- Encrypted files use `.encrypted` extension
- Worker pool sizing based on `runtime.NumCPU()` by default
- Atomic operations for thread-safe statistics tracking
- Graceful error handling with detailed error messages

## Security Considerations

This is a defensive security tool for file protection. The implementation includes:
- Authenticated encryption preventing tampering
- Key derivation functions preventing rainbow table attacks
- Secure memory clearing to prevent key recovery
- Multi-pass secure deletion for anti-forensics
- Cross-platform system file exclusions to avoid encrypting critical OS files