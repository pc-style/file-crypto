# Project Overview

File Crypto is a Go rewrite of the original Python prototype that provided ransomware-style encryption for tabletop exercises. The current implementation keeps the staged, auditable workflow while adding a clearer separation between the CLI entry points and reusable libraries.

## Components

- **Encrypt CLI (`cmd/encrypt`)** – walks a directory tree, filters candidates, optionally compresses, encrypts, and replaces files with `.encrypted` versions while wiping the originals.
- **Decrypt CLI (`cmd/decrypt`)** – reverses the process by reading headers, verifying authentication, and restoring the original content with padding removed.
- **Key Generator (`cmd/genkey`)** – produces RSA-4096 key pairs suitable for hybrid mode and prints metadata about the generated keys.
- **Builder (`cmd/builder`)** – interactive assistant for preparing customised builds with specific flags or embedded keys.

Supporting packages encapsulate the heavy lifting:

- `internal/crypto` – ChaCha20-Poly1305 implementation, RSA wrapping, header parsing, compression helpers, and secure key destruction routines.
- `internal/fs` – directory walking with filters, secure file deletion using multi-pass overwrites, and helpers for `.encrypted` suffix management.
- `internal/system` – default allow lists and deny lists for paths, OS-specific shortcuts, and heuristics for classifying risky targets.
- `pkg/config` – command-line parsing, defaults, validation, and user-facing configuration summaries.

## Encryption Flow

1. **Scanning** – the encryptor walks the filesystem recursively. The default allow list limits work to document, source, archive, media, mailstore, and VM-related extensions.
2. **Filtering** – system directories (`/bin`, `/etc`, `C:\\Windows`, etc.) and previously encrypted files are skipped automatically unless explicitly overridden.
3. **Compression (optional)** – when enabled, data is compressed with LZ4 before encryption to maximise throughput and reduce output size.
4. **Key Derivation** – in symmetric mode the key is derived from the provided secret using PBKDF2; in hybrid mode a random content key is wrapped with the embedded RSA public key.
5. **Encryption** – padded chunks are encrypted using ChaCha20-Poly1305. Headers include versioning information, the original size, chunk count, and authentication tags.
6. **Persistence** – encrypted data is written as `<name>.encrypted`. The original plaintext file is securely wiped and removed.
7. **Reporting** – statistics and benchmark data are emitted at the end of the run.

The decryptor reverses these steps, validating integrity checks prior to restoring the original bytes.

## Build Targets

The `Makefile` exposes convenience targets for building native, Linux, macOS, and Windows binaries, including variants that embed a base64-encoded public key. These are thin wrappers around `go build` that set version information and optionally adjust `-ldflags` to inject the key material.

## Use Cases

- **Backup Drills** – rehearse key management and backup validation for critical workloads.
- **Incident Response Practice** – model encryption-based attacks in a controlled lab to verify containment and recovery playbooks.
- **Forensic Research** – study hybrid encryption headers and wiping routines without relying on commodity ransomware samples.
- **Demonstrations** – create replicas for tabletop exercises using the test data located under `./testdata` or with `make demo-setup`.

Every scenario should start in an isolated environment. Review the safety guidance in `docs/safety.md` or within the README before working with production-like data.
