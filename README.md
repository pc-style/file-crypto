# File Crypto (Go)

File Crypto is a portable command-line utility for encrypting and decrypting files in bulk. It was written for backup automation and blue-team exercises where you need to understand, rehearse, or harden recovery procedures. The tool supports fast symmetric encryption with optional public-key wrapping, optional LZ4 compression, secure wiping of originals, and multi-platform builds.

> **Legal & Safety Notice**
> Use the binaries only on data you are authorised to handle and always keep reliable backups of your private keys. Running destructive operations against production data, especially with `--unsafe`, can lead to irreversible loss.

## Key Capabilities

- ChaCha20-Poly1305 content encryption with per-file random material
- Optional RSA-4096 public key embedding so encryptors can run without distributing key files
- Secure file wiping and `.encrypted` suffix outputs so encrypted and original files never coexist
- Configurable worker pool, buffering, and compression for fast throughput on large datasets
- Built-in system directory guard rails and file-extension allow lists that reduce accidental OS damage
- Cross-platform builds via the `Makefile` (Linux, macOS, Windows, amd64/arm64)
- Policy-driven ransomware simulations that automatically stage recovery assets for blue-team drills

## Getting Started

```bash
# Clone or update dependencies first
make deps

# Build the core binaries into ./build/
make build

# Generate a key pair (writes private-<name> and public-<name>)
./build/genkey -name backup

# Encrypt a directory using the key file
./build/encrypt -dir ./testdata -key private-backup -verbose

# Or embed the public key at build time so the encryptor needs no external key file
make build-encrypt-pub PUBKEY_B64="$(cat public-backup)"

# Decrypt later with the private key
./build/decrypt -dir ./testdata -key private-backup -verbose
```

The binaries print a configuration summary before they run unless `-yes` (or `-y`) is supplied. In non-quiet mode you will also see per-file progress when `-verbose` is set.

## Configuration Overview

Commonly used flags are:

| Flag | Description |
| --- | --- |
| `-dir` | Directory to scan recursively for candidate files |
| `-key` | Path to the private key (encryption uses it unless a public key is embedded) |
| `-workers` | Number of concurrent workers (defaults to detected CPU cores) |
| `-compression` / `-no-compression` | Toggle LZ4 compression before encryption |
| `-system-exclusions` / `-no-system-exclusions` | Control automatic skipping of known OS locations |
| `-include` / `-exclude` | Glob filters to narrow or widen what gets encrypted |
| `-unsafe` | Allow targeting directories that contain user home data or the filesystem root |
| `-benchmark` | Measure throughput after a run |
| `-dry-run` | (Encrypt only) list what would be processed without changing files |

The encryptor only processes files whose extensions are on the default allow list. This focuses on user-generated content (documents, source code, archives, media, mail stores, VM images) while skipping executables and system-critical files.

## Safety Model

System exclusions are enabled by default and prevent traversal of operating system directories such as `/bin`, `/etc`, `C:\\Windows`, and device locations. When you explicitly pass `--unsafe`, those checks are relaxed so you can simulate worst-case incidents or perform full backups. Even in unsafe mode, critical system directories remain hard-coded skips; the tool never attempts to encrypt kernel or boot files.

Dry runs (`-dry-run`) and the confirmation prompt are the safest way to validate scope before executing destructive operations. Combine them with a dedicated test dataset located under `./testdata` or the helper `make demo-setup` to rehearse the workflow.

## Repository Layout

- `cmd/encrypt`, `cmd/decrypt`, `cmd/genkey`, `cmd/builder` – CLI entry points
- `internal/crypto` – encryption primitives, compression helpers, and hybrid RSA logic
- `internal/fs` – filesystem walking, secure deletion, size calculations
- `internal/system` – built-in path exclusions and detection of OS boundaries
- `pkg/config` – CLI flag parsing and shared runtime configuration
- `docs/` – extended documentation for usage, configuration, and troubleshooting

## Development Tasks

Helpful `Makefile` targets:

- `make build`, `make build-encrypt`, `make build-decrypt`, `make build-encrypt-pub`
- `make build-ransom-sim` to generate a self-contained ransomware simulation package (see below)
- `make build-linux`, `make build-windows`, `make build-all`
- `make demo-setup`, `make demo-encrypt`, `make demo-decrypt`, `make demo-clean`
- `make fmt`, `make vet`, `make test`, `make check`
- `make clean` to remove `./build` and cached artifacts

The project is module-aware (see `go.mod`). Run `go test ./...` to execute unit tests.

## Ransomware Simulation Mode

For incident-response rehearsals you can produce a policy-driven encryptor that behaves like controlled ransomware while keeping recovery artefacts within reach:

```bash
make build-ransom-sim
```

The target performs the following steps:

- Builds a decryptor binary and embeds it into the encryptor alongside a freshly generated RSA key pair.
- Embeds the default policy from `policies/ransomware-sim.yaml`, which targets user data patterns and enables simulation behaviour.
- Enables the new `--simulation` flag by default so that, after encryption completes, the binary drops the private key, decryptor, and a recovery note on the current user's desktop.

You can customise the policy or provide your own with `--policy <file>`. Simulation builds always surface the recovery artefacts to avoid accidental data loss during drills. If you modify the embedded policy, ensure it sets `simulation.enabled: true` so the safeguard remains active.

## Documentation

Additional guides live under `docs/`:

- `docs/overview.md` explains the encryption flow and binary outputs
- `docs/usage.md` walks through everyday tasks and CLI combinations
- `docs/configuration.md` catalogues flags, environment variables, and build-time toggles
- `docs/troubleshooting.md` lists common warning messages and suggested resolutions
- `docs/safety.md` summarises safe operating procedures and legal considerations

## License & Intended Use

This project is intended for educational, defensive security, and backup automation scenarios. Review local laws before using it in production environments, and never distribute it for malicious purposes. Keep private keys secured; without them encrypted data cannot be recovered.
