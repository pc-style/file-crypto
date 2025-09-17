# Usage Guide

This guide complements the CLI `-help` output with practical workflows.

## Preparing the Environment

1. Install Go 1.21 or newer.
2. Clone the repository and download dependencies with `make deps`.
3. Optionally run `make demo-setup` to create disposable files under `./test`.

## Generating Keys

```bash
make build-genkey
./build/genkey -name backup-lab
```

The command writes two files alongside the binary:

- `private-backup-lab` – keep this secure; it is required for decryption.
- `public-backup-lab` – base64-encoded DER, useful for embedding in encryptor builds.

## Encrypting Files

```bash
./build/encrypt -dir ./testdata -key private-backup-lab -verbose
```

- All matching files within the directory tree receive a `.encrypted` suffix.
- Original files are securely wiped after the encrypted data is persisted.
- By default system directories and already encrypted files are skipped.
- Add `-dry-run` to inspect the candidate list without touching disk.

Use glob filters to narrow or widen scope:

```bash
./build/encrypt -dir ./testdata -include "**/*.txt" -exclude "**/logs/**" -dry-run
```

### Partial Encryption Mode

When CPU time is at a premium, enable `--partial-encryption` to scramble only selected regions of each file. The encryptor targets roughly 10–30% of the processed payload (depending on file size) across multiple segments, which mirrors how modern ransomware accelerates large campaigns.

```bash
./build/encrypt -dir ./archives --partial-encryption -verbose
```

The output still requires the private key to restore the missing segments, but large portions of the file remain visible. Use this mode only for performance experiments or training scenarios—it is intentionally weaker than full-file encryption.

## Embedding Public Keys

To distribute an encryptor that does not rely on an external key file, embed the public key at build time:

```bash
make build-encrypt-pub PUBKEY_B64="$(cat public-backup-lab)"
./build/encrypt -dir ./testdata -verbose
```

The resulting binary runs in hybrid mode, generating random per-file keys and wrapping them with the embedded RSA key. For safety, system exclusions are enforced automatically for these builds.

## Decrypting Files

```bash
./build/decrypt -dir ./testdata -key private-backup-lab -verbose
```

- The decryptor scans for `*.encrypted` files and restores the original filenames.
- Integrity is verified using the ChaCha20-Poly1305 tag before data is written back.
- Failed decryptions are reported with detailed error messages when `-verbose` is set.

## Working in Unsafe Mode

Passing `--unsafe` relaxes the directory guard rails so that large user data sets or entire volumes can be processed.

```bash
./build/encrypt -dir /home/alice --unsafe -benchmark
```

Even in unsafe mode the hard-coded system deny list applies. Confirm the target path and run a dry-run before executing destructive operations on real machines.

## Cleaning Up

Use `make demo-clean` to remove demo data, or `make clean` to delete build artifacts. The `go clean` step inside the latter removes cached build outputs from module caches.

## Running Ransomware Simulations

Blue-team exercises often require a realistic ransomware run that still guarantees recovery. The `--simulation` flag, together with a policy file, activates a special mode that drops the private key, decryptor, and a recovery note onto the user's desktop once encryption completes.

```bash
./build/encrypt -dir ~/Documents --policy policies/ransomware-sim.yaml --simulation -verbose
```

The default policy (`policies/ransomware-sim.yaml`) targets common user file types, enables unsafe traversal, and instructs the encryptor to stage artefacts on the desktop. For convenience, `make build-ransom-sim` embeds both the policy and a decryptor so you can hand defenders a single binary for training.

## Running Tests

While the project is primarily CLI-focused, core packages include unit tests. Run them as part of regular maintenance:

```bash
make test
```

Replace with `make check` to run formatting, vetting, linting (if `golangci-lint` is installed), and tests in one go.
