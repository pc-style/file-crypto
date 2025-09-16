# Configuration Reference

The CLI binaries share a configuration package (`pkg/config`) so they honour the same flags and defaults. This document groups options by capability and highlights notable behaviours.

## Core Flags

| Flag | Applies To | Description |
| --- | --- | --- |
| `-dir <path>` | encrypt, decrypt | Directory to traverse recursively. Must exist before the run. |
| `-key <file>` | encrypt (symmetric mode), decrypt | Path to the key file. Encrypt only requires it when you are not using an embedded public key. |
| `-workers <n>` | encrypt, decrypt | Maximum concurrent worker goroutines. Defaults to detected CPU cores. |
| `-buffer-size <bytes>` | encrypt, decrypt | Size of the buffered reader/writer blocks. Defaults to 64 KiB. |
| `-compression` / `-no-compression` | encrypt | Enables or disables LZ4 compression prior to encryption. |
| `-system-exclusions` / `-no-system-exclusions` | encrypt, decrypt | Toggle the guard rails that skip system directories and known safe paths. |
| `-unsafe` | encrypt, decrypt | Allow targeting high-risk locations (home directories, volume roots). Use with extreme caution. |
| `-benchmark` | encrypt, decrypt | Report throughput metrics after completion. |
| `-verbose` | all | Print per-file progress information and detailed errors. |
| `-quiet` | encrypt, decrypt | Suppress non-error output (inherited from `pkg/config`). |
| `-dry-run` | encrypt | List candidate files without modifying disk. |
| `-y`, `-yes` | encrypt, decrypt | Skip the confirmation prompt. |

## Include and Exclude Globs

Both encrypt and decrypt honour include/exclude lists supplied through the configuration struct. They accept comma-separated shell-style globs, e.g.

```bash
./build/encrypt -dir ./data -include "**/*.sql,**/*.bak" -exclude "**/tmp/**"
```

Includes are evaluated first; a file must match at least one include when the list is non-empty. Excludes remove files even if they were included previously. Path comparisons normalise path separators to forward slashes for portability.

## Default Allow List

The encryptor processes extensions commonly associated with user data (documents, images, archives, VM disk images, code, configuration). Binaries, drivers, and operating system files are skipped by default to reduce the risk of creating an unbootable machine.

To expand coverage you can either:

- Provide an include glob that matches additional extensions, or
- Modify the `isAllowedExtension` helper in `cmd/encrypt/main.go` for a custom build.

## Build-Time Overrides

Several defaults may be configured during compilation using `-ldflags -X` assignments. Examples:

```bash
go build -ldflags "-X file-crypto/pkg/config.DefaultTargetDirStr=/data -X file-crypto/pkg/config.DefaultEnableCompressionStr=false" ./cmd/encrypt
```

The `Makefile` sets version metadata (`main.version`) automatically using `git describe`. When embedding a public key the build commands override `file-crypto/internal/crypto.EmbeddedPublicKeyBase64` as well.

## System Exclusions

System exclusions are managed by `internal/system`. They perform three levels of protection:

1. **Root detection** – running against `/`, `C:\\`, or other volume roots requires `--unsafe`.
2. **Dangerous path warnings** – directories under `/home`, `/Users`, `/var`, etc. emit warnings when `--unsafe` is not provided, and the run aborts.
3. **Hard skips** – even in unsafe mode, core system paths are excluded to keep the OS bootable.

Review the package for the exact lists before building custom variants.

## Secure Deletion

When encryption succeeds, plaintext files are removed using secure overwrite routines from `internal/fs`. The buffer size is configurable via `-buffer-size`. Failures are logged but do not abort the entire run; the encrypted version remains on disk.

## Environment Variables

The tool does not rely on environment variables for configuration. Instead it intentionally uses explicit flags so that destructive operations require deliberate choices. If you need to script runs, wrap the command invocations in shell scripts or Makefile targets that codify the desired arguments.
