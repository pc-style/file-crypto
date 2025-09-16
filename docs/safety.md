# Safety Guidance

The File Crypto tooling is intentionally destructive. Follow these practices to minimise risk.

## General Principles

- **Operate on disposable data first.** Rehearse the complete encrypt/decrypt lifecycle in a VM or container using the demo data provided by `make demo-setup`.
- **Version-control your keys.** Treat the generated private keys like passwords. Store backups offline and restrict filesystem permissions.
- **Record your commands.** Keep a runbook of the arguments used for every exercise to aid incident reconstruction.
- **Monitor filesystem growth.** Encrypted data is written next to the source file with a `.encrypted` suffix. Ensure there is enough space to accommodate in-place replacements.

## Before Running Encryption

1. Run `./build/encrypt -dir <path> -dry-run` to validate the scope.
2. Confirm that include/exclude globs are correct and do not accidentally expand into temporary or system locations.
3. Verify backups and key custody so that data can be restored.
4. Decide whether `--unsafe` is required and document the justification if it is.

## During Execution

- Use `-verbose` during rehearsals to capture per-file status.
- Cancel the process immediately if it begins touching unintended directories.
- Monitor system resource usage when running with large worker counts; saturation can slow the secure-wiping stage.

## After Execution

- Archive run logs and benchmark data to support auditing.
- Confirm that `.encrypted` files exist for all expected targets before removing plaintext backups.
- When decryption is complete, verify file hashes or checksums to ensure integrity.

## Working with `--unsafe`

Unsafe mode is required when targeting home directories, `/var`, `/Users`, or filesystem roots. Remember:

- The binary still enforces a hard skip list with critical OS directories.
- Secure deletion happens immediately; there is no recycle bin, so mistakes are permanent.
- For production exercises, restrict usage to maintenance windows and obtain change approvals beforehand.

## Legal Notice

These binaries exist to support defensive security practices. Using them for unauthorised access or extortion is illegal. Always obtain written permission before conducting simulations on environments you do not own.
