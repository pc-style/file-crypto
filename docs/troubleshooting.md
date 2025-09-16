# Troubleshooting

This page lists recurring warnings and failures reported by the CLI along with recommended actions.

## Blocked Target Directory

**Message**
```
BLOCKED: Root directory encryption: /
```

**Cause** – You attempted to target a filesystem root without passing `--unsafe`.

**Resolution** – Validate why you need to work on the root volume. If it is intentional (for lab simulations), re-run with `--unsafe`. Otherwise choose a narrower directory.

---

**Message**
```
BLOCKED: Potentially dangerous directory: /home/user
```

**Cause** – Protective checks detected a path that normally contains user profiles. The run stops unless `--unsafe` is provided.

**Resolution** – Confirm the scope. Either run with `--unsafe` to proceed or point the command at a safer subdirectory.

## No Files Found

**Message**
```
ℹ️  No files found to encrypt.
```

**Cause** – Filters removed every file. Common reasons include the default extension allow list, existing `.encrypted` suffixes, or include/exclude globs that cancel each other out.

**Resolution** – Use `-dry-run` with relaxed filters to observe what would be processed. Adjust globs or modify the allow list if necessary.

## Validation Errors

**Message**
```
❌ Configuration error: target directory does not exist
```

**Cause** – The directory provided to `-dir` is missing.

**Resolution** – Create the directory or correct the path. Use absolute paths in automation scripts to avoid surprises.

---

**Message**
```
❌ Failed to load key: key file '...' not found
```

**Cause** – The key path supplied to the encryptor or decryptor is incorrect.

**Resolution** – Ensure the key file exists and that the process has permission to read it. Use `pwd` to verify relative paths.

## Decryption Failures

**Message**
```
❌ [Failed] example.txt.encrypted: decryption failed: chacha20poly1305: message authentication failed
```

**Cause** – The ciphertext was corrupted, the wrong key was supplied, or the file was truncated.

**Resolution** – Confirm that the correct private key is in use and restore the encrypted file from backup if it was partially deleted.

## Secure Deletion Warnings

**Message**
```
⚠️  [Warning] example.txt: secure deletion failed: permission denied
```

**Cause** – The process lacks permissions to overwrite or remove the plaintext file after encryption.

**Resolution** – Run the command with sufficient privileges or adjust filesystem permissions. The encrypted file has still been created; remove the original manually.

## Performance Issues

- Enable `-benchmark` to capture throughput metrics and identify bottlenecks.
- Increase or decrease `-workers` depending on CPU saturation or disk contention.
- When encrypting compressible data, leave `-compression` enabled to reduce I/O volume.

## Getting Help

If a message is not documented here, run the command again with `-verbose` to gather additional context. Review the source packages under `internal/` for implementation details specific to your build.
