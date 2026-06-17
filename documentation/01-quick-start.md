# Quick start

## Build

From the project root:

```bash
cargo build --release
```

The compiled binary will be created at:

```text
target/release/colemen_encrypt
```

On Windows:

```text
target\release\colemen_encrypt.exe
```

## Run from source during development

```bash
cargo run -- encrypt --target "myFile.txt" --password "mySecretPassword"
cargo run -- decrypt --target "myFile.txt.enc" --password "mySecretPassword"
```

Everything after `--` is passed to `colemen_encrypt`.

## Install locally

From the project root:

```bash
cargo install --path .
```

After that, `colemen_encrypt` should be available on your PATH if Cargo's bin directory is configured correctly.

## First safe test

Create a throwaway file:

```bash
mkdir -p ./scratch_encrypt_test
echo "hello world" > ./scratch_encrypt_test/hello.txt
```

Set a password in an environment variable:

```bash
export COLEMEN_ENCRYPT_PASSWORD="dev-test-password"
```

PowerShell:

```powershell
$env:COLEMEN_ENCRYPT_PASSWORD = "dev-test-password"
```

Encrypt while keeping the original:

```bash
colemen_encrypt encrypt \
  --target ./scratch_encrypt_test/hello.txt \
  --password_env COLEMEN_ENCRYPT_PASSWORD \
  --keep_original true \
  --verbose true
```

Expected result:

```text
scratch_encrypt_test/hello.txt
scratch_encrypt_test/hello.txt.enc
```

Decrypt while keeping the encrypted source:

```bash
colemen_encrypt decrypt \
  --target ./scratch_encrypt_test/hello.txt.enc \
  --password_env COLEMEN_ENCRYPT_PASSWORD \
  --keep_original true \
  --collision rename \
  --verbose true
```

Because `hello.txt` already exists, `--collision rename` allows the decrypted output to become something like:

```text
hello.txt.1
```

Without `--collision rename` or `--collision overwrite`, the decrypt command would skip the file because the destination already exists.

## Basic file encryption

```bash
colemen_encrypt encrypt --target "report.pdf" --password_env COLEMEN_ENCRYPT_PASSWORD
```

Creates:

```text
report.pdf.enc
```

Then, after successful verification, the original path is removed unless `--keep_original true` is provided.

## Basic file decryption

```bash
colemen_encrypt decrypt --target "report.pdf.enc" --password_env COLEMEN_ENCRYPT_PASSWORD
```

Creates:

```text
report.pdf
```

Then, after successful verification, the `.enc` source is removed unless `--keep_original true` is provided.

## Directory encryption

```bash
colemen_encrypt encrypt --target "./documents" --password_env COLEMEN_ENCRYPT_PASSWORD
```

By default this recursively encrypts regular files inside `./documents`.

## Directory decryption

```bash
colemen_encrypt decrypt --target "./documents" --password_env COLEMEN_ENCRYPT_PASSWORD
```

In decrypt mode, directories only process files ending in the configured encrypted extension, which defaults to `.enc`.

## Dry run

Use dry run before a large operation:

```bash
colemen_encrypt encrypt \
  --target "./documents" \
  --password_env COLEMEN_ENCRYPT_PASSWORD \
  --dry_run true \
  --verbose true
```

Dry run prints what would happen without writing, renaming, overwriting, decrypting, encrypting, or deleting files.

## Machine-readable mode

```bash
colemen_encrypt encrypt \
  --target "./documents" \
  --password_env COLEMEN_ENCRYPT_PASSWORD \
  --machine_responses true
```

This emits JSON Lines events, one JSON object per line. This mode is intended for scripts, wrappers, and `colemen_py`.
