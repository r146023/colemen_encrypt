# CLI reference

## Command shape

```bash
colemen_encrypt <encrypt|decrypt> [OPTIONS]
```

Examples:

```bash
colemen_encrypt encrypt --target "myFile.txt" --password "mySecretPassword"
colemen_encrypt decrypt --target "myFile.txt.enc" --password "mySecretPassword"
```

Boolean flags accept explicit values:

```bash
--keep_original true
--keep_original false
```

They can also be used as presence flags for `true`:

```bash
--keep_original
```

Hyphen aliases are supported for many options:

```bash
--keep_original true
--keep-original true
```

## Mode

### `encrypt`

Encrypts regular files. If a directory is supplied, regular files inside it are processed recursively by default.

Encrypted files receive the configured encrypted extension, which defaults to `.enc`.

### `decrypt`

Decrypts files in the `colemen_encrypt` container format. If a directory is supplied, only files with the configured encrypted extension are considered.

By default the encrypted extension is removed from the output name.

## Required input selection

Exactly one of the following must be supplied.

### `--target PATH`

A single file or directory to process.

```bash
colemen_encrypt encrypt --target "a.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
colemen_encrypt encrypt --target "./docs" --password_env COLEMEN_ENCRYPT_PASSWORD
```

### `--target_list PATH`

A text file containing one path per line.

```bash
colemen_encrypt encrypt --target_list "targets.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

Rules:

- Empty lines are ignored.
- Lines beginning with `#` are ignored.
- Missing paths are skipped with a warning.
- Directory entries are processed according to `--recursive`.
- If a directory is listed, it is recursive by default.

Example target list:

```text
# files to encrypt
/home/colemen/Documents
/home/colemen/Pictures/private.jpg
D:\Archive\Receipts
```

## Password options

Exactly one of the following must be supplied.

### `--password VALUE`

Supplies the password directly.

```bash
colemen_encrypt encrypt --target "a.txt" --password "secret"
```

This is convenient but not ideal because shell history and process listings can expose command-line arguments.

### `--password_env ENV_VAR_NAME`

Reads the password from an environment variable.

```bash
export COLEMEN_ENCRYPT_PASSWORD="secret"
colemen_encrypt encrypt --target "a.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

PowerShell:

```powershell
$env:COLEMEN_ENCRYPT_PASSWORD = "secret"
colemen_encrypt.exe encrypt --target "a.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

This is the recommended method for normal use.

## Output options

### `--output_dir PATH`

Writes output files into a separate directory.

```bash
colemen_encrypt encrypt \
  --target "./docs" \
  --output_dir "./encrypted_docs" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

If omitted, output files are written next to their source files.

### `--keep_relative_path true|false`

Default: `true`.

Only meaningful when `--output_dir` is provided.

When true, files discovered inside directories retain their relative layout inside `output_dir`.

```bash
colemen_encrypt encrypt \
  --target "./docs" \
  --output_dir "./encrypted" \
  --keep_relative_path true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Example:

```text
source: ./docs/tax/2025/report.pdf
output: ./encrypted/tax/2025/report.pdf.enc
```

When false, files are flattened into the output directory:

```text
source: ./docs/tax/2025/report.pdf
output: ./encrypted/report.pdf.enc
```

Use flattened output carefully because collisions become much more likely.

## Original handling

### `--keep_original true|false`

Default: `false`.

When false, the source file is removed after successful output creation and verification.

When true, the source file is left in place.

```bash
colemen_encrypt encrypt --target "a.txt" --password_env COLEMEN_ENCRYPT_PASSWORD --keep_original true
```

Important: when `keep_original` is false, the tool attempts source removal using the selected `--delete_strategy`. This does not guarantee permanent deletion from SSD cells, filesystem journals, snapshots, backups, cloud sync caches, or remapped storage blocks.

## Traversal and threading

### `--recursive true|false`

Default: `true`.

Controls directory traversal.

```bash
colemen_encrypt encrypt --target "./docs" --recursive false --password_env COLEMEN_ENCRYPT_PASSWORD
```

With `false`, only regular files directly inside the directory are considered.

### `--thread_count N`

Default: `4`.

Controls how many files are processed in parallel.

```bash
colemen_encrypt encrypt --target "./docs" --thread_count 8 --password_env COLEMEN_ENCRYPT_PASSWORD
```

Notes:

- More threads can improve throughput across many small or medium files.
- For a few huge files, disk speed and Argon2 settings may dominate.
- Use a lower number on slow disks or heavily loaded systems.

## Metadata

### `--preserve_metadata true|false`

Default: `true`.

When true, the tool attempts to preserve timestamps and permissions where supported by the platform.

The original metadata is also stored inside the encrypted metadata block so decryption can restore what is practical later.

## Logging

### `--verbose true|false`

Default: `false`.

Prints additional details in human-readable mode.

```bash
colemen_encrypt encrypt --target "./docs" --verbose true --password_env COLEMEN_ENCRYPT_PASSWORD
```

### `--machine_responses true|false`

Default: `false`.

Switches output to JSON Lines.

```bash
colemen_encrypt encrypt --target "./docs" --machine_responses true --password_env COLEMEN_ENCRYPT_PASSWORD
```

Use this for wrappers and automation.

## Dry run

### `--dry_run true|false`

Default: `false`.

Simulates processing without modifying files.

```bash
colemen_encrypt encrypt --target "./docs" --dry_run true --verbose true --password_env COLEMEN_ENCRYPT_PASSWORD
```

Use dry run before any destructive batch operation.

## Naming

### `--extension VALUE`

Default: `.enc`.

```bash
colemen_encrypt encrypt --target "a.txt" --extension ".cenc" --password_env COLEMEN_ENCRYPT_PASSWORD
```

Creates:

```text
a.txt.cenc
```

Decrypt mode only scans files ending in the configured extension when a directory is supplied.

### `--prefix VALUE`

Default: empty.

Applied during encryption.

```bash
colemen_encrypt encrypt --target "a.txt" --prefix "encrypted_" --password_env COLEMEN_ENCRYPT_PASSWORD
```

Creates:

```text
encrypted_a.txt.enc
```

During decryption, the prefix is removed only if the decrypt command provides the same prefix.

### `--suffix VALUE`

Default: empty.

Applied to the filename stem during encryption.

```bash
colemen_encrypt encrypt --target "a.txt" --suffix "_secure" --password_env COLEMEN_ENCRYPT_PASSWORD
```

Creates:

```text
a_secure.txt.enc
```

During decryption, the suffix is removed only if the decrypt command provides the same suffix.

### `--private_names true|false`

Default: `false`.

When true during encryption, output filenames are randomized and the original filename is stored inside encrypted metadata.

```bash
colemen_encrypt encrypt --target "secret-plan.docx" --private_names true --password_env COLEMEN_ENCRYPT_PASSWORD
```

This reduces filename leakage, especially when encrypting files into an output directory.

## Collision behavior

### `--collision skip|rename|overwrite`

Default: `skip`.

#### `skip`

Safest. If the destination already exists, do nothing for that file and log a warning.

```bash
colemen_encrypt decrypt --target "a.txt.enc" --collision skip --password_env COLEMEN_ENCRYPT_PASSWORD
```

#### `rename`

Choose a new available destination name.

```bash
colemen_encrypt decrypt --target "a.txt.enc" --collision rename --password_env COLEMEN_ENCRYPT_PASSWORD
```

#### `overwrite`

Replace the destination after successful temp-file creation and verification.

```bash
colemen_encrypt decrypt --target "a.txt.enc" --collision overwrite --password_env COLEMEN_ENCRYPT_PASSWORD
```

Use overwrite deliberately. It is intentionally not the default.

## Verification

### `--verify full|hash|auth|none`

Default: `full`.

#### `full`

Safest default. Verifies the generated output thoroughly before original removal.

For encryption, this means the encrypted output can be reopened, authenticated, decrypted, and compared against the stored plaintext hash when available.

For decryption, this means the decrypted output can be compared against the plaintext hash stored inside the encrypted metadata when available.

#### `hash`

Hash-centered verification. Similar to full in the current design where plaintext SHA-256 is available.

#### `auth`

Authenticates encrypted chunks without requiring plaintext hash comparison.

This is useful for very large files when extra hash comparison is too expensive, but `full` remains the safest default.

#### `none`

Skips extra verification.

Not recommended except for controlled tests.

## Deletion strategy

### `--delete_strategy unlink|best_effort_overwrite|none`

Default: `unlink`.

#### `unlink`

Removes the source file path using normal filesystem deletion after successful output verification.

#### `best_effort_overwrite`

Attempts to overwrite the source file content with zeros, flush, then remove the file path.

This can reduce recoverability on some storage, but it is not a reliable permanent-deletion guarantee on SSDs, copy-on-write filesystems, journaled filesystems, cloud sync folders, or systems with snapshots/backups.

#### `none`

Leaves the original in place.

This is equivalent in practical source-retention behavior to `--keep_original true`, but it is explicit through the deletion strategy.

## Double encryption

### `--allow_double_encrypt true|false`

Default: `false`.

By default, encrypt mode skips files already ending in the encrypted extension.

Use this only if you intentionally want to encrypt an encrypted file again.

```bash
colemen_encrypt encrypt --target "a.txt.enc" --allow_double_encrypt true --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Cryptographic tuning

The defaults are intended to be reasonable. Change these only when you know why.

### `--chunk_size BYTES`

Default: `4194304` bytes, which is 4 MiB.

Larger chunks can slightly reduce per-chunk overhead. Smaller chunks can reduce memory pressure and improve progress granularity.

```bash
colemen_encrypt encrypt --target "big.iso" --chunk_size 8388608 --password_env COLEMEN_ENCRYPT_PASSWORD
```

### `--argon2_memory_kib N`

Argon2id memory cost in KiB.

Higher values make password guessing more expensive but also make encryption/decryption startup per file heavier.

```bash
colemen_encrypt encrypt --target "a.txt" --argon2_memory_kib 131072 --password_env COLEMEN_ENCRYPT_PASSWORD
```

### `--argon2_iterations N`

Argon2id iteration count.

```bash
colemen_encrypt encrypt --target "a.txt" --argon2_iterations 4 --password_env COLEMEN_ENCRYPT_PASSWORD
```

### `--argon2_parallelism N`

Argon2id parallelism parameter.

```bash
colemen_encrypt encrypt --target "a.txt" --argon2_parallelism 2 --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Failure control

### `--fail_fast true|false`

Default: `false`.

When false, the app keeps processing after file-level failures.

When true, processing stops after the first file-level failure.

```bash
colemen_encrypt encrypt --target "./docs" --fail_fast true --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Exit codes

```text
0 = completed without file failures
1 = completed with one or more file failures
2 = invalid arguments or fatal setup error
5 = unexpected internal error
```

Skipped files are warnings/skips, not necessarily fatal failures.
