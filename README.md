# colemen_encrypt

`colemen_encrypt` is a conservative file encryption/decryption CLI designed for safe batch processing, machine-readable integration, and minimal data-loss risk.

It uses:

- **AES-256-GCM-SIV** authenticated encryption
- **Argon2id** password-based key derivation
- Unique per-file salt
- Chunked streaming encryption/decryption
- Encrypted metadata inside each encrypted file
- Atomic temp-file writes where possible
- Verification before original removal
- Safe collision defaults
- Human logs by default, JSON Lines with `--machine_responses true`

> Important: file-level deletion on SSDs is best-effort only. `colemen_encrypt` can remove or best-effort overwrite source files after successful verification, but it does **not** claim permanent sanitization of SSD cells, remapped blocks, snapshots, journals, backups, cloud-sync caches, or filesystem artifacts. For high-assurance removal of plaintext that already existed on an SSD, use full-device sanitize / cryptographic erase after verified encrypted copies are created.

---

## Basic usage

```bash
colemen_encrypt encrypt --target "myFile.txt" --password "mySecretPassword"
```

Creates:

```text
myFile.txt.enc
```

By default, after the encrypted file is written and verified, the original is removed with the configured deletion strategy. Use `--keep_original true` to keep it.

```bash
colemen_encrypt encrypt --target "myFile.txt" --password "mySecretPassword" --keep_original true
```

Decrypt:

```bash
colemen_encrypt decrypt --target "myFile.txt.enc" --password "mySecretPassword"
```

Creates:

```text
myFile.txt
```

---

## CLI shape

```bash
colemen_encrypt <encrypt|decrypt> [OPTIONS]
```

Common examples:

```bash
colemen_encrypt encrypt --target "./docs" --password "secret" --recursive true
colemen_encrypt decrypt --target "./docs" --password "secret" --recursive true
colemen_encrypt encrypt --target_list "files.txt" --password "secret" --output_dir "./encrypted"
colemen_encrypt encrypt --target "a.txt" --password "secret" --machine_responses true
colemen_encrypt encrypt --target "big.iso" --password "secret" --verify auth
```

---

## Options

### Required input

Exactly one of these must be provided:

```text
--target PATH
--target_list PATH
```

Password can be supplied directly:

```text
--password VALUE
```

Or through an environment variable:

```text
--password_env ENV_VAR_NAME
```

Using `--password_env` is usually safer than putting the password directly in the shell history or process list.

---

## Core options

```text
--output_dir PATH
```

Optional output directory. If omitted, output is written next to each source file.

```text
--keep_relative_path true|false
```

Default: `true`.

When `--output_dir` is provided, this controls whether discovered files keep their relative path structure inside the output directory.

```text
--keep_original true|false
```

Default: `false`.

If `false`, the original is removed only after the output file has been created and verified.

```text
--thread_count N
```

Default: `4`.

Controls parallel file processing.

```text
--recursive true|false
```

Default: `true`.

Controls directory traversal.

```text
--preserve_metadata true|false
```

Default: `true`.

Preserves timestamps and permissions where supported. Original metadata is also stored inside the encrypted file's encrypted metadata block.

```text
--dry_run true|false
```

Default: `false`.

Simulates the run and prints planned work without modifying files.

```text
--verbose true|false
```

Default: `false`.

Prints additional detail.

```text
--machine_responses true|false
```

Default: `false`.

Prints JSON Lines events instead of human-readable logs.

---

## Naming options

```text
--prefix VALUE
--suffix VALUE
```

Prefix and suffix are applied during encryption.

Example:

```bash
colemen_encrypt encrypt --target "myFile.txt" --password "secret" --prefix "encrypted_" --suffix "_secure"
```

Creates:

```text
encrypted_myFile_secure.txt.enc
```

During decryption, prefix/suffix are only removed if the decrypt command provides the matching values:

```bash
colemen_encrypt decrypt --target "encrypted_myFile_secure.txt.enc" --password "secret" --prefix "encrypted_" --suffix "_secure"
```

Creates:

```text
myFile.txt
```

Without those flags, it creates:

```text
encrypted_myFile_secure.txt
```

```text
--extension VALUE
```

Default: `.enc`.

You may choose `.cenc` or another extension.

```text
--private_names true|false
```

Default: `false`.

When enabled during encryption, output filenames are randomized and the original filename is stored only inside the encrypted metadata.

---

## Collision behavior

```text
--collision skip|rename|overwrite
```

Default: `skip`.

- `skip`: safest; do not write if destination exists
- `rename`: choose the next available filename
- `overwrite`: overwrite destination after successful temp-file creation and verification

---

## Verification behavior

```text
--verify full|hash|auth|none
```

Default: `full`.

- `full`: decrypts/rehashes generated encrypted files and compares plaintext hash when available
- `hash`: same hash-centered verification behavior
- `auth`: authenticates encrypted chunks without plaintext hash comparison
- `none`: skips extra verification; not recommended

`full` is the safest default. `auth` is useful for very large files when avoiding extra hashing work matters.

---

## Deletion behavior

```text
--delete_strategy unlink|best_effort_overwrite|none
```

Default: `unlink`.

- `unlink`: removes the source file path
- `best_effort_overwrite`: overwrites file content with zeros, flushes, then removes the file path
- `none`: leaves the source file in place

`best_effort_overwrite` is not a permanent-deletion guarantee on SSDs.

---

## Machine-readable output

Use:

```bash
colemen_encrypt encrypt --target "./docs" --password "secret" --machine_responses true
```

Output is JSON Lines:

```jsonl
{"type":"start","mode":"encrypt","dry_run":false,"thread_count":4,"item_count":10}
{"type":"file_success","mode":"encrypt","source":"/path/a.txt","destination":"/path/a.txt.enc","status":"success","bytes_read":123,"bytes_written":456,"duration_ms":12,"original_deleted":true,"deletion_assurance":"best_effort_file_level"}
{"type":"summary","mode":"encrypt","files_total":10,"files_success":9,"files_failed":0,"files_skipped":1,"warnings":1,"duration_ms":500}
```

---

## Exit codes

```text
0 = completed without file failures
1 = completed with one or more file failures
2 = invalid arguments or fatal setup error
5 = unexpected internal error
```

Skipped files are not considered fatal failures.

---

## Build

```bash
cargo build --release
```

The binary will be at:

```text
target/release/colemen_encrypt
```

On Windows:

```text
target\release\colemen_encrypt.exe
```
