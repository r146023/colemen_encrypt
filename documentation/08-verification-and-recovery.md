# Verification and recovery

`colemen_encrypt` is designed to avoid source deletion until output has been verified.

The important rule is:

```text
Do not remove the source until the destination exists and passes the requested verification mode.
```

## Verification modes

### `full`

Default and safest.

```bash
colemen_encrypt encrypt --target "a.txt" --verify full --password_env COLEMEN_ENCRYPT_PASSWORD
```

For encryption, full verification confirms the encrypted file can be reopened, authenticated, decrypted, and matched against the plaintext hash when available.

For decryption, full verification confirms the decrypted output matches the plaintext hash stored in encrypted metadata when available.

Use `full` for important files.

### `hash`

Hash-centered verification.

```bash
colemen_encrypt encrypt --target "a.txt" --verify hash --password_env COLEMEN_ENCRYPT_PASSWORD
```

This mode is useful when the plaintext hash is the primary verification signal.

### `auth`

Authentication-only verification.

```bash
colemen_encrypt encrypt --target "large.iso" --verify auth --password_env COLEMEN_ENCRYPT_PASSWORD
```

This confirms encrypted chunks authenticate with the provided password/key. It avoids some extra hash comparison work.

Use this for huge files where speed matters, but understand that `full` is the safest default.

### `none`

```bash
colemen_encrypt encrypt --target "a.txt" --verify none --password_env COLEMEN_ENCRYPT_PASSWORD
```

This skips extra verification. It is not recommended for real data.

## What happens if verification fails?

If verification fails:

- The operation reports `file_error`.
- The source is not removed.
- The temporary output should not be promoted as a trusted final output.
- The process continues to the next file unless `--fail_fast true` is set.

## What happens if decryption password is wrong?

Authenticated decryption should fail.

Expected result:

- No successful plaintext output.
- Source encrypted file remains.
- File-level error is reported.

## Recovery after interruption

If the process is interrupted, inspect the directory for temporary files. A well-designed file operation writes to temp paths first and only promotes verified output to final paths.

Recommended recovery steps:

1. Do not immediately delete anything.
2. Check the logs or machine-response events.
3. Identify which files reported success.
4. Re-run with `--dry_run true` to see remaining work.
5. Re-run normally for skipped/failed files.
6. Manually remove stale temp files only after you are sure they are not needed.

## Recovery after collision skips

If files were skipped due to destination collisions, choose one of these strategies:

### Keep destination and skip source

Do nothing. This is safest if the existing destination is already the correct file.

### Rename new output

```bash
colemen_encrypt decrypt \
  --target "a.txt.enc" \
  --collision rename \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

### Overwrite destination

```bash
colemen_encrypt decrypt \
  --target "a.txt.enc" \
  --collision overwrite \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Only use overwrite when you are certain.

## Batch failure handling

Default:

```text
--fail_fast false
```

This means one failure does not stop the whole batch.

For a large target list, this is usually correct. You want all possible files processed and a complete report at the end.

For testing or CI:

```bash
--fail_fast true
```

This stops at the first failure.

## Recommended serious-data workflow

### Step 1: dry run

```bash
colemen_encrypt encrypt \
  --target_list "targets.txt" \
  --output_dir "./encrypted" \
  --keep_relative_path true \
  --collision skip \
  --verify full \
  --dry_run true \
  --verbose true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

### Step 2: real run with machine responses

```bash
colemen_encrypt encrypt \
  --target_list "targets.txt" \
  --output_dir "./encrypted" \
  --keep_relative_path true \
  --collision skip \
  --verify full \
  --machine_responses true \
  --password_env COLEMEN_ENCRYPT_PASSWORD > encrypt-log.jsonl
```

### Step 3: inspect summary

Search for failures:

```bash
grep '"type":"file_error"' encrypt-log.jsonl
```

Search for warnings:

```bash
grep '"type":"file_warning"' encrypt-log.jsonl
```

View final summary:

```bash
tail -n 1 encrypt-log.jsonl
```

### Step 4: backup encrypted output

Copy the encrypted output to another encrypted drive or backup target.

### Step 5: consider device-level sanitization

If the original plaintext existed on an SSD and high-assurance removal matters, sanitize the whole original device after verified encrypted backups exist.

## Hash comparison mindset

A plaintext hash is valuable because it verifies exact byte equality.

During encryption:

```text
read plaintext -> compute SHA-256 -> encrypt -> store hash inside encrypted metadata
```

During verification/decryption:

```text
decrypt -> compute SHA-256 -> compare against stored hash
```

If hashes match, the decrypted plaintext bytes match the original bytes that were encrypted.

## What hash verification does not prove

Hash verification does not prove:

- The password was strong.
- The original was permanently deleted from an SSD.
- No other plaintext copies exist elsewhere.
- No malware captured the file before encryption.
- No application temp files exist.

It proves byte-level round-trip integrity for the encrypted container.

## Password loss

If the password is lost, the encrypted files should be treated as unrecoverable.

There should be no backdoor.

Use a password manager or secure recovery process.

## Password change workflow

To change the password on encrypted files:

1. Decrypt with the old password into a safe encrypted volume.
2. Encrypt with the new password.
3. Verify the new encrypted output.
4. Remove intermediate plaintext carefully.

There is no safe way to change the password without decrypting/re-encrypting unless a future file format adds wrapped data keys.
