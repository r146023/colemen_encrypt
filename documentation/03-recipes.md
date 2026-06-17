# Recipes

This file contains practical command recipes. Replace paths and environment variable names with your own values.

## 1. Encrypt one file and remove the original after verification

```bash
export COLEMEN_ENCRYPT_PASSWORD="correct horse battery staple"
colemen_encrypt encrypt --target "./notes.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

Result:

```text
./notes.txt.enc
```

The original path is removed after verified encrypted output is produced.

## 2. Encrypt one file but keep the original

```bash
colemen_encrypt encrypt \
  --target "./notes.txt" \
  --password_env COLEMEN_ENCRYPT_PASSWORD \
  --keep_original true
```

Result:

```text
./notes.txt
./notes.txt.enc
```

Use this while testing.

## 3. Decrypt one file and keep the encrypted source

```bash
colemen_encrypt decrypt \
  --target "./notes.txt.enc" \
  --password_env COLEMEN_ENCRYPT_PASSWORD \
  --keep_original true
```

Result:

```text
./notes.txt.enc
./notes.txt
```

## 4. Encrypt a directory recursively

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

By default this recursively encrypts files in the directory tree.

## 5. Encrypt only files directly inside a directory

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --recursive false \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Subdirectories are not traversed.

## 6. Decrypt all encrypted files in a directory tree

```bash
colemen_encrypt decrypt \
  --target "./Documents" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

In decrypt mode, directory traversal only picks files ending in the encrypted extension, `.enc` by default.

## 7. Preview a large run before touching anything

```bash
colemen_encrypt encrypt \
  --target "./Archive" \
  --dry_run true \
  --verbose true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Dry run is the right move before destructive operations.

## 8. Encrypt using a target list

Create `targets.txt`:

```text
# One path per line
./Documents/private
./Pictures/id-card.png
./Receipts
```

Then run:

```bash
colemen_encrypt encrypt \
  --target_list "targets.txt" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Missing paths are skipped with warnings.

## 9. Write encrypted output into a separate directory

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --output_dir "./EncryptedDocuments" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

With the default `--keep_relative_path true`, nested files keep their relative structure inside `./EncryptedDocuments`.

## 10. Flatten encrypted output into one directory

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --output_dir "./EncryptedFlat" \
  --keep_relative_path false \
  --collision rename \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Use `--collision rename` when flattening. Otherwise files with the same basename will be skipped by default.

## 11. Encrypt with private output filenames

```bash
colemen_encrypt encrypt \
  --target "./SensitiveDocs" \
  --output_dir "./Encrypted" \
  --private_names true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

This reduces filename leakage. Original filenames are stored inside encrypted metadata.

## 12. Use a custom extension

```bash
colemen_encrypt encrypt \
  --target "./notes.txt" \
  --extension ".cenc" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Creates:

```text
notes.txt.cenc
```

Decrypt with the same extension setting when scanning directories:

```bash
colemen_encrypt decrypt \
  --target "./" \
  --extension ".cenc" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

## 13. Add a prefix and suffix on encryption

```bash
colemen_encrypt encrypt \
  --target "myFile.txt" \
  --prefix "encrypted_" \
  --suffix "_secure" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Creates:

```text
encrypted_myFile_secure.txt.enc
```

## 14. Remove prefix and suffix during decrypt only when explicitly provided

```bash
colemen_encrypt decrypt \
  --target "encrypted_myFile_secure.txt.enc" \
  --prefix "encrypted_" \
  --suffix "_secure" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Creates:

```text
myFile.txt
```

Without the `--prefix` and `--suffix` flags, the output would be:

```text
encrypted_myFile_secure.txt
```

This is deliberate. Decryption does not guess your naming policy.

## 15. Skip collisions safely

```bash
colemen_encrypt decrypt \
  --target "./notes.txt.enc" \
  --collision skip \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

If `notes.txt` already exists, the operation is skipped.

## 16. Rename on collision

```bash
colemen_encrypt decrypt \
  --target "./notes.txt.enc" \
  --collision rename \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

If `notes.txt` exists, the output becomes a new available name.

## 17. Overwrite on collision

```bash
colemen_encrypt decrypt \
  --target "./notes.txt.enc" \
  --collision overwrite \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Use this only when you are completely sure.

## 18. Use auth-only verification for huge files

```bash
colemen_encrypt encrypt \
  --target "./huge-video-archive.iso" \
  --verify auth \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

`auth` verifies encrypted chunks can be authenticated. `full` is safer but performs more work.

## 19. Use full verification for critical files

```bash
colemen_encrypt encrypt \
  --target "./legal-documents" \
  --verify full \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

This is the default and is the recommended setting when stability matters more than speed.

## 20. Produce JSON Lines for automation

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --machine_responses true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Each line is one JSON event. This is the best mode for `colemen_py` integration.

## 21. Stop on first failure

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --fail_fast true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Useful for CI/testing. For large real-world batches, the default `false` is usually better because one bad file should not block the rest of the run.

## 22. Best-effort overwrite before unlinking

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --delete_strategy best_effort_overwrite \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

This attempts to overwrite the original file before removing it. It is not a permanent SSD sanitization guarantee.

## 23. Preserve originals explicitly

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --delete_strategy none \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

or:

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --keep_original true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

## 24. Windows PowerShell example

```powershell
$env:COLEMEN_ENCRYPT_PASSWORD = "my password"
colemen_encrypt.exe encrypt `
  --target "C:\Users\Colemen\Documents\Private" `
  --output_dir "D:\EncryptedBackup" `
  --machine_responses true `
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

## 25. Linux backup-style encryption

```bash
export COLEMEN_ENCRYPT_PASSWORD="my password"
colemen_encrypt encrypt \
  --target "/home/colemen/Documents" \
  --output_dir "/mnt/backup/encrypted/Documents" \
  --keep_relative_path true \
  --collision skip \
  --verify full \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

## 26. Conservative batch command

This is the safe, boring, recommended batch pattern:

```bash
colemen_encrypt encrypt \
  --target_list "targets.txt" \
  --output_dir "./encrypted_output" \
  --keep_relative_path true \
  --collision skip \
  --verify full \
  --dry_run true \
  --verbose true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Review the dry run. Then run the same command with `--dry_run false` or remove the flag.
