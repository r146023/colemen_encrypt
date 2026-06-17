# Troubleshooting

## `provide exactly one of --target or --target_list`

You supplied both, or neither.

Correct:

```bash
colemen_encrypt encrypt --target "a.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

or:

```bash
colemen_encrypt encrypt --target_list "targets.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

Incorrect:

```bash
colemen_encrypt encrypt --target "a.txt" --target_list "targets.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

## `provide exactly one of --password or --password_env`

You supplied both, or neither.

Correct:

```bash
colemen_encrypt encrypt --target "a.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

or:

```bash
colemen_encrypt encrypt --target "a.txt" --password "secret"
```

Prefer `--password_env`.

## Destination exists; file skipped

Default collision behavior is `skip`.

This is intentional.

Options:

```bash
--collision rename
```

or:

```bash
--collision overwrite
```

Use overwrite carefully.

## Decrypt directory finds no files

In decrypt mode, directory traversal only selects files ending in the configured extension.

Default extension:

```text
.enc
```

If you encrypted with `.cenc`, decrypt with:

```bash
colemen_encrypt decrypt --target "./encrypted" --extension ".cenc" --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Wrong password

Expected behavior:

- Decryption fails.
- Source encrypted file remains.
- Output is not trusted/promoted.
- A file error is reported.

There is no password recovery.

## The decrypted file name still has my prefix/suffix

This is expected unless you provide the same prefix/suffix during decrypt.

Example:

```bash
colemen_encrypt decrypt \
  --target "encrypted_myFile_secure.txt.enc" \
  --prefix "encrypted_" \
  --suffix "_secure" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Without those flags:

```text
encrypted_myFile_secure.txt.enc -> encrypted_myFile_secure.txt
```

With those flags:

```text
encrypted_myFile_secure.txt.enc -> myFile.txt
```

## The app says deletion is best-effort

That is intentional and honest.

File-level deletion cannot guarantee permanent SSD sanitization. If high-assurance removal is required, use full-disk encryption ahead of time or sanitize the entire device after verified encrypted copies exist.

## `best_effort_overwrite` is slow

That mode writes over file content before deleting. It can be much slower than normal unlinking.

It is also not a reliable SSD sanitization guarantee.

For most cases, use:

```bash
--delete_strategy unlink
```

## Performance is slow on many small files

Possible causes:

- Argon2id key derivation happens per file.
- Too few worker threads.
- Slow disk or network drive.
- Antivirus scanning every file.
- Full verification doubles some I/O work.

Try:

```bash
--thread_count 8
```

For very large files where speed matters:

```bash
--verify auth
```

Do not weaken Argon2 settings unless you understand the security tradeoff.

## Performance is slow on one huge file

Thread count helps most when there are multiple files. One huge file is mostly limited by disk speed, CPU crypto speed, and verification mode.

Try:

```bash
--verify auth
```

or a larger chunk size:

```bash
--chunk_size 8388608
```

## Permission denied

Possible causes:

- File is open in another program.
- Directory is protected.
- Output directory is not writable.
- You do not have permission to preserve metadata.
- Antivirus or sync software has locked the file.

Try:

1. Close apps using the file.
2. Choose a writable output directory.
3. Run a dry run first.
4. Check OS permissions.

## Machine response parser fails

Make sure you used:

```bash
--machine_responses true
```

Do not parse human-readable logs.

Also capture stderr separately. Fatal setup errors may appear on stderr.

## Target list paths with spaces

Each line in `target_list` is one path. Do not add shell-style quotes unless they are actually part of the path.

Good:

```text
/home/colemen/My Documents/a.txt
D:\My Documents\a.txt
```

Avoid:

```text
"/home/colemen/My Documents/a.txt"
```

## Symlinks are not followed

Directory traversal does not follow symlinks by default. This avoids accidentally encrypting outside the intended tree.

If symlink behavior is needed later, it should be added as an explicit option.

## I encrypted with `--private_names true`; how do I know what files are what?

Private names intentionally hide original names in the output path.

Decrypt the files with the correct password; the original filename is stored inside encrypted metadata and can be restored where practical.

For archive management, keep an external encrypted manifest if you need searchable metadata without decrypting file contents.

## I accidentally used `--keep_original false`

If the operation succeeded, the original path may have been removed.

Recovery depends on the filesystem, drive, backups, and deletion strategy. There is no universal undo.

This is why the recommended workflow for important data is:

```bash
--dry_run true
--keep_original true
```

until you are confident.

## I accidentally overwrote something

Default collision mode is `skip`, so this only happens if `--collision overwrite` was explicitly used or another tool modified files.

Check backups immediately.

## Build fails

Run:

```bash
cargo clean
cargo update
cargo check
```

Then:

```bash
cargo build --release
```

Make sure you are using a current stable Rust toolchain:

```bash
rustup update stable
```

## Command works in terminal but not from another program

Likely causes:

- Different working directory.
- Binary not on PATH.
- Environment variable password not passed to subprocess.
- Path quoting issue.
- Wrapper using `shell=True` incorrectly.

Use absolute paths and pass arguments as a list.

## Good debug command

```bash
colemen_encrypt encrypt \
  --target "./test" \
  --dry_run true \
  --verbose true \
  --machine_responses false \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Once the plan looks right, remove `--dry_run true`.
