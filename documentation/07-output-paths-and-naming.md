# Output paths and naming

Naming and output placement are where accidental data loss can happen. `colemen_encrypt` uses conservative defaults to avoid overwriting files unexpectedly.

## Default encryption name

```text
myFile.txt -> myFile.txt.enc
```

Command:

```bash
colemen_encrypt encrypt --target "myFile.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Default decryption name

```text
myFile.txt.enc -> myFile.txt
```

Command:

```bash
colemen_encrypt decrypt --target "myFile.txt.enc" --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Custom extension

Use `--extension` to change the encrypted extension.

```bash
colemen_encrypt encrypt \
  --target "myFile.txt" \
  --extension ".cenc" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Result:

```text
myFile.txt.cenc
```

When decrypting directories, the same extension must be supplied if it is not `.enc`:

```bash
colemen_encrypt decrypt \
  --target "./encrypted" \
  --extension ".cenc" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Prefix

`--prefix` is applied during encryption before the filename.

```bash
colemen_encrypt encrypt \
  --target "myFile.txt" \
  --prefix "encrypted_" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Result:

```text
encrypted_myFile.txt.enc
```

## Suffix

`--suffix` is applied during encryption to the filename stem.

```bash
colemen_encrypt encrypt \
  --target "myFile.txt" \
  --suffix "_secure" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Result:

```text
myFile_secure.txt.enc
```

## Prefix and suffix together

```bash
colemen_encrypt encrypt \
  --target "myFile.txt" \
  --prefix "encrypted_" \
  --suffix "_secure" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Result:

```text
encrypted_myFile_secure.txt.enc
```

## Prefix/suffix removal during decrypt

Decryption does not automatically reverse prefix/suffix.

This is deliberate.

If you decrypt this file without prefix/suffix flags:

```text
encrypted_myFile_secure.txt.enc
```

The output is:

```text
encrypted_myFile_secure.txt
```

If you provide matching flags:

```bash
colemen_encrypt decrypt \
  --target "encrypted_myFile_secure.txt.enc" \
  --prefix "encrypted_" \
  --suffix "_secure" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

The output is:

```text
myFile.txt
```

This avoids surprising behavior. The user controls whether naming transformations are reversed.

## Output directory

Use `--output_dir` to write outputs somewhere else.

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --output_dir "./EncryptedDocuments" \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Keep relative paths

Default:

```text
--keep_relative_path true
```

Given:

```text
./Documents/tax/2025/report.pdf
```

Command:

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --output_dir "./EncryptedDocuments" \
  --keep_relative_path true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Output:

```text
./EncryptedDocuments/tax/2025/report.pdf.enc
```

## Flatten output

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --output_dir "./EncryptedDocuments" \
  --keep_relative_path false \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Output:

```text
./EncryptedDocuments/report.pdf.enc
```

Flattening can create collisions if multiple files have the same basename.

Example:

```text
./Documents/tax/2025/report.pdf
./Documents/work/2025/report.pdf
```

Both want:

```text
./EncryptedDocuments/report.pdf.enc
```

Default collision behavior is `skip`, so the second one would be skipped.

Use `--collision rename` if flattening many files:

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --output_dir "./EncryptedFlat" \
  --keep_relative_path false \
  --collision rename \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Collision behavior

### Skip

Default:

```text
--collision skip
```

This avoids accidental overwrite. Existing destinations are skipped.

### Rename

```bash
--collision rename
```

The app chooses an available destination name.

Use this when:

- Flattening output.
- Testing decrypt next to existing plaintext.
- Keeping both old and new outputs.

### Overwrite

```bash
--collision overwrite
```

The app overwrites the destination only after successful temp-file creation and verification.

Use only when intentional.

## Private names

Default output leaks filenames:

```text
divorce-paperwork.pdf -> divorce-paperwork.pdf.enc
```

With private names:

```bash
colemen_encrypt encrypt \
  --target "divorce-paperwork.pdf" \
  --private_names true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

The output name is randomized, and the original name is stored inside encrypted metadata.

Use private names when filenames reveal sensitive information.

## Practical naming recommendations

For daily convenience:

```bash
--extension ".enc"
--private_names false
```

For archive privacy:

```bash
--extension ".cenc"
--private_names true
--output_dir "./encrypted_archive"
```

For flattening:

```bash
--keep_relative_path false
--collision rename
```

For safest batch behavior:

```bash
--keep_relative_path true
--collision skip
```
