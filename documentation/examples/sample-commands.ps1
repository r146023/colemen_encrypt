# Example PowerShell command collection for colemen_encrypt.
# Edit paths before use.

$env:COLEMEN_ENCRYPT_PASSWORD = "change-me"

# Dry-run a directory encryption.
colemen_encrypt.exe encrypt `
  --target ".\Documents" `
  --dry_run true `
  --verbose true `
  --password_env COLEMEN_ENCRYPT_PASSWORD

# Encrypt one file while keeping the original.
colemen_encrypt.exe encrypt `
  --target ".\notes.txt" `
  --keep_original true `
  --password_env COLEMEN_ENCRYPT_PASSWORD

# Decrypt one file while keeping the encrypted source.
colemen_encrypt.exe decrypt `
  --target ".\notes.txt.enc" `
  --keep_original true `
  --collision rename `
  --password_env COLEMEN_ENCRYPT_PASSWORD

# Encrypt a directory into a separate output directory.
colemen_encrypt.exe encrypt `
  --target ".\Documents" `
  --output_dir ".\EncryptedDocuments" `
  --keep_relative_path true `
  --collision skip `
  --verify full `
  --password_env COLEMEN_ENCRYPT_PASSWORD

# Machine-readable JSON Lines for automation.
colemen_encrypt.exe encrypt `
  --target ".\Documents" `
  --machine_responses true `
  --password_env COLEMEN_ENCRYPT_PASSWORD | Out-File -Encoding utf8 colemen_encrypt_log.jsonl
