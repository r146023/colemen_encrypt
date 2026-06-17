# colemen_encrypt documentation

This directory is the long-form documentation package for `colemen_encrypt`.

`colemen_encrypt` is a conservative file encryption/decryption command line application designed around these priorities:

1. Stable file operations.
2. Safe defaults.
3. Authenticated encryption.
4. Batch processing.
5. Machine-readable integration.
6. Honest deletion semantics.

The tool is intentionally not marketed as a magic SSD shredder. It can create verified encrypted output and then remove the original path using a configured deletion strategy, but file-level deletion on SSDs is always best-effort. The reliable strategy is to encrypt early, use full-disk encryption where possible, and use whole-device sanitize / cryptographic erase when high-assurance removal of historical plaintext is required.

## Documentation map

| File | Purpose |
|---|---|
| `01-quick-start.md` | Build, install, first encrypt/decrypt commands. |
| `02-cli-reference.md` | Complete command line option reference. |
| `03-recipes.md` | Practical command recipes for common workflows. |
| `04-safety-model.md` | Operational safety, deletion model, SSD caveats, and guarantees. |
| `05-file-format.md` | High-level explanation of the encrypted container format. |
| `06-machine-responses.md` | JSON Lines event format for scripts and `colemen_py`. |
| `07-output-paths-and-naming.md` | Output directory, relative paths, prefixes/suffixes, collisions, private names. |
| `08-verification-and-recovery.md` | Verification modes, recovery workflow, and failure handling. |
| `09-colemen-py-integration.md` | Integration pattern for wrapping the binary from Python. |
| `10-troubleshooting.md` | Common failures and fixes. |
| `examples/targets.txt` | Example target list file. |
| `examples/sample-commands.sh` | Bash examples. |
| `examples/sample-commands.ps1` | PowerShell examples. |

## Default behavior summary

The default behavior is intentionally conservative:

```text
collision        = skip
verify           = full
keep_original    = false
recursive        = true
preserve_metadata = true
thread_count     = 4
delete_strategy  = unlink
machine_responses = false
extension        = .enc
```

That means the application will skip output collisions, fully verify generated output, and only then attempt to remove the original file path. It will not overwrite existing files unless explicitly told to do so.

## Basic commands

Encrypt one file:

```bash
colemen_encrypt encrypt --target "myFile.txt" --password "mySecretPassword"
```

Decrypt one file:

```bash
colemen_encrypt decrypt --target "myFile.txt.enc" --password "mySecretPassword"
```

Safer password handling using an environment variable:

```bash
export COLEMEN_ENCRYPT_PASSWORD="mySecretPassword"
colemen_encrypt encrypt --target "myFile.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

Windows PowerShell:

```powershell
$env:COLEMEN_ENCRYPT_PASSWORD = "mySecretPassword"
colemen_encrypt.exe encrypt --target "myFile.txt" --password_env COLEMEN_ENCRYPT_PASSWORD
```

## Recommended first test

Before using the tool on important data, test it with a disposable directory:

```bash
mkdir -p ./ce_test
printf "hello colemen\n" > ./ce_test/a.txt
printf "another file\n" > ./ce_test/b.txt

export COLEMEN_ENCRYPT_PASSWORD="test-password"
colemen_encrypt encrypt --target ./ce_test --password_env COLEMEN_ENCRYPT_PASSWORD --keep_original true --verbose true
colemen_encrypt decrypt --target ./ce_test --password_env COLEMEN_ENCRYPT_PASSWORD --keep_original true --verbose true
```

Then inspect the outputs and only remove the test files once you understand the naming and deletion behavior.
