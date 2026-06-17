# File format

This document explains the encrypted container at a high level. It is not a formal binary specification, but it captures the important design ideas.

## Goals

The encrypted file format is designed to be:

- Versioned.
- Self-describing enough to decrypt later.
- Authenticated.
- Streamable for large files.
- Able to store original metadata securely.
- Able to evolve in future versions.

## Magic and version

Encrypted files begin with an 8-byte magic value:

```text
CLENC001
```

This identifies the file as a `colemen_encrypt` version 1 container.

The configured filename extension defaults to `.enc`, but the extension is only a naming convention. The real format identifier is the magic/header inside the file.

## Cryptographic design

The current design uses:

```text
Cipher: AES-256-GCM-SIV
KDF:    Argon2id
Salt:   random per file
Chunks: authenticated encrypted chunks
```

AES-256-GCM-SIV provides authenticated encryption. That means decryption fails if the ciphertext, chunk authentication tag, associated data, or password is wrong.

Argon2id derives the actual encryption key from the user password and a per-file random salt.

## Public header

The file contains a public header with information needed to derive the key and process the file.

Conceptually:

```json
{
  "format": "colemen_encrypt",
  "format_version": 1,
  "cipher": "AES-256-GCM-SIV",
  "kdf": {
    "algorithm": "Argon2id",
    "version": 19,
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt_hex": "..."
  },
  "chunk_size": 4194304,
  "data_nonce_prefix_hex": "...",
  "filename_mode": "normal|private"
}
```

The public header is not secret, but it is authenticated through the encryption process so that tampering is detected.

## Encrypted metadata block

The original file metadata is stored inside an encrypted metadata block.

Conceptually:

```json
{
  "original_file_name": "report.pdf",
  "original_size": 123456,
  "chunk_size": 4194304,
  "chunk_count": 1,
  "plaintext_sha256": "...",
  "readonly": false,
  "modified_unix_ms": 1780000000000,
  "accessed_unix_ms": 1780000000000,
  "created_unix_ms": 1780000000000,
  "unix_mode": 420
}
```

Because this block is encrypted, private filename mode can avoid leaking the original file name through the output path.

## Plaintext hash

When verification mode is `full` or `hash`, the plaintext SHA-256 is computed during encryption and stored inside encrypted metadata.

This enables later verification that decrypted output exactly matches the original plaintext bytes.

## Chunked encryption

Large files are processed in chunks rather than loaded entirely into memory.

Default chunk size:

```text
4 MiB
```

Each chunk is encrypted and authenticated independently using associated data that ties it to its position and context. This prevents a chunk from being silently changed or rearranged without detection.

## Why chunking matters

Chunking allows the tool to process huge files without requiring huge memory usage.

For example, a 40 GB file should not require 40 GB of RAM. It should be processed as a stream of chunks.

## Filename modes

### Normal names

Default behavior preserves the source filename in the encrypted output filename:

```text
report.pdf -> report.pdf.enc
```

This is convenient, but leaks the original filename.

### Private names

With:

```bash
--private_names true
```

The encrypted output filename is randomized.

The original filename is stored inside encrypted metadata and restored during decryption where practical.

This is useful when filenames themselves reveal sensitive information.

## Extension is configurable

Default:

```text
.enc
```

Alternative:

```bash
--extension ".cenc"
```

If a directory is supplied in decrypt mode, only files ending in the configured extension are selected.

## Compatibility expectations

The file format is versioned so future versions can change details while preserving backwards compatibility.

A future version could add:

- Additional ciphers.
- External key files.
- Different KDF settings.
- Stronger metadata preservation.
- More formal manifests.
- Compression before encryption.

Compatibility rule:

```text
Do not silently decrypt unknown format versions.
```

Unknown versions should fail clearly.

## Corruption and tampering behavior

If the file is corrupted, truncated, modified, or decrypted with the wrong password, decryption should fail.

Expected symptoms:

- Authentication failure.
- Header parse failure.
- Metadata decrypt failure.
- Chunk decrypt failure.
- Hash verification failure.

In all cases, the tool should avoid deleting the source encrypted file unless successful verified output has been produced.

## Manual identification

You can inspect the first bytes of an encrypted file with a hex tool. The magic should start with ASCII:

```text
CLENC001
```

Do not edit encrypted files manually. Even a one-byte change should cause authentication failure.
