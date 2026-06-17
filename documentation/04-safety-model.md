# Safety model

`colemen_encrypt` is designed to be conservative. Its main job is to transform files safely:

```text
plaintext file -> verified encrypted file -> optional source removal
encrypted file -> verified plaintext file -> optional source removal
```

It is not designed to claim impossible guarantees about SSD-level permanent deletion.

## What the tool is meant to guarantee

When a file operation reports success, the intended guarantee is:

1. The source file was readable.
2. The output file was written to a temporary path first.
3. The output was flushed.
4. The output was verified according to `--verify`.
5. The temporary file was renamed/moved into its final destination.
6. Metadata preservation was attempted if enabled.
7. If `--keep_original false`, source removal was attempted after verified output existed.
8. The per-file report describes the result.

That is the right level of confidence for a file transformer.

## What the tool does not guarantee

The tool does not guarantee that old plaintext bytes are physically unrecoverable from:

- SSD wear-leveled cells.
- SSD spare/remapped blocks.
- Filesystem journals.
- Copy-on-write filesystem history.
- Snapshots.
- Backups.
- Cloud sync caches.
- Thumbnail caches.
- Search indexes.
- Application temp directories.
- Swap/page files.
- Hibernation files.
- RAM remnants.

This is not a weakness specific to `colemen_encrypt`; it is a reality of modern storage and operating systems.

## Why file-level SSD shredding is unreliable

On old spinning disks, overwriting a file's sectors was at least conceptually connected to the physical location of the data. On SSDs, that relationship breaks down.

SSDs use wear leveling and block remapping. When software writes to a logical block, the SSD firmware may write to a different physical flash cell and retire the old one later. The operating system usually cannot force a specific old physical cell to be overwritten.

That means file-level overwrite can reduce risk, but it cannot honestly promise permanent destruction of every previous copy.

## Recommended high-assurance strategy

For data that must be unrecoverable:

1. Use full-disk encryption before plaintext exists.
2. Keep sensitive working directories inside encrypted volumes.
3. When retiring or repurposing a drive, use whole-device sanitize / secure erase / cryptographic erase.
4. If the drive is leaving your control and the threat model is serious, destroy the media.

## Best practical strategy for existing plaintext

If plaintext already existed on an SSD and you now need to minimize exposure:

1. Encrypt the data you want to keep using `colemen_encrypt` or another trusted method.
2. Store the encrypted copy on a separate trusted encrypted volume.
3. Verify the encrypted copy.
4. Sanitize the entire original device using the drive/platform's supported sanitize mechanism.
5. Restore only the encrypted data.

This is the only sane way to handle historical plaintext on SSDs with high confidence.

## The role of `--keep_original`

Default:

```text
--keep_original false
```

This means the app attempts to remove the source after verified output exists.

It does not mean:

```text
all historical plaintext copies are permanently gone from the device
```

Machine-readable integrations should treat this as:

```json
{
  "original_deleted": true,
  "deletion_assurance": "best_effort_file_level"
}
```

## Deletion strategies

### `unlink`

Normal filesystem deletion. This removes the path from the filesystem after verified output exists.

Pros:

- Fast.
- Cross-platform.
- Less likely to fail in weird ways.

Cons:

- Does not overwrite content.
- Does not sanitize SSD cells.
- Does not remove snapshots/backups/cache copies.

### `best_effort_overwrite`

Attempts to write zeros over the file before unlinking it.

Pros:

- May help on some media/filesystems.
- Can reduce casual recovery risk on simple storage.

Cons:

- Not reliable on SSDs.
- Not reliable on copy-on-write filesystems.
- Not reliable with snapshots, journals, or backups.
- Slower.

### `none`

Does not remove the source.

Pros:

- Safest during testing.
- No destructive behavior.

Cons:

- Plaintext remains.

## Recommended defaults

The defaults are intentionally boring:

```text
collision        = skip
verify           = full
keep_original    = false
delete_strategy  = unlink
preserve_metadata = true
recursive        = true
```

Why these defaults?

- `skip` avoids accidental overwrite data loss.
- `full` avoids deleting originals before confidence is high.
- `unlink` is cross-platform and honest.
- `preserve_metadata` makes round-trips less destructive.
- `recursive` matches the expected target-list/directory behavior.

## Safe batch workflow

For serious data, use this pattern:

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

Review the plan.

Then run:

```bash
colemen_encrypt encrypt \
  --target_list "targets.txt" \
  --output_dir "./encrypted" \
  --keep_relative_path true \
  --collision skip \
  --verify full \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

Only after the summary is acceptable should you consider sanitizing original media if the threat model requires it.

## Threat-model tiers

### Casual privacy

Goal: prevent someone casually browsing your files.

Good enough:

```bash
colemen_encrypt encrypt --target "./private" --password_env COLEMEN_ENCRYPT_PASSWORD
```

### Lost laptop / stolen external drive

Goal: protect files if storage is stolen later.

Better:

- Use full-disk encryption.
- Store sensitive files already encrypted.
- Use strong passwords.
- Avoid leaving plaintext working copies.

### Drive disposal / adversarial recovery

Goal: prevent forensic recovery from media.

Required:

- Whole-device sanitize / cryptographic erase.
- Or physical destruction.
- File-level deletion is not enough.

## Practical leak minimization

Use these habits:

- Prefer `--password_env` over `--password`.
- Use `--private_names true` when filenames are sensitive.
- Use `--output_dir` on an encrypted volume.
- Avoid opening sensitive files in apps that create temp files or previews.
- Disable or understand cloud sync behavior.
- Be careful with OS search indexing and thumbnail generation.
- Use full-disk encryption wherever possible.
