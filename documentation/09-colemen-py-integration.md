# colemen_py integration guide

This guide describes how `colemen_py` should wrap `colemen_encrypt` safely.

The key rule:

```text
Use --machine_responses true and parse JSON Lines. Do not parse human logs.
```

## Recommended subprocess pattern

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os
import subprocess
from typing import Any


@dataclass
class ColemenEncryptRunResult:
    exit_code: int
    success: bool
    summary: dict[str, Any] | None
    events: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    stderr: str


def run_colemen_encrypt(
    binary: str | Path,
    mode: str,
    *,
    target: str | Path | None = None,
    target_list: str | Path | None = None,
    password: str,
    output_dir: str | Path | None = None,
    keep_original: bool = False,
    recursive: bool = True,
    thread_count: int = 4,
    verify: str = "full",
    collision: str = "skip",
    delete_strategy: str = "unlink",
) -> ColemenEncryptRunResult:
    if (target is None) == (target_list is None):
        raise ValueError("provide exactly one of target or target_list")

    env = os.environ.copy()
    env["COLEMEN_ENCRYPT_PASSWORD"] = password

    cmd = [
        str(binary),
        mode,
        "--password_env", "COLEMEN_ENCRYPT_PASSWORD",
        "--machine_responses", "true",
        "--keep_original", str(keep_original).lower(),
        "--recursive", str(recursive).lower(),
        "--thread_count", str(thread_count),
        "--verify", verify,
        "--collision", collision,
        "--delete_strategy", delete_strategy,
    ]

    if target is not None:
        cmd.extend(["--target", str(target)])
    else:
        cmd.extend(["--target_list", str(target_list)])

    if output_dir is not None:
        cmd.extend(["--output_dir", str(output_dir)])

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    events: list[dict[str, Any]] = []

    assert proc.stdout is not None
    for raw_line in proc.stdout:
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            proc.kill()
            raise RuntimeError(f"Invalid JSON from colemen_encrypt: {line!r}") from exc
        events.append(event)

    stderr = proc.stderr.read() if proc.stderr else ""
    exit_code = proc.wait()

    warnings = [e for e in events if e.get("type") == "file_warning" or e.get("warnings")]
    errors = [e for e in events if e.get("type") == "file_error" or e.get("status") == "failed"]
    summary = next((e for e in reversed(events) if e.get("type") == "summary"), None)

    success = exit_code == 0 and not errors and (summary is None or summary.get("files_failed", 0) == 0)

    return ColemenEncryptRunResult(
        exit_code=exit_code,
        success=success,
        summary=summary,
        events=events,
        warnings=warnings,
        errors=errors,
        stderr=stderr,
    )
```

## Password handling

Prefer environment variables over command-line passwords.

Good:

```text
--password_env COLEMEN_ENCRYPT_PASSWORD
```

Avoid where possible:

```text
--password mySecretPassword
```

Reason: command-line arguments may appear in shell history, logs, process listings, crash reports, and debug tools.

## Wrapper-level validation

Before launching the binary, `colemen_py` should validate:

- Exactly one of `target` or `target_list` is set.
- The binary exists.
- The password is non-empty.
- `mode` is `encrypt` or `decrypt`.
- `verify` is one of `full`, `hash`, `auth`, `none`.
- `collision` is one of `skip`, `rename`, `overwrite`.
- `delete_strategy` is one of `unlink`, `best_effort_overwrite`, `none`.
- `thread_count > 0`.

Let the Rust binary remain the source of truth, but fail early in Python for obvious wrapper mistakes.

## Suggested API shape

```python
def encrypt_file(
    path: str | Path,
    password: str,
    *,
    output_dir: str | Path | None = None,
    keep_original: bool = False,
    verify: str = "full",
    collision: str = "skip",
) -> ColemenEncryptRunResult:
    ...


def decrypt_file(
    path: str | Path,
    password: str,
    *,
    output_dir: str | Path | None = None,
    keep_original: bool = False,
    verify: str = "full",
    collision: str = "skip",
) -> ColemenEncryptRunResult:
    ...


def encrypt_directory(
    path: str | Path,
    password: str,
    *,
    output_dir: str | Path | None = None,
    recursive: bool = True,
    keep_relative_path: bool = True,
    thread_count: int = 4,
) -> ColemenEncryptRunResult:
    ...
```

## Monitoring long runs

Because JSON Lines stream progressively, `colemen_py` can update progress as events arrive.

Example policy:

```python
for event in stream_events(proc):
    if event["type"] == "start":
        progress.total = event["item_count"]
    elif event["type"] in {"file_success", "file_warning", "file_error"}:
        progress.completed += 1
        progress.update_current(event["source"], event["status"])
    elif event["type"] == "summary":
        progress.finish(event)
```

## Trust boundary

`colemen_py` should trust the Rust binary to perform encryption/decryption, but should not blindly hide warnings.

Surface these clearly:

- File skipped because destination exists.
- Source missing.
- Auth/decrypt failure.
- Verification failure.
- Original deletion failure.
- SSD best-effort deletion note.

## Recommended wrapper defaults

```python
DEFAULTS = {
    "verify": "full",
    "collision": "skip",
    "delete_strategy": "unlink",
    "keep_original": False,
    "recursive": True,
    "preserve_metadata": True,
    "machine_responses": True,
}
```

Do not make Python defaults more dangerous than the binary defaults.

## Handling partial success

A batch can complete with:

```text
exit_code = 1
files_success > 0
files_failed > 0
```

This is partial success.

Do not treat it as total failure in a way that discards useful information. Preserve all event records.

Suggested result categories:

```python
if exit_code == 0:
    status = "success"
elif summary and summary.get("files_success", 0) > 0:
    status = "partial_success"
else:
    status = "failed"
```

## Avoid shell=True

Use list arguments:

```python
subprocess.Popen(["colemen_encrypt", "encrypt", "--target", str(path), ...])
```

Avoid:

```python
subprocess.Popen("colemen_encrypt encrypt --target ...", shell=True)
```

This prevents quoting bugs and injection issues.

## Binary discovery

Suggested lookup order:

1. User-provided binary path.
2. Bundled binary inside `colemen_py/vendor/bin`.
3. PATH lookup.
4. Clear error with installation instructions.

## Version checking

The wrapper should eventually support:

```bash
colemen_encrypt --version
```

Then compare against a minimum supported version.

## Test matrix for integration

At minimum, `colemen_py` should test:

- Encrypt one file.
- Decrypt one file.
- Wrong password fails.
- Collision skip.
- Collision rename.
- Keep original true.
- Keep original false.
- Target list with missing path.
- Directory recursive.
- Machine responses parse correctly.
- Dry run makes no changes.
