# Machine-readable responses

`colemen_encrypt` supports JSON Lines output for wrappers, scripts, and `colemen_py`.

Enable it with:

```bash
colemen_encrypt encrypt \
  --target "./Documents" \
  --machine_responses true \
  --password_env COLEMEN_ENCRYPT_PASSWORD
```

JSON Lines means each line is a complete JSON object.

This is better than one giant JSON document for long-running operations because callers can process progress incrementally.

## Event types

The current event stream has three broad categories:

```text
start
file_success / file_warning / file_error
summary
```

## Start event

Example:

```json
{"type":"start","mode":"encrypt","dry_run":false,"thread_count":4,"item_count":10}
```

Fields:

| Field | Type | Meaning |
|---|---:|---|
| `type` | string | Always `start`. |
| `mode` | string | `encrypt` or `decrypt`. |
| `dry_run` | bool | Whether writes/deletes are disabled. |
| `thread_count` | number | Worker thread count. |
| `item_count` | number | Number of discovered work items. |

## File success event

Example:

```json
{"type":"file_success","mode":"encrypt","source":"/data/a.txt","destination":"/data/a.txt.enc","status":"success","bytes_read":123,"bytes_written":456,"duration_ms":12,"original_deleted":true,"deletion_strategy":"unlink","deletion_assurance":"best_effort_file_level","warnings":[],"error":null}
```

Fields:

| Field | Type | Meaning |
|---|---:|---|
| `type` | string | Usually `file_success`. |
| `mode` | string | `encrypt` or `decrypt`. |
| `source` | string | Source path. |
| `destination` | string/null | Output path, if known. |
| `status` | string | `success`, `skipped`, or `failed`. |
| `bytes_read` | number | Bytes read from source or encrypted source. |
| `bytes_written` | number | Bytes written to output. |
| `duration_ms` | number | Per-file elapsed time. |
| `original_deleted` | bool | Whether source removal was reported successful. |
| `deletion_strategy` | string | `unlink`, `best_effort_overwrite`, or `none`. |
| `deletion_assurance` | string | Usually `best_effort_file_level` or `none`. |
| `warnings` | array | Non-fatal warnings. |
| `error` | string/null | Error message if failed. |

## File warning event

Example:

```json
{"type":"file_warning","mode":"encrypt","source":"/data/missing.txt","destination":null,"status":"skipped","bytes_read":0,"bytes_written":0,"duration_ms":0,"original_deleted":false,"deletion_strategy":"none","deletion_assurance":"none","warnings":["source path does not exist; skipped"],"error":null}
```

Warnings are not necessarily process failures. Missing target-list entries are warnings/skips so the rest of the batch can continue.

## File error event

Example:

```json
{"type":"file_error","mode":"decrypt","source":"/data/a.txt.enc","destination":"/data/a.txt","status":"failed","bytes_read":0,"bytes_written":0,"duration_ms":44,"original_deleted":false,"deletion_strategy":"none","deletion_assurance":"none","warnings":[],"error":"authentication failed"}
```

Errors indicate that the file operation failed.

Wrappers should assume:

```text
status == failed -> do not trust destination
```

## Summary event

Example:

```json
{"type":"summary","mode":"encrypt","files_total":10,"files_success":9,"files_failed":0,"files_skipped":1,"warnings":1,"duration_ms":500}
```

Fields:

| Field | Type | Meaning |
|---|---:|---|
| `type` | string | Always `summary`. |
| `mode` | string | `encrypt` or `decrypt`. |
| `files_total` | number | Total reports included. |
| `files_success` | number | Successful files. |
| `files_failed` | number | Failed files. |
| `files_skipped` | number | Skipped files. |
| `warnings` | number | Total warnings. |
| `duration_ms` | number | Whole-run elapsed time. |

## Recommended parser behavior

A wrapper should parse line-by-line:

1. Read stdout line.
2. Trim whitespace.
3. Skip empty lines.
4. Parse JSON.
5. Dispatch based on `type`.
6. Keep a list of `file_error` and `file_warning` events.
7. Use the final `summary` and process exit code to decide success.

## Exit code handling

Expected exit codes:

```text
0 = completed without file failures
1 = completed with one or more file failures
2 = invalid arguments or fatal setup error
5 = unexpected internal error
```

Recommended wrapper rule:

```python
if exit_code == 0 and summary["files_failed"] == 0:
    overall_success = True
else:
    overall_success = False
```

Do not rely only on stdout text in human-readable mode. Use `--machine_responses true` for automation.

## Python parsing example

```python
import json
import subprocess
from pathlib import Path

cmd = [
    "colemen_encrypt",
    "encrypt",
    "--target", str(Path("./docs")),
    "--password_env", "COLEMEN_ENCRYPT_PASSWORD",
    "--machine_responses", "true",
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

events = []
for line in proc.stdout:
    line = line.strip()
    if not line:
        continue
    event = json.loads(line)
    events.append(event)
    if event.get("type") == "file_error":
        print("FAILED:", event.get("source"), event.get("error"))

stderr = proc.stderr.read()
exit_code = proc.wait()

summary = next((e for e in reversed(events) if e.get("type") == "summary"), None)

if exit_code != 0:
    raise RuntimeError(f"colemen_encrypt failed with exit code {exit_code}: {stderr}")

if summary and summary.get("files_failed", 0) > 0:
    raise RuntimeError(f"file failures: {summary}")
```

## Stability notes for wrappers

A stable integration should:

- Always use `--machine_responses true`.
- Prefer `--password_env` over `--password`.
- Capture stderr separately.
- Treat invalid JSON as a fatal integration error.
- Treat `file_error` as file-level failure.
- Treat `file_warning` as non-fatal unless policy says otherwise.
- Preserve the final summary with logs.
- Never parse human-readable output for automation.

## Suggested `colemen_py` result model

A useful Python result object could contain:

```python
@dataclass
class ColemenEncryptResult:
    exit_code: int
    mode: str
    success: bool
    summary: dict | None
    events: list[dict]
    warnings: list[dict]
    errors: list[dict]
    stderr: str
```

And a file-level result:

```python
@dataclass
class ColemenEncryptFileResult:
    source: Path
    destination: Path | None
    status: str
    bytes_read: int
    bytes_written: int
    duration_ms: int
    original_deleted: bool
    deletion_strategy: str
    deletion_assurance: str
    warnings: list[str]
    error: str | None
```
