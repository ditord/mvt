# Normalized Timeline Export

MVT can emit a lightweight, cross-module timeline alongside each module's
regular JSON output.  The timeline is written as
[JSONL](https://jsonlines.org/) (one JSON object per line, UTF-8, sorted by
timestamp) into a file named `{module_slug}_normalized.jsonl` inside the
`--output` directory.

The format is read-only — it does **not** replace or alter any existing module
output.

---

## Supported modules

| Module | Slug | Artifact type | Notes |
|---|---|---|---|
| `FSEvents` | `fsevents` | `fsevent` | |
| `XattrMetadata` | `xattr_metadata` | `xattr` | |
| `CrashReports` | `crash_reports` | `crash_report` | |
| `UnifiedLog` | `unified_log` | `unified_log` | macOS only (prototype) |

---

## Record schema

Every record has the same 13 fields.  Missing values are always `""` (empty
string) or `null` — a field is never omitted.

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | ISO-8601 UTC timestamp; `""` when unavailable |
| `module` | string | MVT module class name, e.g. `"FSEvents"` |
| `artifact_type` | string | Short type tag: `"fsevent"`, `"xattr"`, `"crash_report"` |
| `path` | string | On-device or relative filesystem path most relevant to the record |
| `process` | string | Process or binary name; `""` when not applicable |
| `bundle_id` | string | App bundle identifier; `""` when not applicable |
| `domain` | string | First extracted domain; `""` when none |
| `url` | string | First extracted URL; `""` when none |
| `event_type` | string | Module-specific event sub-type (see below) |
| `description` | string | Human-readable one-line summary |
| `matched_ioc` | string | IOC indicator value if this record triggered a detection; `""` otherwise |
| `source_file` | string | Archive member or log file the record originated from |
| `raw` | object \| null | Full original module result dict |

### `event_type` values per module

- **FSEvents** — comma-separated decoded flag names, e.g. `"Created, IsFile"`;
  `"none"` when no flags are set.
- **XattrMetadata** — the xattr attribute name, e.g.
  `"com.apple.metadata:kMDItemWhereFroms"` or `"com.apple.quarantine"`.
- **CrashReports** — exception string such as `"EXC_CRASH (SIGKILL)"`;
  falls back to `"crash_report"` when no exception is recorded.

---

## Output files

```
<output>/
  fsevents.json                    ← unchanged existing output
  fsevents_normalized.jsonl        ← timeline (new)
  xattr_metadata.json
  xattr_metadata_normalized.jsonl
  crash_reports.json
  crash_reports_normalized.jsonl
```

The JSONL file is only created when there is at least one record to write.

---

## Example record

```json
{"timestamp": "2024-01-15 10:23:41.000000", "module": "FSEvents", "artifact_type": "fsevent", "path": "/private/var/mobile/Containers/Data/Application/ABCD1234/payload", "process": "", "bundle_id": "", "domain": "", "url": "", "event_type": "Created, IsFile", "description": "Created, IsFile (event_id=1099511628032)", "matched_ioc": "", "source_file": ".fseventsd/000000004200e000", "raw": {"timestamp": "2024-01-15 10:23:41.000000", "event_id": 1099511628032, "path": "/private/var/mobile/Containers/Data/Application/ABCD1234/payload", "flags_raw": 65792, "flags_decoded": ["Created", "IsFile"], "source_log_file": ".fseventsd/000000004200e000"}}
{"timestamp": "2024-01-15 10:23:45.000000", "module": "XattrMetadata", "artifact_type": "xattr", "path": "private/var/mobile/Downloads/payload.dmg", "process": "", "bundle_id": "", "domain": "evil.example.org", "url": "https://evil.example.org/payload.dmg", "event_type": "com.apple.metadata:kMDItemWhereFroms", "description": "com.apple.metadata:kMDItemWhereFroms: ['https://evil.example.org/payload.dmg', 'https://evil.example.org/']", "matched_ioc": "evil.example.org", "source_file": "private/var/mobile/Downloads/payload.dmg", "raw": {"file_path": "private/var/mobile/Downloads/payload.dmg", "attribute_name": "com.apple.metadata:kMDItemWhereFroms", "raw_value": "62706c6973...", "decoded_value": ["https://evil.example.org/payload.dmg", "https://evil.example.org/"], "extracted_urls": ["https://evil.example.org/payload.dmg", "https://evil.example.org/"], "extracted_domains": ["evil.example.org"], "isodate": "2024-01-15 10:23:45.000000"}}
{"timestamp": "2024-01-15 10:00:00.000000", "module": "CrashReports", "artifact_type": "crash_report", "path": "/System/Library/CoreServices/SpringBoard.app/SpringBoard", "process": "SpringBoard", "bundle_id": "com.apple.springboard", "domain": "", "url": "", "event_type": "EXC_CRASH (SIGKILL)", "description": "com.apple.springboard | EXC_CRASH (SIGKILL) | watchdog timeout", "matched_ioc": "", "source_file": "DiagnosticLogs/CrashReporter/sb.ips", "raw": {"source_file": "DiagnosticLogs/CrashReporter/sb.ips", "timestamp": "2024-01-15 10:00:00.000000", "process_name": "SpringBoard", "bundle_identifier": "com.apple.springboard", "process_path": "/System/Library/CoreServices/SpringBoard.app/SpringBoard", "os_version": "iPhone OS 17.0 (21A329)", "exception_type": "EXC_CRASH", "exception_signal": "SIGKILL", "termination_reasons": ["watchdog timeout"], "crashed_thread": 0, "extracted_urls": [], "extracted_domains": []}}
```

---

## How investigators use the timeline

### 1. Correlate events across acquisition types

After running both `check-fs` and `check-sysdiagnose` with the same
`--output` directory, combine the JSONL files into a single sorted stream:

```bash
cat output/*_normalized.jsonl \
  | jq -s 'sort_by(.timestamp)[]' \
  > combined_timeline.jsonl
```

### 2. Filter to detections only

```bash
jq 'select(.matched_ioc != "")' output/*_normalized.jsonl
```

### 3. Narrow to a time window

```bash
jq 'select(.timestamp >= "2024-01-15 09:00" and .timestamp <= "2024-01-15 11:00")' \
  output/*_normalized.jsonl
```

### 4. Pivot on a suspicious path

```bash
grep -h '"path"' output/*_normalized.jsonl \
  | jq 'select(.path | contains("ABCD1234"))'
```

### 5. Inspect the original record for any timeline entry

Every timeline record carries the full original module result in `raw`,
so no information is lost when working exclusively with the JSONL output:

```bash
jq '.raw' output/crash_reports_normalized.jsonl | head -40
```

---

## Limitations

- Records without a timestamp sort before all timestamped records
  (empty string sorts before any date string lexicographically).
- FSEvents timestamps are derived from log-file mtime, not per-event kernel
  timestamps; treat them as approximate file-window timestamps.
- The `domain` and `url` fields carry only the **first** extracted value.
  Use `raw.extracted_urls` / `raw.extracted_domains` for the full list.
- Unified Log (`.logarchive` / `tracev3`) is not yet supported; timeline
  coverage is limited to FSEvents, xattr, and crash reports for now.
