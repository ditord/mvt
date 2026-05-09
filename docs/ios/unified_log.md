# Unified Log Module (Prototype)

> **This is prototype support.**  Coverage is limited, the macOS `log` binary
> is required, and absence of findings does **not** rule out compromise.

---

## Overview

The `UnifiedLog` sysdiagnose module extracts forensic events from Apple
Unified Log archives (`.logarchive` bundles) found inside a sysdiagnose
archive or extracted sysdiagnose directory.

On **macOS**, the system `log` binary reads the binary `.tracev3` log
files inside the archive and streams events as JSON.  MVT parses that
stream, extracts network indicators and file paths from log messages,
and checks them against any loaded IOC lists.

On **non-macOS** platforms (Linux, Windows) the module logs an informational
message and exits without error — it produces no results and does not attempt
to parse the binary log format directly.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| macOS host | The `log` binary is a macOS system tool |
| `log` on PATH | Standard location: `/usr/bin/log` |
| `.logarchive` in sysdiagnose | Typically `system_logs.logarchive` |

---

## How it works

1. **Discovery** — MVT walks the sysdiagnose directory (or scans the tar
   member list) looking for directories ending in `.logarchive`.

2. **Extraction (tar mode)** — If the sysdiagnose is a `.tar.gz`, the
   `.logarchive` bundle is extracted to a temporary directory before
   processing, then cleaned up automatically.

3. **Invocation** — For each bundle, MVT runs:

   ```
   log show --style json --archive <path> --info --debug
   ```

   No `shell=True` is used.  The subprocess is killed if it exceeds the
   configured timeout (default: 120 seconds).

4. **Streaming parse** — The JSON array output is parsed incrementally
   using `json.JSONDecoder.raw_decode()` so the full output is never loaded
   into memory at once.  Processing stops after `max_events` events
   (default: 5 000).

5. **Field extraction** — For each event, MVT extracts:

   | Field | Source |
   |---|---|
   | `timestamp` | `log show` event timestamp (normalised to UTC) |
   | `process` | Basename of `processImagePath` |
   | `process_path` | `processImagePath` |
   | `subsystem` | `subsystem` |
   | `category` | `category` |
   | `event_message` | `eventMessage` |
   | `event_type` | `eventType` |
   | `sender` | `senderImagePath` |
   | `extracted_urls` | URLs matched by regex in `eventMessage` |
   | `extracted_domains` | Domains extracted from `extracted_urls` |
   | `extracted_ips` | IPv4 addresses matched in `eventMessage` |
   | `extracted_paths` | `/var/`, `/tmp/`, etc. paths in `eventMessage` |
   | `source_logarchive` | Name of the `.logarchive` bundle |

6. **IOC checks** — `check_indicators()` tests each result against:
   - Process name → `check_process()`
   - Process binary path → `check_file_path()`
   - Extracted URLs → `check_url()`

7. **Normalized timeline** — Each result is emitted to
   `unified_log_normalized.jsonl` (when `--output` is provided) using the
   standard 13-field schema.

---

## Output

```
<output>/
  unified_log.json                  ← full results (serialised)
  unified_log_normalized.jsonl      ← normalized timeline (new)
  correlation.json                  ← updated with unified_log entries
```

### Example result record

```json
{
  "source_logarchive": "system_logs.logarchive",
  "timestamp": "2024-01-15 18:23:41.000000+0000",
  "process": "networkd",
  "process_path": "/usr/libexec/networkd",
  "subsystem": "com.apple.network",
  "category": "connection",
  "event_message": "TLS handshake to evil.example.org failed",
  "event_type": "logEvent",
  "sender": "/usr/lib/libnetwork.dylib",
  "extracted_urls": [],
  "extracted_domains": ["evil.example.org"],
  "extracted_ips": [],
  "extracted_paths": []
}
```

---

## Configuration

The following attributes can be adjusted on the module instance before
calling `run()`:

| Attribute | Default | Description |
|---|---|---|
| `max_events` | `5000` | Maximum events to ingest per archive |
| `timeout` | `120` | Seconds before `log show` is forcibly killed |

Increase `max_events` for higher coverage; be aware that very large archives
can produce millions of events.

---

## Limitations

- **macOS only.** The module produces no output on Linux or Windows.  A
  cross-platform tracev3 parser would be required for non-macOS coverage.
- **Event cap.** Only the first `max_events` events per archive are
  processed.  If the limit is reached a warning is logged.
- **No time-range filter** is applied by default; on large archives the
  timeout or event cap may cut off coverage.
- **IP IOC matching** is not yet implemented.  IPv4 addresses are extracted
  from messages and stored in `extracted_ips` but not checked against
  IOC collections.
- **Only `eventMessage` is scanned** for network indicators and paths.
  Indicators embedded in structured log fields, backtraces, or binary
  metadata are not extracted.
- **Absence of findings does not rule out compromise.**  The Unified Log is
  very high-volume.  Spyware may leave no obvious log messages, or relevant
  entries may have been rotated out before the sysdiagnose was captured.

---

## What would be needed for cross-platform tracev3 parsing

A non-macOS implementation would require:

1. A pure-Python (or Rust/C extension) `.tracev3` parser that handles the
   compressed chunk format, UUID map files, and deferred format-string
   resolution from the shared cache / DSC.
2. Handling of the `timesync` directory for accurate timestamp anchoring.
3. Reconstruction of log message strings from the binary format strings
   stored in the sender images (requires access to the original device
   dyld shared cache or symbol tables).

The closest available libraries at time of writing are
[`libimobiledevice`](https://libimobiledevice.org/) (C) and the
[`aul`](https://github.com/mandiant/aul) Rust crate (Mandiant).  Neither
has a stable, maintained Python binding suitable for direct inclusion.
