# Case Summary Report Generator

The `generate-report` command reads an MVT iOS output directory (produced by
`check-backup`, `check-fs`, or `check-sysdiagnose`) and writes a concise
case summary without re-running any analysis.

---

## Usage

```bash
mvt-ios generate-report [OPTIONS] INPUT_DIR
```

### Arguments

| Argument | Description |
|---|---|
| `INPUT_DIR` | Path to a folder containing existing MVT JSON output |

### Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--output-dir PATH` | `-o` | `INPUT_DIR` | Folder for the generated report files |
| `--case-id TEXT` | `-c` | `""` | Case identifier string (free text) |
| `--analyst TEXT` | `-a` | `""` | Analyst name (free text) |
| `--format [json\|md\|both]` | `-F` | `json` | Output format |

### Examples

```bash
# JSON summary written to the same folder that was analyzed
mvt-ios generate-report /path/to/mvt_output/

# Markdown report in a separate directory
mvt-ios generate-report --format md --output-dir /path/to/reports/ /path/to/mvt_output/

# Both formats with metadata
mvt-ios generate-report \
    --format both \
    --case-id "CASE-2024-001" \
    --analyst "Alice Smith" \
    --output-dir /cases/CASE-2024-001/report/ \
    /cases/CASE-2024-001/mvt_output/
```

---

## Output files

```
<output-dir>/
  case_summary.json    ← machine-readable summary (json or both)
  case_summary.md      ← human-readable report    (md or both)
```

---

## `case_summary.json` schema

```json
{
  "mvt_version": "2026.4.28",
  "generated_at": "2024-01-16T09:00:00+00:00",
  "case_id": "CASE-2024-001",
  "analyst": "Alice Smith",
  "input_dir": "/cases/CASE-2024-001/mvt_output",
  "verdict": "HIGH",
  "alert_counts": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 1,
    "INFORMATIONAL": 0,
    "total": 2
  },
  "alerts": [ ... ],
  "correlation_findings": [ ... ],
  "ioc_matches": [
    {
      "value": "evil.example.org",
      "type": "domain",
      "name": "APT-X C2",
      "module": "crash_reports",
      "alert_level": "HIGH"
    }
  ],
  "module_artifact_counts": {
    "crash_reports": 3,
    "fsevents": 15042
  },
  "timeline_record_counts": {
    "crash_reports": 3,
    "fsevents": 15042
  }
}
```

### `verdict` values

| Value | Meaning |
|---|---|
| `CRITICAL` | At least one CRITICAL-level alert |
| `HIGH` | At least one HIGH-level alert (no CRITICAL) |
| `MEDIUM` | At least one MEDIUM-level alert (no higher) |
| `LOW` | At least one LOW-level alert (no higher) |
| `INFORMATIONAL` | Only INFORMATIONAL alerts |
| `CLEAN` | No alerts found in `alerts.json` |
| `UNKNOWN` | Alerts present but all levels unrecognised |

The verdict reflects the highest alert level seen.  **A `CLEAN` verdict does
not rule out compromise** — it means no detections were recorded by the
modules that ran, which may reflect limited IOC coverage, log rotation, or
collection timing.

---

## What is read

| File | Used for |
|---|---|
| `alerts.json` | Alert counts, verdict, IOC matches |
| `correlation.json` | Correlation findings section |
| `*.json` (module results) | Per-module artifact record counts |
| `*_normalized.jsonl` | Per-module timeline record counts |

Files named `alerts.json`, `correlation.json`, `case_summary.json`, and
`info.json` are excluded from the module artifact counts table.

---

## Limitations

- The report is a read-only summary.  It does **not** re-run any module or
  IOC check.
- The `verdict` is derived solely from alerts already written to
  `alerts.json`.  If no IOC file was provided during the original analysis,
  `verdict` will be `CLEAN` regardless of what was found.
- Only the **first** IOC match per unique indicator value appears in
  `ioc_matches`; duplicates across modules are de-duplicated by value.
- `module_artifact_counts` counts top-level array items in each `*.json`
  file; for modules that write a dict instead of an array the count is 0.
