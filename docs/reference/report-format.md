# Report format

A scan produces two kinds of output:

- `.security_reports/` contains each scanner's raw JSON, unmodified except for
  pretty-printing.
- `security_audit.json` contains the merged report described here.

## Input files

The aggregator looks for these exact filenames in the report directory. Missing
files are skipped without error, which is how disabled tools are handled.

| Tool | Filename |
| --- | --- |
| Trivy | `trivy.json` |
| Semgrep | `semgrep.json` |
| Gitleaks | `gitleaks.json` |
| ZAP | `zap.json` |

ZAP also writes `zap.html`, which is not read by the aggregator.

## Schema

```json
{
  "summary": {
    "total_issues": 4,
    "tools_run": ["Trivy", "Semgrep", "Gitleaks", "ZAP"]
  },
  "findings": [
    {
      "tool": "Gitleaks",
      "severity": "CRITICAL",
      "file": ".env",
      "description": "Secret detected: generic-api-key",
      "line": 3,
      "snippet": "REDACTED"
    }
  ]
}
```

### `summary`

| Field | Type | Meaning |
| --- | --- | --- |
| `total_issues` | integer | Number of entries in `findings`. |
| `tools_run` | array of strings | Tools whose report file was present and parsable. |

`tools_run` reflects which reports were *found*, not which tools were enabled. A
tool that was enabled but crashed before writing its report will be absent.

### `findings`

Sorted by severity, most severe first. Within a severity, order follows the
tool order above.

Always present:

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | `Trivy`, `Semgrep`, `Gitleaks`, or `ZAP`. |
| `severity` | string | Normalised severity. See below. |
| `file` | string | File path, or for ZAP the affected URL. `Unknown` when the source report omits it. |
| `description` | string | Human-readable summary. |

Present only when the source tool provides them:

| Field | Type | Set by | Meaning |
| --- | --- | --- | --- |
| `line` | integer | Semgrep, Gitleaks | Line number of the finding. |
| `fix` | string | Trivy | Fixed package version, or `No fix available`. |
| `rule_id` | string | Semgrep | The rule that matched. |
| `snippet` | string | Gitleaks | Always the literal `REDACTED`. |
| `solution` | string | ZAP | Remediation advice from the alert. |

Gitleaks findings never include the matched secret. The `snippet` field is
hardcoded to `REDACTED`, so the report is safe to upload as a CI artifact.

## Severity normalisation

Each scanner uses its own severity vocabulary. The aggregator maps them onto one
scale: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `UNKNOWN`.

Values are upper-cased before lookup. Anything unrecognised, empty, or missing
becomes `UNKNOWN`.

| Source value | Becomes |
| --- | --- |
| `CRIT`, `CRITICAL` | `CRITICAL` |
| `ERROR`, `HIGH` | `HIGH` |
| `WARN`, `WARNING`, `MEDIUM` | `MEDIUM` |
| `LOW` | `LOW` |
| `INFO`, `INFORMATION`, `INFORMATIONAL` | `INFO` |

Two per-tool rules are worth knowing:

- **Semgrep** reports `ERROR` and `WARNING`. These become `HIGH` and `MEDIUM`,
  respectively. A Semgrep `ERROR` finding will fail your build.
- **Gitleaks** findings are always assigned `CRITICAL`, regardless of what the
  rule was. Any detected secret fails the build.

**ZAP** does not use severity names. It reports a numeric `riskcode`:

| `riskcode` | Becomes |
| --- | --- |
| `3` | `HIGH` |
| `2` | `MEDIUM` |
| `1` | `LOW` |
| `0` | `INFO` |

Any other value becomes `UNKNOWN`. Because ZAP tops out at `HIGH`, a DAST
finding can fail a build but will never appear as `CRITICAL`.

## Terminal summary

The table printed at the end of a run groups findings by tool category rather
than by tool name:

| Category | Tool |
| --- | --- |
| `Secrets` | Gitleaks |
| `Code` | Semgrep |
| `Deps` | Trivy |
| `ZAP` | ZAP |

The breakdown column is populated for Critical and High only. Medium shows a
count with no breakdown. Low, Info, and Unknown appear in
`security_audit.json`, but not in the table.
