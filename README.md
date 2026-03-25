# Veracode Findings API Export

Export vulnerability findings from Veracode across all scan types (SAST, DAST, SCA, Manual, IaC) into a single CSV file. Handles paginated API calls, concurrent processing, rate limiting, and normalisation across scan types with audit-quality output.

---

## How It Works

`script.py` connects to the Veracode REST APIs and:

1. Fetches all application profiles (paginated, supports 1000s of apps)
2. Retrieves SCA workspace/project mappings and Dynamic Analysis metadata
3. Processes applications concurrently - each worker thread fetches policy scan findings, SCA findings (separate API), and optionally sandbox findings
4. Enriches findings with deep links, team names, and scan metadata
5. Optionally merges IaC (Container Security) findings from a pre-fetched JSON file-
6. Writes a normalised CSV and a timestamped raw JSON file

IaC scans use a browser session cookie API that is not available via standard HMAC auth. `fetch_iac_details.py` handles this separately, fetch first, then pass the JSON to `script.py` via `--iac-json`.

All operations are safe to re-run. Filtering, pagination, and output are deterministic.

---

## Quickstart

### Export all findings

```bash
python script.py
```

Writes `veracode_findings_api.csv` and `veracode_findings_api_raw_<timestamp>.json` to the current directory.

### Filter by application and severity

```bash
python script.py --app-name "App1,App2" --severity-gte 4 --status OPEN --output high-severity.csv
```

### Include sandbox findings

```bash
python script.py --include-sandbox --app-name "MyApp"
```

### Behind an SSL inspection device

```bash
python script.py --ca-cert /path/to/corp-ca.pem
```

### With IaC scans

```bash
# 1. Fetch IaC data (requires browser cookies)
python fetch_iac_details.py --cookies-file cookies.txt --output iac-findings.json

# 2. Export all findings including IaC
python script.py --iac-json iac-findings.json --output complete-findings.csv
```

### Test connectivity

```bash
python script.py --max-apps 5 --output test.csv
```

---

## Requirements

```bash
pip install requests veracode-api-signing
```

Python 3.9+

---

## Credentials

### API Credentials (script.py)

Requires one of:
- **API Service Account** with **Results API** role (recommended for org-wide access)
- **User Account** with **Reviewer** or **Security Lead** role (limited to assigned teams)

```ini
# Windows: C:\Users\<username>\.veracode\credentials
# Mac/Linux: ~/.veracode/credentials

[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

### Browser Cookies (fetch_iac_details.py)

IaC scans require browser session cookies (not available via standard API):

1. Log into Veracode Platform (https://analysiscenter.veracode.com)
2. Press F12 → Network tab → Refresh page
3. Click any request → Headers → Copy `Cookie:` value
4. Save to `cookies.txt`

Cookies expire after a few hours. The script validates the cookie string is not empty and exits with a non-zero code on authentication failure.

---

## Command-Line Reference

### script.py

#### Filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--app-name` | - | Comma-separated application names (exact match) |
| `--app-guid` | - | Specific application GUID |
| `--scan-type` | - | STATIC, DYNAMIC, MANUAL, SCA (comma-separated) |
| `--severity` | - | Exact severity, 0–5 (validated) |
| `--severity-gte` | - | Minimum severity, 0–5 (validated) |
| `--cwe` | - | CWE ID (single or comma-separated) |
| `--status` | - | `OPEN` or `CLOSED` (validated) |
| `--include-sandbox` | `False` | Include findings from development sandboxes |

#### Output

| Flag | Default | Description |
|------|---------|-------------|
| `--output` | `veracode_findings_api.csv` | Output CSV filename |
| `--iac-json` | - | Path to IaC detailed-findings JSON (from `fetch_iac_details.py`) |

#### Performance

| Flag | Default | Description |
|------|---------|-------------|
| `--max-workers` | `10` | Concurrent threads for parallel processing |
| `--rate-limit` | `10.0` | Max API requests/second (token bucket) |
| `--sleep` | `0.01` | Sleep between API pages within a single request (seconds) |
| `--max-apps` | - | Limit apps processed (for testing) |

#### SSL / Network

| Flag | Default | Description |
|------|---------|-------------|
| `--ca-cert` | - | Path to custom CA certificate bundle (.pem). Validated at startup, produces a clear error if the file doesn't exist. Required behind SSL inspection devices (e.g. Zscaler). |

### fetch_iac_details.py

| Flag | Default | Description |
|------|---------|-------------|
| `--output` | `iac-findings.json` | Output file for detailed findings |
| `--cookies` | - | Browser session cookies (string) |
| `--cookies-file` | - | File containing browser session cookies (recommended) |
| `--scan-limit` | `5000` | Max scans to fetch |
| `--findings-limit` | `1000` | Max findings per scan |
| `--max-workers` | `5` | Concurrent threads |
| `--rate-limit` | `10.0` | Max requests/second |
| `--filter-apps` | - | Comma-separated app names to process |

---

## IaC (Container Security) Integration

IaC scans require browser session cookies and a two-step workflow:

```bash
# Step 1: Fetch detailed IaC findings
python fetch_iac_details.py --cookies-file cookies.txt --output iac-findings.json --filter-apps "App1,App2"

# Step 2: Include in main export
python script.py --app-name "App1,App2" --iac-json iac-findings.json
```

The script validates the JSON contains detailed findings (not just summary counts). IaC asset names are matched to Veracode applications using case-insensitive lookup. Unmatched assets are included with a placeholder profile and a warning.

---

## SSL Inspection (Corporate Proxy)

Pass your corporate CA certificate via `--ca-cert`. The file path is validated at startup - if the file doesn't exist, you get a clear `FileNotFoundError` with conversion instructions instead of a cryptic SSL error later.

If it's DER-encoded (`.cer`), convert first:

```bash
openssl x509 -inform DER -in corp-ca.cer -out corp-ca.pem
python script.py --ca-cert /path/to/corp-ca.pem
```

---

## Performance Tuning

The script processes applications concurrently using a thread pool. All API calls are I/O-bound, so threading provides real throughput gains.

| Apps | `--max-workers` | `--rate-limit` |
|------|-----------------|----------------|
| < 50 | `10` (default) | `10` (default) |
| 100+ | `20` | `20` |
| 500+ | `30` | `30` |

The rate limiter uses a token bucket algorithm. Key design choices:

- **Sleeps outside the lock** - sleeping threads don't block others from acquiring tokens
- **Uses `time.monotonic()`** - immune to NTP adjustments and wall-clock jumps
- All worker threads share a single rate limiter instance

---

## Output Files

The script generates two files per run:

| File | Description |
|------|-------------|
| `veracode_findings_api.csv` | Normalised findings, one row per finding across all scan types. Customizable via `--output`. |
| `veracode_findings_api_raw_<timestamp>.json` | Raw API response data. Timestamped to avoid overwrites. Contains complete nested structures for debugging or advanced analysis. |

### CSV Columns

#### Standard Columns (All Scan Types)

| Column | Description |
|--------|-------------|
| Application Name | Application name from Veracode profile |
| Application ID | Application GUID |
| Sandbox Name | Sandbox name (blank for policy scans and IaC) |
| Custom Severity Name | Very High / High / Medium / Low / Very Low / Informational |
| CVE ID | CVE identifier (SCA/IaC only). **IaC**: Finding ID if vulnerability type |
| Description | Full finding description (HTML stripped). **IaC**: Title + description + finding ID |
| Vulnerability Title | Finding title. **IaC**: Finding type (e.g., "Vulnerability", "Misconfiguration") |
| CWE ID | CWE numeric ID. **IaC**: Rule/Policy ID (e.g., "CIS-DI-0001") |
| Flaw Name | CWE name, finding category, or title. **IaC**: Finding ID or title |
| First Found Date | ISO 8601 date. **IaC**: Scan date |
| Filename/Class | File path (STATIC), URL (DYNAMIC), component (SCA). **IaC**: File path with line numbers |
| Finding Status | OPEN or CLOSED. **IaC**: Always OPEN |
| Fixed Date | Resolution date (ISO 8601). **IaC**: Always blank |
| Team Name | Business unit or first team from application profile |
| Days to Resolve | Days between first found and fixed. **IaC**: Always blank |
| Scan Type | STATIC, Dynamic Analysis, DAST, MANUAL, SCA, SCA Agent, or **IAC** |
| CVSS | CVSS score (prefers v3 for SCA). **IaC**: From finding if available |
| Severity | Numeric: 5=Very High … 0=Informational. **IaC**: Mapped from critical/high/medium/low/negligible/unknown |
| Resolution Status | Resolution status from platform. **IaC**: Always blank |
| Resolution | Resolution type (e.g., APPROVED, FALSE POSITIVE). **IaC**: Always blank |
| Mitigation Comments | Annotation comments. **IaC**: Suggested fix text |
| Veracode Link | Deep link to finding in Veracode Platform. **IaC**: Link to Container Security scan |

#### IaC-Specific Columns

| Column | Description |
|--------|-------------|
| IAC File Path | Full file path in repository |
| IAC Start Line | Starting line number |
| IAC End Line | Ending line number |

IaC-specific columns are blank for non-IaC findings. Standard columns may be blank for IaC findings where not applicable.

### Severity Mapping

| Numeric | Label |
|---------|-------|
| 5 | Very High |
| 4 | High |
| 3 | Medium |
| 2 | Low |
| 1 | Very Low |
| 0 | Informational |

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| 401/403 | Check credentials file and API role (Results API for service accounts) |
| 0 apps returned | Service accounts see all apps; user accounts only see assigned teams |
| `SSLError: certificate verify failed` | Use `--ca-cert /path/to/corp-ca.pem`, see [SSL Inspection](#ssl-inspection-corporate-proxy) |
| `FileNotFoundError: CA certificate` | The `--ca-cert` path doesn't exist; check the file path |
| `handshake_failure` | Veracode requires TLS 1.2+; check your proxy supports it |
| 429 Too Many Requests | Lower `--rate-limit` and `--max-workers` |
| 404 on application | No scans yet, insufficient permissions, or app archived, script skips and continues |
| Missing CSV fields | Expected, some fields are scan-type specific (e.g. CVE ID is SCA/IaC only) |
| `--severity 9` rejected | Severity is validated to 0–5; use a valid value |
| `--status MAYBE` rejected | Status only accepts `OPEN` or `CLOSED` |
| IaC cookies expired | Re-export cookies from browser dev tools (expire after ~2-4 hours) |
| IaC empty cookie error | Ensure `cookies.txt` is not empty; the script validates this at startup |
| IaC asset not matched | Asset name in JSON doesn't match app name in Veracode exactly |
| IaC wrong format error | Run `fetch_iac_details.py` first - the JSON must contain detailed findings |

---

## Common Use Cases

**Specific applications with all scan types including IaC:**
```bash
python fetch_iac_details.py --cookies-file cookies.txt --output iac-findings.json --filter-apps "App1,App2"
python script.py --app-name "App1,App2" --iac-json iac-findings.json --include-sandbox
```

**High severity open findings only:**
```bash
python script.py --severity-gte 4 --status OPEN --output high-severity.csv
```

**Behind SSL inspection with filters:**
```bash
python script.py --ca-cert /path/to/corp-ca.pem --severity-gte 3 --status OPEN --output findings.csv
```

**Full export with maximum throughput:**
```bash
python script.py --max-workers 30 --rate-limit 30
```

---

## Execution Flow

1. **Initialization** - validates credentials, creates HTTP sessions with connection pooling, validates `--ca-cert` path (if provided), initializes thread-safe rate limiter
2. **Data collection** - single shared session fetches SCA workspace mappings, Dynamic Analysis metadata, and the application list; session is closed after this phase
3. **Concurrent processing** - each worker thread gets its own session (closed in `finally`), parses scan URLs in a single pass, fetches findings, enriches with metadata
4. **IaC integration** - loads JSON, matches assets to apps via O(1) case-insensitive lookup, normalises to common schema
5. **Output** - writes timestamped raw JSON, normalises all findings (HTML stripped via pre-compiled regexes), writes CSV with `extrasaction="ignore"` for safe mixed-schema output

---

## API References

- [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro)
- [Applications REST API](https://docs.veracode.com/r/c_apps_intro)
- [API Authentication](https://docs.veracode.com/r/t_install_api_authen)
- [Configure SSL Certificates](https://docs.veracode.com/r/c_using_certificates)

---

**Note:** This is a community tool and is not officially supported by Veracode.
