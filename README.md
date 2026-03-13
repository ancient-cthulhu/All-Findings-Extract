# Veracode Findings API Export

Export vulnerability findings from Veracode across all scan types (SAST, DAST, SCA, Manual, IaC) into a single CSV file.

## Prerequisites

### API Credentials

Requires one of:
- **API Service Account** with **Results API** role (recommended for org-wide access)
- **User Account** with **Reviewer** or **Security Lead** role (limited to assigned teams)

**Setup:**
```ini
# Windows: C:\Users\<username>\.veracode\credentials
# Mac/Linux: ~/.veracode/credentials

[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

### Python Requirements
```bash
pip install requests veracode-api-signing
```

## Features

- **Comprehensive Coverage**: Exports findings from all Veracode scan types:
  - Static Analysis (SAST)
  - Dynamic Analysis (DAST) 
  - Software Composition Analysis (SCA & SCA Agent)
  - Manual Penetration Testing
  - Infrastructure as Code (Container Security)
- **Concurrent Processing**: Parallel API requests with configurable thread pools for fast exports
- **Rate Limiting**: Built-in token bucket algorithm prevents API throttling
- **Smart Filtering**: Filter by application, scan type, severity, CWE, status
- **Sandbox Support**: Optionally include findings from development sandboxes
- **SSL Inspection Support**: Custom CA certificate support for environments behind SSL inspection devices (e.g. Zscaler)

## Quick Start

**Export all findings:**
```bash
python script.py
```

**Filter by applications:**
```bash
python script.py --app-name "App1,App2,App3"
```

**Include sandboxes + high severity only:**
```bash
python script.py --include-sandbox --severity-gte 4 --status OPEN
```

**Behind an SSL inspection device:**
```bash
python script.py --ca-cert /path/to/corp-ca.pem
```

**With IaC scans:**
```bash
# 1. Fetch IaC data (requires browser cookies)
python fetch_iac_details.py --cookies-file cookies.txt --output iac-findings.json

# 2. Export all findings
python script.py --iac-json iac-findings.json --output complete-findings.csv
```

## Command-Line Arguments

|Argument           |Default |Description                                                         |
|-------------------|--------|--------------------------------------------------------------------|
|`--output`         |`veracode_findings_api.csv`|Output CSV filename                              |
|`--app-name`       |None    |Comma-separated application names (exact match)                     |
|`--app-guid`       |None    |Specific application GUID                                           |
|`--scan-type`      |None    |STATIC, DYNAMIC, MANUAL, SCA (comma-separated)                      |
|`--severity`       |None    |Exact severity (0-5)                                                |
|`--severity-gte`   |None    |Severity >= (0-5)                                                   |
|`--cwe`            |None    |CWE ID (single or comma-separated)                                  |
|`--status`         |None    |OPEN or CLOSED                                                      |
|`--include-sandbox`|False   |Include sandbox findings                                            |
|`--iac-json`       |None    |Path to IaC findings JSON file                                      |
|`--max-workers`    |10      |Concurrent threads for parallel processing                          |
|`--rate-limit`     |10.0    |Max API requests/second                                             |
|`--max-apps`       |None    |Limit apps processed (testing)                                      |
|`--ca-cert`        |None    |Path to custom CA certificate bundle (.pem)                         |

## SSL Inspection (Corporate Proxy)

If you're behind an SSL inspection device (e.g. Zscaler), pass your corporate CA certificate via `--ca-cert`. Get the `.pem` from IT or export it from your browser using the [Veracode SSL certificate guide](https://docs.veracode.com/r/c_using_certificates). 

If it's DER-encoded (`.cer`), convert first:

```bash
openssl x509 -inform DER -in corp-ca.cer -out corp-ca.pem
python script.py --ca-cert /path/to/corp-ca.pem
```

## IaC (Container Security) Integration

IaC scans require browser session cookies (not available via standard API).

### Getting IaC Data

**Step 1: Extract browser cookies**
1. Log into Veracode Platform (https://analysiscenter.veracode.com)
2. Press F12 → Network tab → Refresh page
3. Click any request → Headers → Copy `Cookie:` value
4. Save to `cookies.txt`

**Step 2: Fetch IaC findings**
```bash
python fetch_iac_details.py --cookies-file cookies.txt --output iac-findings.json --filter-apps "App1,App2"
```

**Step 3: Include in export**
```bash
python script.py --app-name "App1,App2" --iac-json iac-findings.json
```

**Note:** Cookies expire after a few hours. The script validates the JSON contains detailed findings (not just summary counts).

## Output Files

The script generates two output files:

### 1. CSV File (Default: `veracode_findings_api.csv`)

- Primary output containing all findings in tabular format
- One row per finding across all scan types
- Can be opened in Excel, imported into databases, or processed by other tools
- Filename customizable via `--output` argument

### 2. JSON File (Auto-generated: `veracode_findings_api_raw_<timestamp>.json`)

- Raw API response data for all findings
- Includes complete nested data structures from Veracode APIs
- Useful for debugging, advanced analysis, or custom processing
- Automatically timestamped to avoid overwriting previous exports
- Contains all metadata that may not fit in CSV format

**Example:**
```bash
python script.py --app-name "MyApp" --output myapp-findings.csv
```
**Generates:**
- `myapp-findings.csv` - Main CSV output
- `veracode_findings_api_raw_20260305_143022.json` - Raw JSON data



### Standard Columns (All Scan Types)

|Column              |Description                                                           |
|--------------------|----------------------------------------------------------------------|
|Application Name    |Application name from Veracode profile                                |
|Application ID      |Application GUID                                                      |
|Sandbox Name        |Sandbox name (blank for policy scans and IaC)                         |
|Custom Severity Name|Very High / High / Medium / Low / Very Low / Informational            |
|CVE ID              |CVE identifier (SCA/IaC vulnerabilities only). **IaC**: Finding ID if vulnerability type|
|Description         |Full finding description (HTML tags stripped). **IaC**: Title + description + finding ID|
|Vulnerability Title |Finding title or first 100 chars of description. **IaC**: Finding type (e.g., "Vulnerability", "Misconfiguration")|
|CWE ID              |CWE numeric ID. **IaC**: Rule/Policy ID (e.g., "CIS-DI-0001")        |
|Flaw Name           |CWE name, finding category, or title. **IaC**: Finding ID or title   |
|First Found Date    |ISO 8601 date when finding was first observed. **IaC**: Scan date    |
|Filename/Class      |File path (STATIC), URL (DYNAMIC), component (SCA). **IaC**: File path with line numbers (e.g., "Dockerfile (Lines 12-15)")|
|Finding Status      |OPEN or CLOSED. **IaC**: Always OPEN                                  |
|Fixed Date          |Resolution date (ISO 8601) - only populated when CLOSED/FIXED. **IaC**: Always blank|
|Team Name           |Business unit name or first team from application profile             |
|Days to Resolve     |Calculated days between first found and fixed. **IaC**: Always blank |
|Scan Type           |STATIC, Dynamic Analysis, DAST, MANUAL, SCA, SCA Agent, or **IAC**   |
|CVSS                |CVSS score (prefers v3 for SCA). **IaC**: CVSS from finding if available|
|Severity            |Numeric severity: 5=Very High, 4=High, 3=Medium, 2=Low, 1=Very Low, 0=Informational. **IaC**: Mapped from critical/high/medium/low/negligible/unknown|
|Resolution Status   |Resolution status from Veracode platform. **IaC**: Always blank       |
|Resolution          |Resolution type (e.g., APPROVED, FALSE POSITIVE, etc.). **IaC**: Always blank|
|Mitigation Comments |Comments from annotations/mitigations. **IaC**: Suggested fix text    |
|Veracode Link       |Deep link to finding in Veracode Platform (format varies by scan type). **IaC**: Link to Container Security scan|

### IAC-Specific Columns (IaC Findings Only)

|Column              |Description                                                           |
|--------------------|----------------------------------------------------------------------|
|IAC File Path       |Full file path in repository where IaC issue was found               |
|IAC Start Line      |Starting line number of the finding                                   |
|IAC End Line        |Ending line number of the finding                                     |

**Note:** IAC-specific columns are blank for non-IaC findings. Standard columns may be blank for IaC findings (e.g., CVE ID, CVSS, Fixed Date, Days to Resolve, Resolution Status, Resolution).

## Performance Tuning

**Default (< 50 apps):**
```bash
python script.py  # Uses --max-workers 10 --rate-limit 10
```

**Large deployments (100+ apps):**
```bash
python script.py --max-workers 20 --rate-limit 20
```

**Very large (500+ apps):**
```bash
python script.py --max-workers 30 --rate-limit 30
```

## Severity Mapping

|Numeric|Label        |
|-------|-------------|
|5      |Very High    |
|4      |High         |
|3      |Medium       |
|2      |Low          |
|1      |Very Low     |
|0      |Informational|

## How It Works

### Execution Flow

1. **Initialization**
   - Validates API credentials
   - Creates optimized HTTP sessions with connection pooling
   - Initializes rate limiter with token bucket algorithm
   - Applies custom CA certificate to all sessions if `--ca-cert` is provided

2. **Data Collection Phase**
   - Fetches all application profiles (paginated, supports 1000s of apps)
   - Retrieves SCA workspace/project mappings for agent-based findings
   - Fetches Dynamic Analysis scan mappings
   - Filters applications by `--app-name` or `--app-guid` if specified

3. **Concurrent Processing**
   - Submits all applications to thread pool executor
   - Each worker thread processes one application at a time
   - Rate limiter coordinates requests across all threads
   - Applications are processed in parallel for optimal performance

4. **Finding Extraction (Per Application)**
   - Fetches policy scan findings (all scan types except SCA)
   - Fetches SCA findings separately (API requirement)
   - If `--include-sandbox`: iterates through all sandboxes and repeats above
   - Enriches findings with application metadata and deep links
   - Maps SCA Agent findings to workspace/project IDs
   - Maps Dynamic findings to Dynamic Analysis IDs

5. **IaC Integration (If Enabled)**
   - Loads detailed IaC findings from JSON file
   - Validates file contains detailed findings (not just summary)
   - Matches IaC asset names to Veracode applications using fuzzy logic
   - Creates placeholder entries for unmatched IaC assets
   - Normalizes IaC findings to match standard schema

6. **Post-Processing**
   - Normalizes all findings to common schema
   - Strips HTML tags and entities from descriptions
   - Calculates derived fields (Days to Resolve, etc.)
   - Generates Veracode Platform deep links based on scan type

7. **Output Generation**
   - Writes raw JSON with complete API responses (timestamped)
   - Writes normalized CSV with all findings
   - Displays summary statistics


## Troubleshooting

### Authentication Issues

| Error | Fix |
|-------|-----|
| 401/403 | Check credentials file and API role (Results API for service accounts) |
| 0 apps returned | Service accounts see all apps; user accounts only see assigned teams |
| `SSLError: certificate verify failed` | Use `--ca-cert /path/to/corp-ca.pem` - see [SSL Inspection](#ssl-inspection-corporate-proxy) |
| `handshake_failure` | Veracode requires TLS 1.2+; check your proxy supports it |
| 429 Too Many Requests | Lower `--rate-limit` and `--max-workers` |
| 404 on application | No scans yet, insufficient permissions, or app archived - script skips and continues |
| Missing CSV fields | Expected - some fields are scan-type specific (e.g. CVE ID is SCA/IaC only) |
| IaC cookies expired | Re-export cookies from browser dev tools (expire after ~2-4 hours) |
| IaC asset not matched | Asset name in JSON doesn't match app name in Veracode exactly |
| IaC wrong format error | Run `fetch_iac_details.py` first - the JSON must contain detailed findings |

**Test connectivity:**
```bash
python script.py --max-apps 5 --output test.csv
```

## Common Use Cases

**Specific applications with all scan types:**
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

**Testing with limited apps:**
```bash
python script.py --max-apps 5
```

## API References

- [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro)
- [Applications REST API](https://docs.veracode.com/r/c_apps_intro)
- [API Authentication](https://docs.veracode.com/r/t_install_api_authen)
- [Configure SSL Certificates](https://docs.veracode.com/r/c_using_certificates)

---

**Note:** This is a community tool and is not officially supported by Veracode.
