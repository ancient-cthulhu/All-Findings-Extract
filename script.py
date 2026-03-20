#!/usr/bin/env python3
"""Export vulnerability findings from Veracode across all scan types into a single CSV.

Covers SAST, DAST, SCA, Manual, and IaC scan types with concurrent API processing,
rate limiting, and optional sandbox inclusion.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import html
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL = "https://api.veracode.com"
APPLICATIONS_URL = f"{BASE_URL}/appsec/v1/applications"
SANDBOXES_URL_TEMPLATE = f"{BASE_URL}/appsec/v1/applications/{{app_guid}}/sandboxes"
FINDINGS_URL_TEMPLATE = f"{BASE_URL}/appsec/v2/applications/{{app_guid}}/findings"
SCA_API_BASE = f"{BASE_URL}/srcclr/v3"
DYNAMIC_ANALYSES_URL = f"{BASE_URL}/was/configservice/v1/analyses"
ANALYSIS_CENTER_BASE = "https://analysiscenter.veracode.com/auth/index.jsp"

DEFAULT_PAGE_SIZE = 1000
MAX_CONSECUTIVE_ERRORS = 3
NON_SCA_SCAN_TYPES = ("STATIC", "DYNAMIC", "MANUAL")
MAX_ERROR_BODY_LOG = 500

# Pre-compiled regexes for the hot-path in strip_html_tags
_RE_HTML_TAG = re.compile(r"<[^>]+>")
_RE_WHITESPACE = re.compile(r"\s+")

SEVERITY_LABEL: dict[int, str] = {
    5: "Very High",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Very Low",
    0: "Informational",
}

IAC_SEVERITY_MAP: dict[str, tuple[int, str]] = {
    "critical": (5, "Very High"),
    "high": (4, "High"),
    "medium": (3, "Medium"),
    "low": (2, "Low"),
    "negligible": (1, "Very Low"),
    "unknown": (0, "Informational"),
}

CSV_FIELDNAMES: list[str] = [
    "Application Name",
    "Application ID",
    "Sandbox Name",
    "Custom Severity Name",
    "CVE ID",
    "Description",
    "Vulnerability Title",
    "CWE ID",
    "Flaw Name",
    "First Found Date",
    "Filename/Class",
    "Finding Status",
    "Fixed Date",
    "Team Name",
    "Days to Resolve",
    "Scan Type",
    "CVSS",
    "Severity",
    "Resolution Status",
    "Resolution",
    "Mitigation Comments",
    "Veracode Link",
    "IAC File Path",
    "IAC Start Line",
    "IAC End Line",
]


# ---------------------------------------------------------------------------
# Session Factory
# ---------------------------------------------------------------------------

def create_session(ca_cert: Optional[str] = None) -> requests.Session:
    """Create an HTTP session with connection pooling and optional custom CA cert.

    Raises:
        FileNotFoundError: If *ca_cert* is provided but the file does not exist.
    """
    if ca_cert and not os.path.isfile(ca_cert):
        raise FileNotFoundError(
            f"CA certificate file not found: {ca_cert}\n"
            "If DER-encoded (.cer), convert first: "
            "openssl x509 -inform DER -in corp-ca.cer -out corp-ca.pem"
        )

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=50,
        max_retries=3,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if ca_cert:
        session.verify = ca_cert
    return session


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe token-bucket rate limiter.

    Key design choices:
    - ``time.sleep()`` is called **outside** the lock so sleeping threads do
      not prevent others from acquiring tokens that have become available.
    - Uses ``time.monotonic()`` to be immune to NTP / wall-clock adjustments.
    """

    def __init__(self, requests_per_second: float = 10.0) -> None:
        self._rps = requests_per_second
        self._tokens = float(requests_per_second)
        self._max_tokens = float(requests_per_second)
        self._last_update = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a token is available, then consume it."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_update
                self._tokens = min(
                    self._max_tokens,
                    self._tokens + elapsed * self._rps,
                )
                self._last_update = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return  # token acquired — lock released

                sleep_needed = (1.0 - self._tokens) / self._rps

            # Sleep WITHOUT holding the lock
            time.sleep(sleep_needed)


# ---------------------------------------------------------------------------
# Text Utilities
# ---------------------------------------------------------------------------

def strip_html_tags(text: Optional[str]) -> Optional[str]:
    """Remove HTML tags, decode entities, and normalise whitespace.

    Also attempts base64 decoding for payloads that look like encoded HTML.
    """
    if not text:
        return text

    # Heuristic: long, space-free ASCII → likely base64-encoded HTML.
    if len(text) > 100 and " " not in text and text.isascii():
        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="ignore")
            if "<" in decoded and ">" in decoded:
                text = decoded
        except Exception:
            pass

    text = _RE_HTML_TAG.sub("", text)
    text = html.unescape(text)
    text = _RE_WHITESPACE.sub(" ", text).strip()
    return text


def _extract_team_name(app_profile: dict[str, Any]) -> Optional[str]:
    """Extract the team/BU name from an application profile.

    Consolidates the identical logic formerly duplicated in
    ``normalize_finding`` and ``normalize_detailed_iac_finding``.
    """
    bu = app_profile.get("business_unit")
    if isinstance(bu, dict):
        name = bu.get("name")
        if name and name != "Not Specified":
            return name

    teams = app_profile.get("teams", [])
    if isinstance(teams, list) and teams:
        first = teams[0]
        if isinstance(first, dict):
            return first.get("team_name")
    return None


# ---------------------------------------------------------------------------
# Finding Field Extractors
# ---------------------------------------------------------------------------

def _extract_cwe_id(details: dict[str, Any]) -> Optional[int]:
    cwe = details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("id")
    if isinstance(cwe, (int, float)):
        return int(cwe)
    return None


def _extract_cwe_name(details: dict[str, Any]) -> Optional[str]:
    cwe = details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("name")
    return details.get("finding_category") or details.get("flaw_name")


def _extract_cve_id(details: dict[str, Any]) -> Optional[str]:
    cve = details.get("cve")
    if isinstance(cve, dict):
        return cve.get("name")
    if isinstance(cve, str):
        return cve
    return None


def _extract_cvss(details: dict[str, Any]) -> Optional[float]:
    cve = details.get("cve")
    if isinstance(cve, dict):
        cvss3 = cve.get("cvss3") or {}
        if cvss3.get("score"):
            return cvss3["score"]
        return cve.get("cvss")
    return details.get("cvss")


_FILENAME_KEYS: dict[str, tuple[str, ...]] = {
    "STATIC": ("file_name", "file_path"),
    "DYNAMIC": ("path", "URL"),
    "MANUAL": ("location", "module"),
    "SCA": ("component_filename", "version"),
}


def _extract_filename(details: dict[str, Any], scan_type: str) -> Optional[str]:
    for key in _FILENAME_KEYS.get(scan_type, ()):
        val = details.get(key)
        if val:
            return val
    return None


def _extract_mitigation_comments(finding: dict[str, Any]) -> Optional[str]:
    """Build a pipe-delimited string from annotation comments."""
    annotations = finding.get("annotations") or []
    parts: list[str] = []
    for ann in annotations:
        comment = ann.get("comment")
        if comment:
            action = ann.get("action", "")
            parts.append(f"[{action}] {comment}" if action else comment)
    return " | ".join(parts) if parts else None


# ---------------------------------------------------------------------------
# Date Helpers
# ---------------------------------------------------------------------------

def _days_between(start_iso: Optional[str], end_iso: Optional[str]) -> Optional[int]:
    """Return the number of days between two ISO-8601 date strings, or *None*."""
    if not start_iso or not end_iso:
        return None
    try:
        s = dt.datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        e = dt.datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
        return (e - s).days
    except (ValueError, TypeError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Scan-URL Parsing
# ---------------------------------------------------------------------------

def _parse_scan_url_params(scan_url: str) -> Optional[tuple[int, str]]:
    """Parse ``'Prefix:a:b:12345:extra'`` → ``(12345, '12345:extra')``.

    Returns *None* if the URL doesn't match the expected format.
    """
    parts = scan_url.split(":")
    if len(parts) >= 4:
        try:
            build_id = int(parts[3])
            return build_id, ":".join(parts[3:])
        except (ValueError, IndexError):
            pass
    return None


# ---------------------------------------------------------------------------
# Veracode Deep-Link Generation
# ---------------------------------------------------------------------------

def _link_suffix(primary: str, secondary: Optional[str]) -> str:
    return f"{primary}:{secondary}" if secondary else f"{primary}:"


def _generate_veracode_link(
    app_guid: str,
    scan_type: str,
    details: Optional[dict[str, Any]],
    sandbox_guid: Optional[str] = None,
    finding_obj: Optional[dict[str, Any]] = None,
    app_id: Optional[str] = None,
    app_oid: Optional[str] = None,
) -> Optional[str]:
    """Build a platform deep-link appropriate for the scan type."""
    if not app_guid:
        return None
    base = ANALYSIS_CENTER_BASE

    if scan_type == "STATIC":
        return _link_static(base, app_guid, app_id, app_oid, sandbox_guid, finding_obj, details)
    if scan_type == "DYNAMIC":
        return _link_dynamic(base, app_guid, sandbox_guid, finding_obj)
    if scan_type == "MANUAL":
        return f"{base}#AnalyzeAppManualList:{_link_suffix(app_guid, sandbox_guid)}"
    if scan_type == "SCA":
        return _link_sca(base, app_guid, app_id, app_oid, sandbox_guid, finding_obj, details)
    return f"{base}#AnalyzeAppModuleList:{app_guid}:"


def _link_static(
    base: str, app_guid: str, app_id: Optional[str], app_oid: Optional[str],
    sandbox_guid: Optional[str], finding_obj: Optional[dict], details: Optional[dict],
) -> str:
    scan_params = None
    if finding_obj:
        scan_params = finding_obj.get("_latest_scan_params") or finding_obj.get("_finding_scan_params")
    if scan_params and app_oid and app_id:
        return f"{base}#ReviewResultsAllFlaws:{app_oid}:{app_id}:{scan_params}"

    build_id = (finding_obj or {}).get("build_id") or (details or {}).get("build_id")
    if build_id and app_oid and app_id:
        return f"{base}#ReviewResultsAllFlaws:{app_oid}:{app_id}:{build_id}"
    if app_oid and app_id:
        return f"{base}#AnalyzeAppModuleList:{app_oid}:{app_id}:"
    return f"{base}#AnalyzeAppModuleList:{_link_suffix(app_guid, sandbox_guid)}"


def _link_dynamic(
    base: str, app_guid: str, sandbox_guid: Optional[str], finding_obj: Optional[dict],
) -> str:
    if finding_obj:
        da_id = finding_obj.get("_dynamic_analysis_id")
        if da_id:
            return f"https://web.analysiscenter.veracode.com/was/#/analysis/{da_id}/scans"
        dast_url = finding_obj.get("_dast_scan_url")
        if dast_url:
            return f"{base}#{dast_url}"
    return f"{base}#AnalyzeAppDynamicList:{_link_suffix(app_guid, sandbox_guid)}"


def _link_sca(
    base: str, app_guid: str, app_id: Optional[str], app_oid: Optional[str],
    sandbox_guid: Optional[str], finding_obj: Optional[dict], details: Optional[dict],
) -> str:
    if details:
        metadata = details.get("metadata") or {}
        if metadata.get("sca_scan_mode", "").upper() == "AGENT":
            ws = (
                details.get("workspace_guid") or details.get("workspace_id")
                or metadata.get("workspace_guid") or metadata.get("workspace_id")
            )
            pid = details.get("project_id") or metadata.get("project_id")
            if finding_obj:
                ws = ws or finding_obj.get("_sca_workspace_guid") or finding_obj.get("workspace_guid")
                pid = pid or finding_obj.get("_sca_project_id") or finding_obj.get("project_id")
            if ws and pid:
                return f"https://sca.analysiscenter.veracode.com/workspaces/{ws}/projects/{pid}/issues"
            return "https://sca.analysiscenter.veracode.com/workspaces"

    scan_params = (finding_obj or {}).get("_latest_scan_params")
    if scan_params and app_oid and app_id:
        return f"{base}#ReviewResultsSCA:{app_oid}:{app_id}:{scan_params}"
    if app_oid and app_id:
        return f"{base}#AnalyzeAppSourceComposition:{app_oid}:{app_id}:"
    return f"{base}#AnalyzeAppSourceComposition:{_link_suffix(app_guid, sandbox_guid)}"


# ---------------------------------------------------------------------------
# Finding Normalisation
# ---------------------------------------------------------------------------

def normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Normalise a raw API finding record into the common CSV schema."""
    app_profile = finding.get("_app_profile") or {}
    scan_type = finding.get("scan_type")
    original_scan_type = scan_type
    details = finding.get("finding_details") or {}

    # Refine scan-type label for display
    if scan_type == "SCA":
        if (details.get("metadata") or {}).get("sca_scan_mode") == "AGENT":
            scan_type = "SCA Agent"
    elif scan_type == "DYNAMIC":
        if finding.get("_dynamic_analysis_id"):
            scan_type = "Dynamic Analysis"
        elif finding.get("_dast_scan_url"):
            scan_type = "DAST"

    status_obj = finding.get("finding_status") or {}
    first_found = status_obj.get("first_found_date")
    status = status_obj.get("status")
    resolution_status = status_obj.get("resolution_status")

    fixed_date = None
    if status == "CLOSED" or resolution_status == "FIXED":
        fixed_date = status_obj.get("resolution_date") or status_obj.get("last_seen_date")

    cve_id = _extract_cve_id(details)
    flaw_name = _extract_cwe_name(details)
    severity = details.get("severity")

    vuln_title = None
    if scan_type in ("SCA", "SCA Agent"):
        vuln_title = cve_id or flaw_name

    app_guid = finding.get("_app_guid")
    app_id = finding.get("_app_id")
    app_oid = finding.get("_app_oid")

    return {
        "Application Name": finding.get("_app_name"),
        "Application ID": app_guid,
        "Sandbox Name": finding.get("_sandbox_name"),
        "Custom Severity Name": SEVERITY_LABEL.get(severity) if severity is not None else None,
        "CVE ID": cve_id,
        "Description": strip_html_tags(finding.get("description")),
        "Vulnerability Title": vuln_title,
        "CWE ID": _extract_cwe_id(details),
        "Flaw Name": flaw_name,
        "First Found Date": first_found,
        "Filename/Class": _extract_filename(details, original_scan_type),
        "Finding Status": status,
        "Fixed Date": fixed_date,
        "Team Name": _extract_team_name(app_profile),
        "Days to Resolve": _days_between(first_found, fixed_date),
        "Scan Type": scan_type,
        "CVSS": _extract_cvss(details),
        "Severity": severity,
        "Resolution Status": resolution_status,
        "Resolution": status_obj.get("resolution"),
        "Veracode Link": _generate_veracode_link(
            app_guid, original_scan_type, details,
            finding.get("_sandbox_guid"), finding, app_id, app_oid,
        ),
        "Mitigation Comments": _extract_mitigation_comments(finding),
    }


def normalize_iac_finding(
    finding: dict[str, Any],
    iac_record: dict[str, Any],
    app_name: str,
    app_guid: str,
    app_profile: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Normalise a detailed IaC finding into the common CSV schema."""
    sev_str = finding.get("severity", "unknown").lower()
    sev_level, sev_label = IAC_SEVERITY_MAP.get(sev_str, (0, "Informational"))

    finding_id = finding.get("id", "")
    finding_type = finding.get("finding_type", "")
    title = strip_html_tags(finding.get("title", "") or finding.get("description", "IaC Misconfiguration"))
    description = strip_html_tags(finding.get("description", ""))
    suggested_fix = strip_html_tags(finding.get("suggested_fix", ""))
    rule_id = finding.get("rule_id", "")
    cvss = finding.get("cvss", "")

    raw_path = finding.get("filepath", [])
    file_path = raw_path[0] if isinstance(raw_path, list) and raw_path else (raw_path or "")
    start_line = finding.get("start_line", "")
    end_line = finding.get("end_line", "")

    full_desc = description or title
    if finding_id:
        full_desc = f"{finding_id}: {full_desc}"

    location = file_path
    if start_line and end_line:
        location += f" (Lines {start_line}-{end_line})"
    elif start_line:
        location += f" (Line {start_line})"

    scan_id = iac_record.get("scan_id", "")

    return {
        "Application Name": app_name,
        "Application ID": app_guid,
        "Sandbox Name": None,
        "Custom Severity Name": sev_label,
        "CVE ID": finding_id if finding_type == "vulnerability" else None,
        "Description": full_desc,
        "Vulnerability Title": finding_type.title() if finding_type else None,
        "CWE ID": rule_id or None,
        "Flaw Name": finding_id or title,
        "First Found Date": iac_record.get("scanned_at"),
        "Filename/Class": location or None,
        "Finding Status": "OPEN",
        "Fixed Date": None,
        "Team Name": _extract_team_name(app_profile) if app_profile else None,
        "Days to Resolve": None,
        "Scan Type": "IAC",
        "CVSS": cvss or None,
        "Severity": sev_level,
        "Resolution Status": None,
        "Resolution": None,
        "Veracode Link": (
            f"https://web.analysiscenter.veracode.com/app/container-iac-scans/{scan_id}/summary"
            if scan_id else None
        ),
        "Mitigation Comments": suggested_fix or None,
        "IAC File Path": file_path,
        "IAC Start Line": start_line or None,
        "IAC End Line": end_line or None,
    }


# ---------------------------------------------------------------------------
# API Fetchers
# ---------------------------------------------------------------------------

def _get_embedded(data: dict, key: str) -> list[dict]:
    """Safely extract ``data["_embedded"][key]``, defaulting to ``[]``."""
    return data.get("_embedded", {}).get(key, [])


def get_applications(
    session: requests.Session,
    rate_limiter: Optional[RateLimiter] = None,
) -> list[dict[str, Any]]:
    """Fetch all applications via pagination."""
    print("\n" + "=" * 70)
    print("  FETCHING APPLICATIONS")
    print("=" * 70)
    print("  Fetching applications...")

    all_apps: list[dict] = []
    page = 0
    consecutive_errors = 0

    while True:
        try:
            if page > 0:
                time.sleep(0.1)
            if rate_limiter:
                rate_limiter.acquire()

            resp = session.get(
                APPLICATIONS_URL,
                params={"page": page, "size": 1000},
                auth=RequestsAuthPluginVeracodeHMAC(),
                timeout=45,
            )

            if resp.status_code != 200:
                print(f"  WARNING: Status {resp.status_code} on page {page}, retrying...")
                consecutive_errors += 1
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    print(f"  ERROR: {MAX_CONSECUTIVE_ERRORS} consecutive errors, "
                          f"stopping at {len(all_apps)} applications")
                    break
                time.sleep(1)
                continue

            consecutive_errors = 0
            data = resp.json()
            apps = _get_embedded(data, "applications")
            if not apps:
                break

            all_apps.extend(apps)
            if page == 0 or (page + 1) % 5 == 0:
                print(f"  Retrieved {len(all_apps)} applications so far...")
            if not data.get("_links", {}).get("next"):
                break
            page += 1

        except KeyboardInterrupt:
            print(f"\n  Interrupted. Retrieved {len(all_apps)} applications so far.")
            break
        except Exception as exc:
            print(f"  WARNING: Error on page {page}: {str(exc)[:100]}")
            consecutive_errors += 1
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                print(f"  ERROR: {MAX_CONSECUTIVE_ERRORS} consecutive errors, "
                      f"stopping at {len(all_apps)} applications")
                break
            time.sleep(1)

    print(f"\n  ✓ Total applications found: {len(all_apps)}\n")
    return all_apps


def get_sandboxes(
    session: requests.Session,
    app_guid: str,
    rate_limiter: Optional[RateLimiter] = None,
) -> list[dict[str, Any]]:
    """Return development sandboxes for an application."""
    url = SANDBOXES_URL_TEMPLATE.format(app_guid=app_guid)
    try:
        if rate_limiter:
            rate_limiter.acquire()
        resp = session.get(url, auth=RequestsAuthPluginVeracodeHMAC(), timeout=60)
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            print(f"    WARNING: Could not fetch sandboxes (status {resp.status_code})")
            return []
        return _get_embedded(resp.json(), "sandboxes")
    except Exception as exc:
        print(f"    WARNING: Error fetching sandboxes: {exc}")
        return []


def get_sca_workspaces(
    session: requests.Session,
    sleep_time: float = 0.01,
    rate_limiter: Optional[RateLimiter] = None,
) -> dict[str, dict[str, str]]:
    """Fetch SCA workspaces/projects.  Returns lookup keyed by lower-cased
    project name and ``'guid:<linked_app_guid>'``."""
    ws_map: dict[str, dict[str, str]] = {}
    try:
        all_ws: list[dict] = []
        page = 0
        while True:
            if rate_limiter:
                rate_limiter.acquire()
            resp = session.get(
                f"{SCA_API_BASE}/workspaces",
                params={"page": page, "size": 500},
                auth=RequestsAuthPluginVeracodeHMAC(), timeout=60,
            )
            if resp.status_code != 200:
                break
            data = resp.json()
            ws = _get_embedded(data, "workspaces")
            if not ws:
                break
            all_ws.extend(ws)
            if not data.get("_links", {}).get("next"):
                break
            page += 1
            if sleep_time > 0:
                time.sleep(sleep_time)

        print(f"  Fetched {len(all_ws)} SCA workspaces")

        total_proj = 0
        for workspace in all_ws:
            ws_id = workspace.get("id")
            ws_site = workspace.get("site_id")
            if not ws_id:
                continue
            pp = 0
            while True:
                if rate_limiter:
                    rate_limiter.acquire()
                resp = session.get(
                    f"{SCA_API_BASE}/workspaces/{ws_id}/projects",
                    params={"page": pp, "size": 500},
                    auth=RequestsAuthPluginVeracodeHMAC(), timeout=60,
                )
                if resp.status_code != 200:
                    break
                pdata = resp.json()
                projects = _get_embedded(pdata, "projects")
                if not projects:
                    break
                for proj in projects:
                    ps = proj.get("site_id")
                    pn = proj.get("name", "")
                    lg = (proj.get("linked_application") or {}).get("guid")
                    if ps and ws_site:
                        mapping = {"workspace_guid": ws_site, "project_id": ps, "project_name": pn}
                        ws_map[pn.lower()] = mapping
                        if lg:
                            ws_map[f"guid:{lg}"] = mapping
                        total_proj += 1
                if not pdata.get("_links", {}).get("next"):
                    break
                pp += 1
                if sleep_time > 0:
                    time.sleep(sleep_time)

        print(f"  Fetched {total_proj} total SCA projects across all workspaces")
    except Exception as exc:
        print(f"    WARNING: Could not fetch SCA workspaces: {exc}")
    return ws_map


def get_dynamic_analyses(
    session: requests.Session,
    sleep_time: float = 0.01,
    rate_limiter: Optional[RateLimiter] = None,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch Dynamic Analysis metadata keyed by linked application GUID."""
    da_map: dict[str, list[dict]] = {}
    try:
        if rate_limiter:
            rate_limiter.acquire()
        resp = session.get(
            DYNAMIC_ANALYSES_URL, params={"size": 500},
            auth=RequestsAuthPluginVeracodeHMAC(), timeout=60,
        )
        if resp.status_code != 200:
            return da_map

        for analysis in _get_embedded(resp.json(), "analyses"):
            a_id = analysis.get("analysis_id")
            if not a_id:
                continue
            if rate_limiter:
                rate_limiter.acquire()
            sr = session.get(
                f"{DYNAMIC_ANALYSES_URL}/{a_id}/scans",
                auth=RequestsAuthPluginVeracodeHMAC(), timeout=60,
            )
            if sr.status_code == 200:
                for scan in _get_embedded(sr.json(), "scans"):
                    guid = scan.get("linked_platform_app_uuid")
                    if guid:
                        da_map.setdefault(guid, []).append({
                            "analysis_id": a_id,
                            "analysis_name": analysis.get("name"),
                        })
            if sleep_time > 0:
                time.sleep(sleep_time)
    except Exception as exc:
        print(f"    WARNING: Could not fetch Dynamic Analysis: {exc}")
    return da_map


# ---------------------------------------------------------------------------
# Findings Fetchers
# ---------------------------------------------------------------------------

def _fetch_findings_page(
    session: requests.Session,
    app_guid: str,
    app_name: str,
    app_profile: dict[str, Any],
    filters: dict[str, Any],
    sleep_time: float,
    sandbox_guid: Optional[str],
    sandbox_name: Optional[str],
    app_id: Optional[str],
    app_oid: Optional[str],
    rate_limiter: Optional[RateLimiter],
) -> list[dict[str, Any]]:
    """Paginate through all findings for one app/sandbox combination."""
    url = FINDINGS_URL_TEMPLATE.format(app_guid=app_guid)
    all_findings: list[dict] = []
    page = 0

    params: dict[str, Any] = {"size": DEFAULT_PAGE_SIZE}
    if sandbox_guid:
        params["context"] = sandbox_guid
    for key in ("scan_type", "cwe"):
        if filters.get(key):
            params[key] = filters[key]
    for key in ("severity", "severity_gte"):
        if filters.get(key) is not None:
            params[key] = filters[key]
    if filters.get("status"):
        params["status"] = filters["status"].upper()

    if sandbox_guid:
        label = f"sandbox '{sandbox_name}'"
    elif sandbox_name:
        label = sandbox_name
    else:
        label = "policy scan"

    while True:
        params["page"] = page
        try:
            if rate_limiter:
                rate_limiter.acquire()

            resp = session.get(
                url, params=params,
                auth=RequestsAuthPluginVeracodeHMAC(), timeout=120,
            )
            if resp.status_code == 404:
                print(f"    No findings or app not found (404) [{label}]")
                break
            if resp.status_code != 200:
                print(f"    ERROR: Status {resp.status_code} [{label}]")
                print(f"    Response: {resp.text[:MAX_ERROR_BODY_LOG]}")
                resp.raise_for_status()

            data = resp.json()
            findings = _get_embedded(data, "findings")
            if not findings:
                break

            for finding in findings:
                finding["_app_name"] = app_name
                finding["_app_guid"] = app_guid
                finding["_app_profile"] = app_profile
                finding["_sandbox_name"] = sandbox_name if sandbox_guid else None
                finding["_sandbox_guid"] = sandbox_guid
                finding["_app_id"] = app_id
                finding["_app_oid"] = app_oid

            all_findings.extend(findings)

            if page == 0:
                print(f"    [{label}] Page {page}: {len(findings)} findings")
            else:
                print(f"    [{label}] Page {page}: {len(findings)} findings "
                      f"(Total so far: {len(all_findings)})")

            if not data.get("_links", {}).get("next"):
                break
            page += 1
            if sleep_time > 0:
                time.sleep(sleep_time)
        except Exception as exc:
            print(f"    ERROR fetching findings [{label}]: {exc}")
            break

    return all_findings


def _get_all_findings_for_app(
    session: requests.Session,
    app_guid: str,
    app_name: str,
    app_profile: dict[str, Any],
    filters: dict[str, Any],
    sleep_time: float,
    include_sandboxes: bool,
    app_id: Optional[str],
    app_oid: Optional[str],
    rate_limiter: Optional[RateLimiter],
) -> list[dict[str, Any]]:
    """Fetch findings for policy scan (+ sandboxes).  SCA fetched separately per API rules."""
    all_findings: list[dict] = []

    requested = (
        [s.strip().upper() for s in filters["scan_type"].split(",") if s.strip()]
        if filters.get("scan_type") else []
    )
    if requested:
        fetch_sca = "SCA" in requested
        non_sca = [t for t in requested if t in NON_SCA_SCAN_TYPES]
        fetch_non_sca = bool(non_sca)
    else:
        fetch_sca = True
        fetch_non_sca = True
        non_sca = list(NON_SCA_SCAN_TYPES)

    def _run(scan_filter: str, ctx_guid: Optional[str] = None, ctx_name: Optional[str] = None) -> list[dict]:
        pf = dict(filters)
        if scan_filter:
            pf["scan_type"] = scan_filter
        else:
            pf.pop("scan_type", None)
        return _fetch_findings_page(
            session, app_guid, app_name, app_profile, pf, sleep_time,
            ctx_guid, ctx_name, app_id, app_oid, rate_limiter,
        )

    if fetch_non_sca:
        all_findings.extend(_run(",".join(non_sca)))
    if fetch_sca:
        all_findings.extend(_run("SCA", ctx_name="policy scan (SCA)"))

    if include_sandboxes:
        sbs = get_sandboxes(session, app_guid, rate_limiter)
        if sbs:
            print(f"    Found {len(sbs)} sandbox(es), fetching findings for each...")
        for sb in sbs:
            sg = sb.get("guid")
            sn = sb.get("name", sg)
            if not sg:
                continue
            if fetch_non_sca:
                all_findings.extend(_run(",".join(non_sca), sg, sn))
            if fetch_sca:
                all_findings.extend(_run("SCA", sg, f"{sn} (SCA)"))

    return all_findings


# ---------------------------------------------------------------------------
# Per-Application Worker (thread pool)
# ---------------------------------------------------------------------------

def _process_application(
    app: dict[str, Any],
    idx: int,
    total: int,
    filters: dict[str, Any],
    sleep_time: float,
    include_sandboxes: bool,
    sca_map: dict[str, dict[str, str]],
    da_map: dict[str, list[dict[str, Any]]],
    rate_limiter: RateLimiter,
    ca_cert: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Fetch and enrich findings for one application (thread worker).

    Creates its own session (thread-safe) and closes it in a finally block
    to guarantee no connection leak on exceptions.
    """
    session = create_session(ca_cert=ca_cert)
    try:
        profile = app.get("profile") or {}
        app_guid = app.get("guid")
        app_name = profile.get("name", "Unknown")
        app_id = app.get("id")
        app_oid = app.get("oid") or app.get("alt_org_id")

        # ---- Single-pass scan-URL parsing ----
        static_params_by_build: dict[int, str] = {}
        dast_url_by_build: dict[int, str] = {}
        latest_scan_params: Optional[str] = None

        for scan in app.get("scans", []):
            scan_url = scan.get("scan_url", "")
            if not scan_url:
                continue
            stype = scan.get("scan_type")
            if stype == "STATIC":
                parsed = _parse_scan_url_params(scan_url)
                if parsed:
                    static_params_by_build[parsed[0]] = parsed[1]
                    if latest_scan_params is None:  # first entry = latest
                        latest_scan_params = parsed[1]
            elif stype == "DYNAMIC" and scan_url.startswith("DynamicParamsView:"):
                parsed = _parse_scan_url_params(scan_url)
                if parsed:
                    dast_url_by_build[parsed[0]] = scan_url

        print(f"  [{idx}/{total}] {app_name}")
        print(f"    GUID: {app_guid}")

        findings = _get_all_findings_for_app(
            session, app_guid, app_name, profile, filters,
            sleep_time, include_sandboxes, app_id, app_oid, rate_limiter,
        )

        # ---- Enrich findings (only values actually consumed downstream) ----
        for finding in findings:
            finding["_latest_scan_params"] = latest_scan_params
            ftype = finding.get("scan_type")
            build_id = finding.get("build_id")

            if ftype == "STATIC" and build_id and build_id in static_params_by_build:
                finding["_finding_scan_params"] = static_params_by_build[build_id]

            elif ftype == "DYNAMIC":
                if build_id and build_id in dast_url_by_build:
                    finding["_dast_scan_url"] = dast_url_by_build[build_id]
                da_list = da_map.get(app_guid)
                if da_list:
                    finding["_dynamic_analysis_id"] = da_list[0].get("analysis_id")

            elif ftype == "SCA":
                meta = (finding.get("finding_details") or {}).get("metadata") or {}
                if meta.get("sca_scan_mode") == "AGENT":
                    mapping = sca_map.get(f"guid:{app_guid}") or sca_map.get(app_name.lower())
                    if mapping:
                        finding["_sca_workspace_guid"] = mapping["workspace_guid"]
                        finding["_sca_project_id"] = mapping["project_id"]

        if findings:
            print(f"    ✓ Total findings for this app: {len(findings)}\n")
        else:
            print("    ✗ No findings\n")

        return findings
    finally:
        session.close()


# ---------------------------------------------------------------------------
# IaC Data Loading
# ---------------------------------------------------------------------------

def _load_iac_data(path: str) -> list[dict[str, Any]]:
    """Load and validate IaC detailed findings from a JSON file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"✗ ERROR: IaC JSON file not found: {path}")
        return []
    except json.JSONDecodeError as exc:
        print(f"✗ ERROR: Invalid JSON in IaC file: {exc}")
        return []
    except Exception as exc:
        print(f"✗ ERROR loading IaC data: {exc}")
        return []

    print(f"✓ Loaded IaC data from {path}")
    records = data.get("records", [])
    if not records:
        print("  ✗ No IaC records found in file")
        return []
    if "detailed_findings" not in records[0]:
        print("  ✗ ERROR: File does not contain detailed findings.")
        print("  Please use fetch_iac_details.py to fetch detailed findings.")
        return []
    total = sum(len(r.get("detailed_findings", [])) for r in records)
    print(f"  Found {len(records)} IaC scans with {total} total findings")
    return records


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Export Veracode FINDINGS data via Findings REST API.",
    )
    p.add_argument("--output", default="veracode_findings_api.csv",
                   help="Output CSV filename (default: veracode_findings_api.csv).")
    p.add_argument("--app-name",
                   help="Comma-separated application name(s) to filter.")
    p.add_argument("--app-guid",
                   help="Specific application GUID to process.")
    p.add_argument("--scan-type",
                   help="Comma-separated scan types: STATIC, DYNAMIC, MANUAL, SCA.")
    p.add_argument("--severity", type=int, choices=range(6), metavar="0-5",
                   help="Exact severity filter (0-5).")
    p.add_argument("--severity-gte", type=int, choices=range(6), metavar="0-5",
                   help="Minimum severity filter (0-5).")
    p.add_argument("--cwe",
                   help="CWE ID filter (single or comma-separated).")
    p.add_argument("--status", choices=["OPEN", "CLOSED"],
                   help="Finding status filter.")
    p.add_argument("--include-sandbox", action="store_true", default=False,
                   help="Include sandbox findings (default: policy only).")
    p.add_argument("--sleep", type=float, default=0.01,
                   help="Sleep between API pages (default: 0.01s).")
    p.add_argument("--max-workers", type=int, default=10,
                   help="Concurrent threads (default: 10).")
    p.add_argument("--rate-limit", type=float, default=10.0,
                   help="Max API requests/second (default: 10).")
    p.add_argument("--max-apps", type=int,
                   help="Limit apps processed (testing).")
    p.add_argument("--iac-json",
                   help="Path to IaC detailed-findings JSON file.")
    p.add_argument("--ca-cert",
                   help="Path to custom CA certificate bundle (.pem).")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()
    rate_limiter = RateLimiter(requests_per_second=args.rate_limit)

    # --- Build filter dict ---
    filters: dict[str, Any] = {}
    if args.scan_type:
        filters["scan_type"] = args.scan_type
    if args.severity is not None:
        filters["severity"] = args.severity
    if args.severity_gte is not None:
        filters["severity_gte"] = args.severity_gte
    if args.cwe:
        filters["cwe"] = args.cwe
    if args.status:
        filters["status"] = args.status

    # --- Banner ---
    print("\n" + "=" * 70)
    print("  VERACODE FINDINGS API EXPORT")
    print("=" * 70)
    print(f"  Output File      : {args.output}")
    print(f"  Include Sandboxes: {args.include_sandbox}")
    print(f"  Max Workers      : {args.max_workers}")
    print(f"  Rate Limit       : {args.rate_limit} req/sec")
    for label, val in [
        ("CA Cert Bundle", args.ca_cert), ("Filter App Name", args.app_name),
        ("Filter App GUID", args.app_guid), ("Filter Scan Type", args.scan_type),
        ("Filter CWE", args.cwe), ("Filter Status", args.status),
    ]:
        if val:
            print(f"  {label:19s}: {val}")
    if args.severity is not None:
        print(f"  Filter Severity  : {args.severity}")
    if args.severity_gte is not None:
        print(f"  Filter Sev >=    : {args.severity_gte}")
    print("=" * 70 + "\n")

    # --- Phase 1: Pre-fetch lookup data (single shared session) ---
    session = create_session(ca_cert=args.ca_cert)
    try:
        print("\n" + "=" * 70)
        print("  FETCHING SCA WORKSPACE MAPPINGS")
        print("=" * 70)
        sca_map = get_sca_workspaces(session, args.sleep, rate_limiter)
        if sca_map:
            print(f"  Found {len(sca_map)} SCA project mappings")
        else:
            print("  No SCA projects found or unable to fetch")
        print("=" * 70 + "\n")

        print("\n" + "=" * 70)
        print("  FETCHING DYNAMIC ANALYSIS MAPPINGS")
        print("=" * 70)
        da_map = get_dynamic_analyses(session, args.sleep, rate_limiter)
        if da_map:
            total_da = sum(len(v) for v in da_map.values())
            print(f"  Found {total_da} Dynamic Analysis across {len(da_map)} applications")
        else:
            print("  No Dynamic Analysis found or unable to fetch")
        print("=" * 70 + "\n")

        # --- Phase 2: Resolve application list ---
        if args.app_guid:
            applications = [{"guid": args.app_guid, "profile": {"name": "Unknown"}}]
            print(f"Processing single application: {args.app_guid}\n")
        else:
            applications = get_applications(session, rate_limiter)
            if args.app_name:
                target_set = {n.strip() for n in args.app_name.split(",")}
                applications = [
                    a for a in applications
                    if a.get("profile", {}).get("name", "") in target_set
                ]
                print(f"Filtered to {len(applications)} applications matching provided names\n")
                found = {a.get("profile", {}).get("name", "") for a in applications}
                missing = target_set - found
                if missing:
                    print(f"WARNING: Could not find: {', '.join(sorted(missing))}\n")
            if args.max_apps:
                applications = applications[:args.max_apps]
                print(f"Limited to {args.max_apps} applications (for testing)\n")
    finally:
        session.close()

    # --- Filter SCA map to relevant apps ---
    if sca_map and applications:
        app_guids = {a.get("guid") for a in applications if a.get("guid")}
        app_names_lc = {a.get("profile", {}).get("name", "").lower() for a in applications}
        app_names_lc.discard("")
        orig = len(sca_map)
        # SCA map keys are already lowercase (project names) or "guid:" prefixed
        sca_map = {
            k: v for k, v in sca_map.items()
            if (k.startswith("guid:") and k[5:] in app_guids)
            or (not k.startswith("guid:") and k in app_names_lc)
        }
        print(f"  Filtered SCA mappings: {orig} → {len(sca_map)} (relevant to selected apps)")

    # --- Phase 3: Fetch findings concurrently ---
    print("\n" + "=" * 70)
    print("  FETCHING FINDINGS FROM APPLICATIONS")
    print("=" * 70 + "\n")

    all_findings: list[dict] = []
    apps_with_findings = 0

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_app = {
            executor.submit(
                _process_application,
                app=app, idx=idx, total=len(applications),
                filters=filters, sleep_time=args.sleep,
                include_sandboxes=args.include_sandbox,
                sca_map=sca_map, da_map=da_map,
                rate_limiter=rate_limiter, ca_cert=args.ca_cert,
            ): app
            for idx, app in enumerate(applications, 1)
        }
        for future in as_completed(future_to_app):
            try:
                findings = future.result()
                if findings:
                    all_findings.extend(findings)
                    apps_with_findings += 1
            except Exception as exc:
                name = future_to_app[future].get("profile", {}).get("name", "Unknown")
                print(f"    ✗ ERROR processing {name}: {exc}\n")

    # --- Phase 4: IaC integration ---
    if args.iac_json:
        print("\n" + "=" * 70)
        print("  PROCESSING IAC SCAN DATA")
        print("=" * 70 + "\n")

        iac_records = _load_iac_data(args.iac_json)
        if iac_records:
            # Build exact + case-insensitive lookups (O(1) matching)
            app_by_name: dict[str, dict] = {}
            app_name_lc: dict[str, str] = {}
            for app in applications:
                prof = app.get("profile") or {}
                nm = prof.get("name", "Unknown")
                app_by_name[nm] = {"guid": app.get("guid"), "profile": prof}
                app_name_lc[nm.lower()] = nm

            iac_count = 0
            iac_apps = 0
            print("  Processing detailed IaC findings...\n")

            for rec in iac_records:
                asset = rec.get("asset_name", "")
                info = app_by_name.get(asset)
                if not info:
                    canonical = app_name_lc.get(asset.lower())
                    if canonical:
                        info = app_by_name[canonical]

                if info:
                    matched_name = info["profile"].get("name", asset)
                else:
                    sid = rec.get("scan_id", asset)
                    print(f"  ⚠️  No matching app for IaC asset '{asset}' — using placeholder")
                    info = {
                        "guid": str(sid),
                        "profile": {"name": asset, "business_unit": {"name": "Unknown"}, "teams": []},
                    }
                    matched_name = asset

                iac_apps += 1
                detailed = rec.get("detailed_findings", [])
                if detailed:
                    print(f"  Processing {asset}: {len(detailed)} findings")

                for iac_finding in detailed:
                    all_findings.append(normalize_iac_finding(
                        iac_finding, rec, matched_name, info["guid"], info["profile"],
                    ))
                    iac_count += 1

            print(f"\n  ✓ Processed {iac_apps} IaC applications")
            print(f"  ✓ Added {iac_count} individual IaC findings\n")
        else:
            print("  ✗ No IaC records to process\n")

    # --- Phase 5: Write outputs ---
    print("\n" + "=" * 70)
    print("  SAVING RESULTS")
    print("=" * 70)

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"veracode_findings_api_raw_{timestamp}.json"
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(all_findings, jf, indent=2)
    print(f"  Raw JSON: {json_path} ({len(all_findings)} findings)")

    if all_findings:
        normalised = [
            row if "Application Name" in row else normalize_finding(row)
            for row in all_findings
        ]
        with open(args.output, "w", encoding="utf-8", newline="") as csvf:
            writer = csv.DictWriter(csvf, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(normalised)
        print(f"  CSV File: {args.output} ({len(normalised)} findings)")
    else:
        print("  No findings found with the specified filters.")

    # --- Summary ---
    print("\n" + "=" * 70)
    print("  EXPORT COMPLETED")
    print("=" * 70)
    print(f"  Applications processed    : {len(applications)}")
    print(f"  Applications with findings: {apps_with_findings}")
    print(f"  Total findings            : {len(all_findings)}")
    if args.iac_json:
        iac_n = sum(1 for r in all_findings if isinstance(r, dict) and r.get("Scan Type") == "IAC")
        print(f"    - Regular scan findings : {len(all_findings) - iac_n}")
        print(f"    - IaC scan findings     : {iac_n}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
