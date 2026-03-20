#!/usr/bin/env python3
"""Fetch detailed IaC findings from Veracode using browser session cookies.

Automatically fetches the scan summary and then detailed findings for each scan.
Supports concurrent processing and rate limiting.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

import requests


# ---------------------------------------------------------------------------
# Session Factory
# ---------------------------------------------------------------------------

def _create_pooled_session() -> requests.Session:
    """Create a session with connection pooling."""
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=50,
        max_retries=3,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def setup_session(cookie_string: str) -> requests.Session:
    """Create a session with browser cookies and connection pooling."""
    session = _create_pooled_session()
    for cookie in cookie_string.split(";"):
        cookie = cookie.strip()
        if "=" in cookie:
            name, value = cookie.split("=", 1)
            session.cookies.set(name.strip(), value.strip())
    return session


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe token-bucket rate limiter.

    - Sleeps **outside** the lock so sleeping threads don't block others.
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
                    return

                sleep_needed = (1.0 - self._tokens) / self._rps

            # Sleep WITHOUT holding the lock
            time.sleep(sleep_needed)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IAC_SCANS_URL = "https://ui.analysiscenter.veracode.com/container-scan-query/v1/scans"


# ---------------------------------------------------------------------------
# API Fetchers
# ---------------------------------------------------------------------------

def fetch_iac_summary(
    session: requests.Session,
    limit: int = 5000,
    rate_limiter: Optional[RateLimiter] = None,
) -> list[dict[str, Any]]:
    """Fetch IaC summary data (scan list)."""
    all_records: list[dict] = []
    page = 0

    print("Fetching IaC scan list...")

    while True:
        params = {"page": page, "limit": limit}
        try:
            if rate_limiter:
                rate_limiter.acquire()

            response = session.get(IAC_SCANS_URL, params=params, timeout=30)

            if response.status_code == 401:
                print("  ✗ Authentication failed. Cookies may be expired.")
                return []
            if response.status_code != 200:
                print(f"  ✗ Error fetching scans: HTTP {response.status_code}")
                return []

            data = response.json()
            records = data.get("records", [])
            if not records:
                break

            all_records.extend(records)
            print(f"  Page {page}: {len(records)} scans (Total: {len(all_records)})")

            total_pages = data.get("pagination", {}).get("total_pages", 1)
            if page >= total_pages - 1:
                break
            page += 1

        except Exception as exc:
            print(f"  ✗ Exception: {exc}")
            return all_records

    print(f"✓ Found {len(all_records)} total scans\n")
    return all_records


def fetch_scan_findings(
    session: requests.Session,
    scan_id: int,
    limit: int = 1000,
    rate_limiter: Optional[RateLimiter] = None,
) -> list[dict[str, Any]]:
    """Fetch all findings for a specific scan ID."""
    url = f"{IAC_SCANS_URL}/{scan_id}/findings"
    all_findings: list[dict] = []
    page = 0

    while True:
        params = {"page": page, "limit": limit, "sort": "severity", "direction": "desc"}
        try:
            if rate_limiter:
                rate_limiter.acquire()

            response = session.get(url, params=params, timeout=30)
            if response.status_code in (401,) or response.status_code != 200:
                return all_findings

            data = response.json()
            findings = data.get("findings", [])
            if not findings:
                break

            all_findings.extend(findings)

            total_pages = data.get("pagination", {}).get("total_pages", 1)
            if page >= total_pages - 1:
                break
            page += 1

        except Exception:
            return all_findings

    return all_findings


def process_single_scan(
    record: dict[str, Any],
    idx: int,
    total: int,
    cookie_string: str,
    findings_limit: int,
    rate_limiter: Optional[RateLimiter] = None,
) -> dict[str, Any]:
    """Process a single scan and fetch its findings (thread worker).

    Creates its own session and closes it in a finally block to prevent leaks.
    """
    asset_name = record.get("asset_name", "Unknown")
    scan_id = record.get("scan_id")

    if not scan_id:
        print(f"  [{idx}/{total}] {asset_name}: ✗ No scan_id")
        return record

    print(f"  [{idx}/{total}] {asset_name} (Scan {scan_id})...")

    session = setup_session(cookie_string)
    try:
        findings = fetch_scan_findings(session, scan_id, findings_limit, rate_limiter)
    finally:
        session.close()

    detailed_record = record.copy()
    detailed_record["detailed_findings"] = findings

    if findings:
        print(f"    ✓ {len(findings)} findings")
    else:
        print("    ℹ No findings")

    return detailed_record


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch detailed IaC findings from Veracode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
How to get your session cookies:
1. Open Chrome/Firefox Developer Tools (F12)
2. Go to the Veracode Platform (analysiscenter.veracode.com)
3. Go to Network tab, refresh the page
4. Click on any request to analysiscenter.veracode.com
5. In Headers, find "Cookie:" and copy the entire value
6. Save it to a file (e.g., cookies.txt)

Examples:
  python fetch_iac_details.py --cookies-file cookies.txt --max-workers 10
  python fetch_iac_details.py --cookies-file cookies.txt --filter-apps "App1,App2"
  python fetch_iac_details.py --cookies-file cookies.txt --output my-iac-findings.json --rate-limit 5
        """,
    )
    parser.add_argument("--output", default="iac-findings.json",
                        help="Output file (default: iac-findings.json)")
    parser.add_argument("--cookies",
                        help="Browser session cookies string")
    parser.add_argument("--cookies-file",
                        help="File containing browser session cookies")
    parser.add_argument("--scan-limit", type=int, default=5000,
                        help="Max scans to fetch (default: 5000)")
    parser.add_argument("--findings-limit", type=int, default=1000,
                        help="Max findings per scan (default: 1000)")
    parser.add_argument("--max-workers", type=int, default=5,
                        help="Concurrent threads (default: 5)")
    parser.add_argument("--rate-limit", type=float, default=10.0,
                        help="Max requests/second (default: 10)")
    parser.add_argument("--filter-apps",
                        help="Comma-separated app names to process")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()

    # --- Validate authentication ---
    if not args.cookies and not args.cookies_file:
        print("ERROR: You must provide either --cookies or --cookies-file")
        sys.exit(1)

    if args.cookies_file:
        try:
            with open(args.cookies_file, "r", encoding="utf-8") as fh:
                cookies_string = fh.read().strip()
        except FileNotFoundError:
            print(f"ERROR: Cookies file not found: {args.cookies_file}")
            sys.exit(1)
        except Exception as exc:
            print(f"ERROR reading cookies file: {exc}")
            sys.exit(1)
    else:
        cookies_string = args.cookies

    if not cookies_string:
        print("ERROR: Cookie string is empty")
        sys.exit(1)

    # --- Banner ---
    print("=" * 70)
    print("  IAC FINDINGS FETCHER")
    print("=" * 70)
    print(f"  Output file  : {args.output}")
    print(f"  Max Workers  : {args.max_workers}")
    print(f"  Rate Limit   : {args.rate_limit} req/sec")
    if args.filter_apps:
        filter_list = [a.strip() for a in args.filter_apps.split(",")]
        print(f"  Filter apps  : {len(filter_list)} application(s)")
    print("=" * 70 + "\n")

    # --- Fetch scan summary ---
    print("Setting up authenticated session...")
    session = setup_session(cookies_string)
    print("✓ Session configured\n")

    rate_limiter = RateLimiter(requests_per_second=args.rate_limit)

    print("=" * 70)
    print("  FETCHING SCAN LIST")
    print("=" * 70 + "\n")

    try:
        records = fetch_iac_summary(session, args.scan_limit, rate_limiter)
    finally:
        session.close()

    if not records:
        print("✗ No scans found or authentication failed\n")
        sys.exit(1)

    # --- Filter by app names ---
    if args.filter_apps:
        filter_names = {name.strip() for name in args.filter_apps.split(",")}
        records = [r for r in records if r.get("asset_name", "") in filter_names]
        print(f"✓ Filtered to {len(records)} scans matching specified apps\n")
        if not records:
            print("✗ No scans match the specified app filter\n")
            return

    # --- Fetch detailed findings concurrently ---
    print("=" * 70)
    print("  FETCHING DETAILED FINDINGS (CONCURRENT)")
    print("=" * 70 + "\n")

    detailed_records: list[dict] = []

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_record = {
            executor.submit(
                process_single_scan,
                record=record, idx=idx, total=len(records),
                cookie_string=cookies_string,
                findings_limit=args.findings_limit,
                rate_limiter=rate_limiter,
            ): record
            for idx, record in enumerate(records, 1)
        }
        for future in as_completed(future_to_record):
            try:
                detailed_records.append(future.result())
            except Exception as exc:
                record = future_to_record[future]
                print(f"    ✗ ERROR processing {record.get('asset_name', 'Unknown')}: {exc}")

    print()

    # --- Save results ---
    print("=" * 70)
    print("  SAVING RESULTS")
    print("=" * 70)

    output_data = {
        "records": detailed_records,
        "metadata": {
            "total_scans": len(detailed_records),
            "total_findings": sum(len(r.get("detailed_findings", [])) for r in detailed_records),
        },
    }

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(output_data, fh, indent=2)

    print(f"✓ Saved to {args.output}")
    print(f"  Total scans: {output_data['metadata']['total_scans']}")
    print(f"  Total findings: {output_data['metadata']['total_findings']}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
