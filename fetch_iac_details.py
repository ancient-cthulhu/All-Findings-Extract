#!/usr/bin/env python3
"""
Fetch detailed IaC findings from Veracode using browser session cookies.

This script automatically fetches the scan summary and then detailed findings for each scan.
Optimized version with concurrent processing and rate limiting.
"""

import argparse
import json
import time
import threading
import requests
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed


def create_optimized_session():
    """Create a session with optimized connection pooling settings."""
    session = requests.Session()
    
    # Configure connection pool
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,  # Number of connection pools
        pool_maxsize=50,      # Max connections per pool
        max_retries=3,        # Retry on transient failures
        pool_block=False      # Don't block if pool is full
    )
    
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    return session


class RateLimiter:
    """Thread-safe rate limiter using token bucket algorithm."""
    
    def __init__(self, requests_per_second=10):
        self.requests_per_second = requests_per_second
        self.tokens = requests_per_second
        self.max_tokens = requests_per_second
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    def acquire(self):
        """Wait until a token is available, then consume it."""
        with self.lock:
            while True:
                now = time.time()
                elapsed = now - self.last_update
                self.tokens = min(self.max_tokens, self.tokens + elapsed * self.requests_per_second)
                self.last_update = now
                
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                
                sleep_time = (1 - self.tokens) / self.requests_per_second
                time.sleep(sleep_time)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Fetch detailed IaC findings from Veracode (Optimized)',
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
  # Fetch detailed IaC findings for all scans (concurrent)
  python fetch_iac_details.py --cookies-file cookies.txt --max-workers 10
  
  # Filter by specific apps
  python fetch_iac_details.py --cookies-file cookies.txt --filter-apps "App1,App2"
  
  # Custom output file with rate limiting
  python fetch_iac_details.py --cookies-file cookies.txt --output my-iac-findings.json --rate-limit 5
        """
    )
    
    # Input/Output files
    parser.add_argument(
        '--output',
        default='iac-findings.json',
        help='Output file for detailed findings (default: iac-findings.json)'
    )
    
    # Authentication
    parser.add_argument(
        '--cookies',
        help='Browser session cookies (copy from Developer Tools)'
    )
    parser.add_argument(
        '--cookies-file',
        help='File containing browser session cookies (recommended)'
    )
    
    # Query parameters
    parser.add_argument(
        '--scan-limit',
        type=int,
        default=5000,
        help='Max scans to fetch (default: 5000)'
    )
    parser.add_argument(
        '--findings-limit',
        type=int,
        default=1000,
        help='Max findings per scan (default: 1000)'
    )
    parser.add_argument(
        '--sleep',
        type=float,
        default=0.01,
        help='Sleep between API pages in same request (default: 0.01)'
    )
    parser.add_argument(
        '--max-workers',
        type=int,
        default=5,
        help='Maximum number of concurrent threads for API requests (default: 5)'
    )
    parser.add_argument(
        '--rate-limit',
        type=float,
        default=10.0,
        help='Maximum API requests per second across all threads (default: 10)'
    )
    parser.add_argument(
        '--filter-apps',
        help='Comma-separated list of app names to process (optional)'
    )
    
    return parser.parse_args()


def setup_session(cookie_string: str) -> requests.Session:
    """Create a session with browser cookies and connection pooling."""
    session = create_optimized_session()
    
    # Parse cookie string and add to session
    for cookie in cookie_string.split(';'):
        cookie = cookie.strip()
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            session.cookies.set(name.strip(), value.strip())
    
    return session


def fetch_iac_summary(session: requests.Session, limit: int = 5000, rate_limiter=None) -> List[Dict]:
    """Fetch IaC summary data (scan list)."""
    base_url = "https://ui.analysiscenter.veracode.com/container-scan-query/v1/scans"
    all_records = []
    page = 0
    
    print("Fetching IaC scan list...")
    
    while True:
        params = {
            'page': page,
            'limit': limit
        }
        
        try:
            if rate_limiter:
                rate_limiter.acquire()
            
            response = session.get(base_url, params=params, timeout=30)
            
            if response.status_code == 401:
                print(f"  ✗ Authentication failed. Cookies may be expired.")
                return []
            
            if response.status_code != 200:
                print(f"  ✗ Error fetching scans: HTTP {response.status_code}")
                return []
            
            data = response.json()
            records = data.get('records', [])
            
            if not records:
                break
            
            all_records.extend(records)
            print(f"  Page {page}: {len(records)} scans (Total: {len(all_records)})")
            
            # Check if there are more pages
            pagination = data.get('pagination', {})
            total_pages = pagination.get('total_pages', 1)
            
            if page >= total_pages - 1:
                break
            
            page += 1
            
        except Exception as e:
            print(f"  ✗ Exception: {e}")
            return all_records
    
    print(f"✓ Found {len(all_records)} total scans\n")
    return all_records


def fetch_scan_findings(session: requests.Session, scan_id: int, limit: int = 1000, rate_limiter=None) -> List[Dict]:
    """Fetch all findings for a specific scan ID."""
    base_url = f"https://ui.analysiscenter.veracode.com/container-scan-query/v1/scans/{scan_id}/findings"
    all_findings = []
    page = 0
    
    while True:
        params = {
            'page': page,
            'limit': limit,
            'sort': 'severity',
            'direction': 'desc'
        }
        
        try:
            if rate_limiter:
                rate_limiter.acquire()
            
            response = session.get(base_url, params=params, timeout=30)
            
            if response.status_code == 401:
                return []
            
            if response.status_code != 200:
                return []
            
            data = response.json()
            findings = data.get('findings', [])
            
            if not findings:
                break
            
            all_findings.extend(findings)
            
            # Check if there are more pages
            pagination = data.get('pagination', {})
            total_pages = pagination.get('total_pages', 1)
            
            if page >= total_pages - 1:
                break
            
            page += 1
            
        except Exception:
            return all_findings
    
    return all_findings


def process_single_scan(record: Dict, idx: int, total: int, cookie_string: str, findings_limit: int, rate_limiter=None) -> Dict:
    """Process a single scan and fetch its findings. Designed for concurrent execution."""
    asset_name = record.get('asset_name', 'Unknown')
    scan_id = record.get('scan_id')
    
    if not scan_id:
        print(f"  [{idx}/{total}] {asset_name}: ✗ No scan_id")
        return record
    
    print(f"  [{idx}/{total}] {asset_name} (Scan {scan_id})...")
    
    # Create a separate session for this thread
    session = setup_session(cookie_string)
    
    # Fetch findings
    findings = fetch_scan_findings(session, scan_id, findings_limit, rate_limiter)
    
    # Create detailed record
    detailed_record = record.copy()
    detailed_record['detailed_findings'] = findings
    
    if findings:
        print(f"    ✓ {len(findings)} findings")
    else:
        print(f"    ℹ No findings")
    
    session.close()
    return detailed_record


def main():
    args = parse_args()
    
    # Validate authentication
    if not args.cookies and not args.cookies_file:
        print("ERROR: You must provide either --cookies or --cookies-file")
        return
    
    # Load cookies
    if args.cookies_file:
        try:
            with open(args.cookies_file, 'r', encoding='utf-8') as f:
                cookies_string = f.read().strip()
        except FileNotFoundError:
            print(f"ERROR: Cookies file not found: {args.cookies_file}")
            return
        except Exception as e:
            print(f"ERROR reading cookies file: {e}")
            return
    else:
        cookies_string = args.cookies
    
    print("=" * 70)
    print("  IAC FINDINGS FETCHER (OPTIMIZED)")
    print("=" * 70)
    print(f"  Output file  : {args.output}")
    print(f"  Max Workers  : {args.max_workers}")
    print(f"  Rate Limit   : {args.rate_limit} req/sec")
    if args.filter_apps:
        filter_list = [a.strip() for a in args.filter_apps.split(',')]
        print(f"  Filter apps  : {len(filter_list)} application(s)")
    print("=" * 70 + "\n")
    
    # Setup session
    print("Setting up authenticated session...")
    session = setup_session(cookies_string)
    print("✓ Session configured\n")
    
    # Initialize rate limiter
    rate_limiter = RateLimiter(requests_per_second=args.rate_limit)
    
    # Fetch scan summary
    print("=" * 70)
    print("  FETCHING SCAN LIST")
    print("=" * 70 + "\n")
    
    records = fetch_iac_summary(session, args.scan_limit, rate_limiter)
    
    if not records:
        print("✗ No scans found or authentication failed\n")
        return
    
    # Filter by app names if specified
    if args.filter_apps:
        filter_names = [name.strip() for name in args.filter_apps.split(',')]
        records = [r for r in records if r.get('asset_name', '') in filter_names]
        print(f"✓ Filtered to {len(records)} scans matching specified apps\n")
        
        if not records:
            print("✗ No scans match the specified app filter\n")
            return
    
    # Fetch detailed findings
    print("=" * 70)
    print("  FETCHING DETAILED FINDINGS (CONCURRENT)")
    print("=" * 70 + "\n")
    
    detailed_records = []
    
    # Process scans concurrently
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        # Submit all scans for processing
        future_to_record = {}
        for idx, record in enumerate(records, 1):
            future = executor.submit(
                process_single_scan,
                record=record,
                idx=idx,
                total=len(records),
                cookie_string=cookies_string,
                findings_limit=args.findings_limit,
                rate_limiter=rate_limiter
            )
            future_to_record[future] = record
        
        # Collect results as they complete
        for future in as_completed(future_to_record):
            try:
                detailed_record = future.result()
                detailed_records.append(detailed_record)
            except Exception as e:
                record = future_to_record[future]
                asset_name = record.get('asset_name', 'Unknown')
                print(f"    ✗ ERROR processing {asset_name}: {e}")
    
    print()
    
    # Save results
    print("=" * 70)
    print("  SAVING RESULTS")
    print("=" * 70)
    
    output_data = {
        'records': detailed_records,
        'metadata': {
            'total_scans': len(detailed_records),
            'total_findings': sum(len(r.get('detailed_findings', [])) for r in detailed_records)
        }
    }
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"✓ Saved to {args.output}")
    print(f"  Total scans: {output_data['metadata']['total_scans']}")
    print(f"  Total findings: {output_data['metadata']['total_findings']}")
    print("=" * 70 + "\n")


if __name__ == '__main__':
    main()
