#!/usr/bin/env python3
"""
Fetch detailed IaC findings from Veracode using browser session cookies.

This script automatically fetches the scan summary and then detailed findings for each scan.
"""

import argparse
import json
import time
import requests
from typing import List, Dict


def parse_args():
    parser = argparse.ArgumentParser(
        description='Fetch detailed IaC findings from Veracode',
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
  # Fetch detailed IaC findings for all scans
  python fetch_iac_details.py --cookies-file cookies.txt
  
  # Filter by specific apps
  python fetch_iac_details.py --cookies-file cookies.txt --filter-apps "App1,App2"
  
  # Custom output file
  python fetch_iac_details.py --cookies-file cookies.txt --output my-iac-findings.json
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
        default=0.5,
        help='Sleep between API calls in seconds (default: 0.5)'
    )
    parser.add_argument(
        '--filter-apps',
        help='Comma-separated list of app names to process (optional)'
    )
    
    return parser.parse_args()


def setup_session(cookie_string: str) -> requests.Session:
    """Create a session with browser cookies."""
    session = requests.Session()
    
    # Parse cookie string and add to session
    for cookie in cookie_string.split(';'):
        cookie = cookie.strip()
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            session.cookies.set(name.strip(), value.strip())
    
    return session


def fetch_iac_summary(session: requests.Session, limit: int = 5000) -> List[Dict]:
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
    
    print(f"✓ Found {len(all_records)} total scans\\n")
    return all_records


def fetch_scan_findings(session: requests.Session, scan_id: int, limit: int = 1000) -> List[Dict]:
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
    print("  IAC FINDINGS FETCHER")
    print("=" * 70)
    print(f"  Output file: {args.output}")
    if args.filter_apps:
        filter_list = [a.strip() for a in args.filter_apps.split(',')]
        print(f"  Filter apps: {len(filter_list)} application(s)")
    print("=" * 70 + "\\n")
    
    # Setup session
    print("Setting up authenticated session...")
    session = setup_session(cookies_string)
    print("✓ Session configured\\n")
    
    # Fetch scan summary
    print("=" * 70)
    print("  FETCHING SCAN LIST")
    print("=" * 70 + "\\n")
    
    records = fetch_iac_summary(session, args.scan_limit)
    
    if not records:
        print("✗ No scans found or authentication failed\\n")
        return
    
    # Filter by app names if specified
    if args.filter_apps:
        filter_names = [name.strip() for name in args.filter_apps.split(',')]
        records = [r for r in records if r.get('asset_name', '') in filter_names]
        print(f"✓ Filtered to {len(records)} scans matching specified apps\\n")
        
        if not records:
            print("✗ No scans match the specified app filter\\n")
            return
    
    # Fetch detailed findings
    print("=" * 70)
    print("  FETCHING DETAILED FINDINGS")
    print("=" * 70 + "\\n")
    
    detailed_records = []
    
    for idx, record in enumerate(records, 1):
        asset_name = record.get('asset_name', 'Unknown')
        scan_id = record.get('scan_id')
        
        if not scan_id:
            print(f"  [{idx}/{len(records)}] {asset_name}: ✗ No scan_id")
            continue
        
        print(f"  [{idx}/{len(records)}] {asset_name} (Scan {scan_id})...")
        
        # Fetch findings
        findings = fetch_scan_findings(session, scan_id, args.findings_limit)
        
        # Create detailed record
        detailed_record = record.copy()
        detailed_record['detailed_findings'] = findings
        detailed_records.append(detailed_record)
        
        if findings:
            print(f"    ✓ {len(findings)} findings")
        else:
            print(f"    ℹ No findings")
        
        # Sleep between requests
        if idx < len(records):
            time.sleep(args.sleep)
    
    print()
    
    # Step 3: Save results
    print("=" * 70)
    print("  STEP 3: SAVING RESULTS")
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
    print("=" * 70 + "\\n")


if __name__ == '__main__':
    main()
