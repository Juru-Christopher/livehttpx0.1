#!/usr/bin/env python3
"""
Subdomain Live Host Checker - Fast, clean tool for checking live subdomains
"""

import argparse
import sys
import os
import time
import concurrent.futures
import threading
from datetime import datetime
import signal
import json
import csv
import shutil
from typing import List, Dict, Optional
from dataclasses import dataclass

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

__version__ = "1.4.0"
__author__ = "Subdomain Checker Tool"
__license__ = "MIT"

# Thread-safe print for progress
print_lock = threading.Lock()

@dataclass
class TerminalInfo:
    """Container for terminal display information"""
    width: int = 80
    height: int = 24
    supports_color: bool = True
    supports_unicode: bool = True

class ProgressDisplay:
    """Simple progress display manager"""
    def __init__(self, total: int, show_progress: bool = True):
        self.total = total
        self.show_progress = show_progress
        self.checked = 0
        self.found = 0
        self.start_time = time.time()
        self.last_update = 0
    
    def update(self, checked: int, found: int):
        """Update progress counters"""
        self.checked = checked
        self.found = found
        
        if self.show_progress and time.time() - self.last_update > 0.1:
            self._render_progress()
            self.last_update = time.time()
    
    def _render_progress(self):
        """Render simple progress"""
        elapsed = time.time() - self.start_time
        percent = (self.checked / self.total * 100) if self.total > 0 else 0
        
        # Simple progress line
        sys.stdout.write(f"\r\033[KProgress: {self.checked}/{self.total} ({percent:.1f}%) | Found: {self.found} | Time: {elapsed:.1f}s")
        sys.stdout.flush()
    
    def complete(self):
        """Display completion message"""
        if self.show_progress:
            elapsed = time.time() - self.start_time
            sys.stdout.write("\r\033[K")  # Clear line
            print(f"[✓] Scan completed in {elapsed:.1f}s")
            print(f"[✓] Found {self.found} live hosts out of {self.total}")

class SubdomainChecker:
    def __init__(self, timeout: int = 5, max_workers: int = 20, 
                 match_codes: Optional[List[int]] = None, 
                 user_agent: Optional[str] = None, 
                 verify_ssl: bool = True, rate_limit: Optional[int] = None,
                 show_progress: bool = True, no_color: bool = False,
                 show_details: bool = False):
        self.timeout = timeout
        self.max_workers = max_workers
        self.match_codes = match_codes if match_codes else [200, 301, 302, 401, 403]
        self.verify_ssl = verify_ssl
        self.rate_limit = rate_limit
        self.show_progress = show_progress
        self.no_color = no_color
        self.show_details = show_details
        
        # Get terminal info
        self.terminal = self._get_terminal_info()
        
        self.headers = {'User-Agent': user_agent or 
                       'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        self.schemes = ["http://", "https://"]
        self.total_checked = 0
        self.live_hosts = []
        self.found_count = 0
        
        # For rate limiting
        self.semaphore = threading.Semaphore(rate_limit) if rate_limit else None
        self.progress_display = None
        self.last_request_time = 0
    
    def _get_terminal_info(self) -> TerminalInfo:
        """Get terminal information"""
        try:
            columns, lines = shutil.get_terminal_size(fallback=(80, 24))
        except:
            columns, lines = 80, 24
        
        supports_color = not self.no_color and os.getenv('NO_COLOR') is None
        supports_unicode = sys.stdout.encoding.lower().startswith('utf')
        
        return TerminalInfo(
            width=columns,
            height=lines,
            supports_color=supports_color,
            supports_unicode=supports_unicode
        )
    
    def _colorize(self, text: str, color_code: str) -> str:
        """Colorize text if terminal supports it"""
        if self.terminal.supports_color and not self.no_color:
            return f"\033[{color_code}m{text}\033[0m"
        return text
    
    def _rate_limit_wait(self):
        """Implement rate limiting if specified"""
        if self.rate_limit:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            if time_since_last < (1.0 / self.rate_limit):
                time.sleep((1.0 / self.rate_limit) - time_since_last)
            self.last_request_time = time.time()
    
    def check_subdomain(self, host: str) -> Optional[Dict]:
        """Check if a subdomain is live"""
        if self.rate_limit:
            self._rate_limit_wait()
        
        for scheme in self.schemes:
            url = scheme + host
            try:
                response = requests.get(
                    url, 
                    timeout=self.timeout,
                    headers=self.headers,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
                
                status_code = response.status_code
                
                if status_code in self.match_codes:
                    # Extract minimal info by default
                    result = {
                        'url': url,
                        'host': host,
                        'status': status_code,
                        'scheme': scheme.replace('://', '')
                    }
                    
                    # Only extract extra info if details flag is set
                    if self.show_details:
                        result['title'] = self._extract_title(response.text)
                        result['content_length'] = len(response.content)
                        result['server'] = response.headers.get('Server', '')
                    
                    return result
                    
            except (Timeout, ConnectionError, RequestException):
                continue
            except Exception:
                continue
        
        return None
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        try:
            if '<title>' in html.lower():
                title_start = html.lower().find('<title>') + 7
                title_end = html.lower().find('</title>', title_start)
                if title_end > title_start:
                    return html[title_start:title_end].strip()[:100]
        except:
            pass
        return ""
    
    def run_checks(self, subdomains: List[str], output_file: Optional[str] = None,
                  output_format: str = 'txt') -> List[Dict]:
        """Run checks on all subdomains"""
        self.total_subdomains = len(subdomains)
        
        # Initialize progress display
        if self.show_progress:
            self.progress_display = ProgressDisplay(len(subdomains), self.show_progress)
            if self.show_details:
                print(f"[*] Starting detailed scan of {len(subdomains)} subdomains...")
            else:
                print(f"[*] Starting quick scan of {len(subdomains)} subdomains...")
        
        start_time = time.time()
        
        # Sort subdomains alphabetically
        subdomains.sort()
        
        # Use ThreadPoolExecutor for concurrent checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, sub): sub 
                for sub in subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                
                # Update counters
                with print_lock:
                    self.total_checked += 1
                    if result:
                        self.live_hosts.append(result)
                        self.found_count += 1
                    
                    # Update progress display
                    if self.show_progress and self.progress_display:
                        self.progress_display.update(self.total_checked, self.found_count)
        
        elapsed_time = time.time() - start_time
        
        # Complete progress display
        if self.show_progress and self.progress_display:
            self.progress_display.complete()
        
        # Display results
        if self.show_progress:
            self.display_results()
        
        # Save to file if requested
        if output_file:
            self.save_results(output_file, output_format)
        
        return self.live_hosts
    
    def display_results(self):
        """Display results - simple by default, detailed with flag"""
        if not self.live_hosts:
            print("[!] No live hosts found")
            return
        
        print(f"\n{'=' * 60}")
        print(f" LIVE HOSTS ({len(self.live_hosts)} found)")
        print(f"{'=' * 60}")
        
        if self.show_details:
            self._display_detailed_results()
        else:
            self._display_simple_results()
        
        print(f"{'=' * 60}")
    
    def _display_simple_results(self):
        """Display simple list of live URLs only"""
        for host in self.live_hosts:
            print(host['url'])
    
    def _display_detailed_results(self):
        """Display detailed results with all information"""
        # Determine column widths
        url_width = min(40, self.terminal.width - 40)
        
        print(f"{'No.':<4} {'Status':<8} {'URL':<{url_width}} {'Title':<30} {'Size':<8}")
        print(f"{'-' * 80}")
        
        for i, host in enumerate(self.live_hosts, 1):
            # Color code status
            status = str(host['status'])
            if self.terminal.supports_color and not self.no_color:
                if host['status'] < 300:
                    status = self._colorize(status, "92")  # Green
                elif host['status'] < 400:
                    status = self._colorize(status, "93")  # Yellow
                else:
                    status = self._colorize(status, "91")  # Red
            
            # Truncate URL if needed
            url = host['url']
            if len(url) > url_width:
                url = url[:url_width - 3] + "..."
            
            # Get title and size if available
            title = host.get('title', '')[:30]
            size = self._format_size(host.get('content_length', 0))
            
            print(f"{i:<4} {status:<15} {url:<{url_width}} {title:<30} {size:<8}")
    
    def _format_size(self, size: int) -> str:
        """Format file size in human readable format"""
        if size == 0:
            return ""
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f}{unit}"
            size /= 1024.0
        return f"{size:.1f}TB"
    
    def save_results(self, filename: str, format: str = 'txt'):
        """Save results to a file"""
        try:
            if format == 'json':
                self._save_json(filename)
            elif format == 'csv':
                self._save_csv(filename)
            else:  # txt
                self._save_txt(filename)
            
            if self.show_progress:
                print(f"[+] Results saved to: {filename}")
        except Exception as e:
            if self.show_progress:
                print(f"[!] Error saving results: {e}")
    
    def _save_txt(self, filename: str):
        """Save results in text format"""
        with open(filename, 'w') as f:
            # Simple format - just URLs
            for host in self.live_hosts:
                f.write(f"{host['url']}\n")
            
            # Add details if flag was set
            if self.show_details:
                f.write("\n# Detailed information:\n")
                for host in self.live_hosts:
                    f.write(f"{host['url']} - Status: {host['status']}")
                    if 'title' in host:
                        f.write(f" - Title: {host['title']}")
                    f.write("\n")
    
    def _save_json(self, filename: str):
        """Save results in JSON format"""
        results = {
            'metadata': {
                'total_checked': self.total_checked,
                'live_hosts': len(self.live_hosts),
                'show_details': self.show_details
            },
            'results': self.live_hosts
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    
    def _save_csv(self, filename: str):
        """Save results in CSV format"""
        with open(filename, 'w', newline='') as f:
            # Simple CSV with URL only by default
            if self.show_details:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Status', 'Title', 'Content Length', 'Server'])
                for host in self.live_hosts:
                    writer.writerow([
                        host['url'],
                        host['status'],
                        host.get('title', ''),
                        host.get('content_length', ''),
                        host.get('server', '')
                    ])
            else:
                # Just URLs
                for host in self.live_hosts:
                    f.write(f"{host['url']}\n")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\n[!] Interrupted by user")
    sys.exit(0)

def read_subdomains_from_file(filename: str) -> List[str]:
    """Read and clean subdomains from file"""
    subdomains = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Clean the line
                if '://' in line:
                    line = line.split('://')[-1]
                if ':' in line:
                    line = line.split(':')[0]
                line = line.rstrip('/')
                
                subdomains.append(line)
        
        # Remove duplicates
        subdomains = list(set(subdomains))
        
    except FileNotFoundError:
        print(f"[!] File not found: {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)
    
    return subdomains

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description='Fast subdomain live host checker - clean output by default',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Examples:
  {sys.argv[0]} -l subdomains.txt              # Simple scan, URLs only
  {sys.argv[0]} -d example.com                 # Check single domain
  {sys.argv[0]} -l subs.txt --detailed         # Show all details
  {sys.argv[0]} -l subs.txt -o results.txt     # Save URLs to file
  {sys.argv[0]} -l subs.txt --detailed -o results.json  # Save detailed results
        '''
    )
    
    # Required arguments
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l', '--list', metavar='FILE',
                      help='File containing list of subdomains')
    group.add_argument('-d', '--domain', metavar='DOMAIN',
                      help='Single domain to check')
    
    # Output control
    parser.add_argument('-o', '--output', metavar='FILE',
                       help='Output file to save results')
    parser.add_argument('--format', choices=['txt', 'json', 'csv'], default='txt',
                       help='Output format (default: txt)')
    
    # Detail flags - simple interface
    parser.add_argument('--detailed', action='store_true',
                       help='Show detailed output (status codes, titles, sizes)')
    parser.add_argument('--simple', action='store_true',
                       help='Force simple output (URLs only) - this is the default')
    
    # Individual detail flags (can be combined)
    parser.add_argument('--status', action='store_true',
                       help='Show HTTP status codes')
    parser.add_argument('--title', action='store_true',
                       help='Show page titles')
    parser.add_argument('--size', action='store_true',
                       help='Show content sizes')
    parser.add_argument('--numbers', action='store_true',
                       help='Show line numbers')
    
    # Performance arguments
    parser.add_argument('-w', '--workers', type=int, default=20,
                       help='Number of concurrent workers (default: 20)')
    parser.add_argument('-t', '--timeout', type=int, default=5,
                       help='Timeout in seconds (default: 5)')
    parser.add_argument('--rate-limit', type=int, metavar='N',
                       help='Limit requests to N per second')
    
    # Filtering arguments
    parser.add_argument('-mc', '--match-codes', nargs='+', type=int,
                       help='HTTP status codes to consider as live (default: 200 301 302 401 403)')
    
    # Other options
    parser.add_argument('--no-progress', action='store_true',
                       help='Disable progress display')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    parser.add_argument('--silent', action='store_true',
                       help='Suppress all output (except errors)')
    parser.add_argument('--version', action='version',
                       version=f'Subdomain Checker v{__version__}')
    
    args = parser.parse_args()
    
    # Determine if we should show details
    show_details = False
    
    # If --detailed flag is used, enable all details
    if args.detailed:
        show_details = True
    # If --simple flag is used, force simple output (default behavior)
    elif args.simple:
        show_details = False
    # If any individual detail flag is used, enable details
    elif args.status or args.title or args.size or args.numbers:
        show_details = True
    
    # Prepare subdomains list
    subdomains = []
    
    if args.domain:
        subdomains = [args.domain.strip()]
    
    if args.list:
        subdomains = read_subdomains_from_file(args.list)
        if not subdomains:
            print("[!] No valid subdomains found in file")
            sys.exit(1)
    
    # Create checker instance
    checker = SubdomainChecker(
        timeout=args.timeout,
        max_workers=args.workers,
        match_codes=args.match_codes,
        user_agent=None,
        verify_ssl=True,
        rate_limit=args.rate_limit,
        show_progress=not args.silent and not args.no_progress,
        no_color=args.no_color,
        show_details=show_details
    )
    
    # Run checks
    try:
        results = checker.run_checks(subdomains, args.output, args.format)
        
        # Exit with appropriate code
        sys.exit(0 if results else 1)
            
    except KeyboardInterrupt:
        if not args.silent:
            print("\n\n[!] Scan interrupted")
        sys.exit(130)
    except Exception as e:
        if not args.silent:
            print(f"\n[!] Error: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
