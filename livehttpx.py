#!/usr/bin/env python3
"""
livehttpx - Fast Live Host Discovery Tool
Version: v0.1
Written by: gc137001e
"""

import argparse
import sys
import os
import time
import signal
import shutil
from typing import List, Optional

from core import (
    SubdomainChecker, ProgressDisplay, ResultDisplay, OutputParser,
    ScanConfig, ScanStats, TerminalInfo, Color,
    parse_subdomains_from_file, InputError
)

__version__ = "0.1.0"
__author__ = "gc137001e"
__license__ = "MIT"

# ASCII Banner
BANNER = r"""
--------------------------------
	LIVE HTTPX V0.1.0
--------------------------------
"""


def print_banner():
    """Print the tool banner"""
    if not os.getenv('NO_BANNER'):
        print(Color.CYAN + BANNER + Color.RESET)
        print(f"livehttpx v{__version__}")
        print(f"Written by: {__author__} | License: {__license__}")
        print(f"{'-' * 50}\n")


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n\n{Color.YELLOW}[!]{Color.RESET} Scan interrupted by user")
    sys.exit(0)


def get_terminal_info(no_color: bool = False) -> TerminalInfo:
    """Get terminal information"""
    try:
        columns, lines = shutil.get_terminal_size(fallback=(80, 24))
    except:
        columns, lines = 80, 24
    
    supports_color = not no_color and os.getenv('NO_COLOR') is None
    supports_unicode = sys.stdout.encoding.lower().startswith('utf')
    
    return TerminalInfo(
        width=columns,
        height=lines,
        supports_color=supports_color,
        supports_unicode=supports_unicode
    )


def create_config_from_args(args) -> ScanConfig:
    """Create ScanConfig from command line arguments"""
    # Determine match codes
    if args.match_codes:
        match_codes = args.match_codes
    elif args.only_200:
        match_codes = [200]
    elif args.only_success:
        match_codes = [200, 201, 202, 204]
    elif args.only_redirect:
        match_codes = [301, 302, 307, 308]
    elif args.only_auth:
        match_codes = [401, 403]
    else:
        match_codes = [200, 201, 202, 204, 301, 302, 307, 308, 401, 403]
    
    # Determine exclude codes
    exclude_codes = []
    if args.exclude_404:
        exclude_codes.append(404)
    if args.exclude_500:
        exclude_codes.extend([500, 502, 503, 504])
    if args.exclude_codes:
        exclude_codes.extend(args.exclude_codes)
    
    # Determine include codes (overrides match codes)
    include_codes = []
    if args.only_codes:
        include_codes = args.only_codes
    
    # Determine schemes
    only_https = False
    only_http = False
    if args.only_https:
        only_https = True
    elif args.only_http:
        only_http = True
    
    # Determine what to show
    show_details = (
        args.detailed or args.status or args.title or args.size or 
        args.ip or args.time or args.tech or args.cms or args.waf or
        args.cdn or args.headers or args.cookies or args.forms or
        args.logins or args.all_details
    )
    
    # Create custom headers
    custom_headers = {}
    if args.headers:
        for header in args.headers:
            if ':' in header:
                key, value = header.split(':', 1)
                custom_headers[key.strip()] = value.strip()
    
    config = ScanConfig(
        timeout=args.timeout,
        max_workers=args.workers,
        match_codes=match_codes,
        verify_ssl=not args.no_ssl_verify,
        rate_limit=args.rate_limit,
        retries=args.retries,
        follow_redirects=not args.no_redirects,
        tech_detection=args.tech or args.all_details,
        detect_waf=args.waf or args.all_details,
        detect_cms=args.cms or args.all_details,
        detect_cdn=args.cdn or args.all_details,
        extract_headers=args.headers_output or args.all_details,
        extract_cookies=args.cookies or args.all_details,
        find_forms=args.forms or args.all_details,
        find_logins=args.logins or args.all_details,
        random_user_agent=not args.no_user_agent_rotation,
        custom_user_agent=args.user_agent,
        custom_headers=custom_headers,
        proxy=args.proxy,
        exclude_codes=exclude_codes,
        include_codes=include_codes,
        only_https=only_https,
        only_http=only_http,
        show_title=args.title or args.all_details,
        show_size=args.size or args.all_details,
        show_ip=args.ip or args.all_details,
        show_time=args.time or args.all_details,
        show_tech=args.tech or args.all_details
    )
    
    return config


def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description='livehttpx - Fast live host discovery tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Color.CYAN}Examples:{Color.RESET}
  {sys.argv[0]} -l subdomains.txt                    # Simple scan, URLs only
  {sys.argv[0]} -d example.com                       # Check single domain
  {sys.argv[0]} -l subs.txt --detailed              # Show all details
  {sys.argv[0]} -l subs.txt -o results.txt          # Save URLs to file
  {sys.argv[0]} -l subs.txt --tech -o results.json  # Save with tech detection
  {sys.argv[0]} -l subs.txt -w 100 --rate-limit 20  # 100 workers, 20 req/sec
  {sys.argv[0]} -l subs.txt --only-https --cms      # HTTPS only with CMS detection
  {sys.argv[0]} -l subs.txt --proxy http://proxy:8080  # Use proxy
  {sys.argv[0]} -l subs.txt --exclude-404 --exclude-500  # Skip error pages

{Color.CYAN}Quick Tips:{Color.RESET}
  • Use --all-details for comprehensive information
  • Use --rate-limit to avoid getting blocked
  • Use --exclude-404 to skip not found pages
  • Use --only-https for SSL-only scanning
  • Use --proxy for scanning through a proxy server
        '''
    )
    
    # Print banner
    print_banner()
    
    # Input arguments
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-l', '--list', metavar='FILE',
                           help='File containing list of subdomains/domains')
    input_group.add_argument('-d', '--domain', metavar='DOMAIN',
                           help='Single domain to check')
    input_group.add_argument('-i', '--stdin', action='store_true',
                           help='Read domains from stdin')
    
    # Output arguments
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', metavar='FILE',
                            help='Output file to save results')
    output_group.add_argument('--format', choices=['txt', 'json', 'csv', 'md'], 
                            default='txt', help='Output format (default: txt)')
    output_group.add_argument('--output-all', action='store_true',
                            help='Output all results (not just live)')
    
    # Detail flags - comprehensive
    detail_group = parser.add_argument_group('Detail Options')
    detail_group.add_argument('--detailed', action='store_true',
                            help='Show detailed output')
    detail_group.add_argument('--all-details', action='store_true',
                            help='Show all possible details')
    detail_group.add_argument('--simple', action='store_true',
                            help='Force simple output (URLs only)')
    
    # Individual detail flags
    detail_group.add_argument('--status', action='store_true',
                            help='Show HTTP status codes')
    detail_group.add_argument('--title', action='store_true',
                            help='Show page titles')
    detail_group.add_argument('--size', action='store_true',
                            help='Show content sizes')
    detail_group.add_argument('--ip', action='store_true',
                            help='Show IP addresses')
    detail_group.add_argument('--time', action='store_true',
                            help='Show response times')
    detail_group.add_argument('--tech', action='store_true',
                            help='Show detected technologies')
    detail_group.add_argument('--cms', action='store_true',
                            help='Show detected CMS')
    detail_group.add_argument('--waf', action='store_true',
                            help='Show detected WAF')
    detail_group.add_argument('--cdn', action='store_true',
                            help='Show detected CDN')
    detail_group.add_argument('--headers', action='store_true',
                            help='Show response headers')
    detail_group.add_argument('--cookies', action='store_true',
                            help='Show cookies')
    detail_group.add_argument('--forms', action='store_true',
                            help='Show if page has forms')
    detail_group.add_argument('--logins', action='store_true',
                            help='Show if page has login forms')
    
    # Performance arguments
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('-w', '--workers', type=int, default=50,
                          help='Number of concurrent workers (default: 50)')
    perf_group.add_argument('-t', '--timeout', type=int, default=5,
                          help='Timeout in seconds (default: 5)')
    perf_group.add_argument('-r', '--retries', type=int, default=1,
                          help='Number of retries for failed requests (default: 1)')
    perf_group.add_argument('--rate-limit', type=int, metavar='N',
                          help='Limit requests to N per second')
    perf_group.add_argument('--no-user-agent-rotation', action='store_true',
                          help='Disable user agent rotation')
    perf_group.add_argument('--user-agent', metavar='AGENT',
                          help='Custom user agent string')
    
    # Filtering arguments
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument('-mc', '--match-codes', nargs='+', type=int,
                            help='HTTP status codes to consider as live')
    filter_group.add_argument('--exclude-codes', nargs='+', type=int,
                            help='HTTP status codes to exclude')
    filter_group.add_argument('--only-codes', nargs='+', type=int,
                            help='Only include these HTTP status codes')
    filter_group.add_argument('--exclude-404', action='store_true',
                            help='Exclude 404 responses')
    filter_group.add_argument('--exclude-500', action='store_true',
                            help='Exclude 5xx server errors')
    filter_group.add_argument('--only-200', action='store_true',
                            help='Only show 200 OK responses')
    filter_group.add_argument('--only-success', action='store_true',
                            help='Only show successful responses (2xx)')
    filter_group.add_argument('--only-redirect', action='store_true',
                            help='Only show redirect responses (3xx)')
    filter_group.add_argument('--only-auth', action='store_true',
                            help='Only show auth/forbidden responses (401, 403)')
    filter_group.add_argument('--only-https', action='store_true',
                            help='Only check HTTPS URLs')
    filter_group.add_argument('--only-http', action='store_true',
                            help='Only check HTTP URLs')
    
    # Network arguments
    network_group = parser.add_argument_group('Network Options')
    network_group.add_argument('--no-ssl-verify', action='store_true',
                             help='Disable SSL certificate verification')
    network_group.add_argument('--no-redirects', action='store_true',
                             help='Do not follow HTTP redirects')
    network_group.add_argument('--proxy', metavar='URL',
                             help='Use proxy server (http://proxy:port)')
    network_group.add_argument('--headers-output', action='store_true',
                             help='Include headers in output')
    network_group.add_argument('--custom-headers', nargs='+', metavar='HEADER',
                             help='Custom headers (format: "Header: Value")')
    
    # Display arguments
    display_group = parser.add_argument_group('Display Options')
    display_group.add_argument('--progress-style', choices=['bar', 'spinner', 'detailed', 'simple'],
                             default='bar', help='Progress display style (default: bar)')
    display_group.add_argument('--no-progress', action='store_true',
                             help='Disable progress display')
    display_group.add_argument('--no-color', action='store_true',
                             help='Disable colored output')
    display_group.add_argument('--no-banner', action='store_true',
                             help='Do not display banner')
    display_group.add_argument('--silent', action='store_true',
                             help='Suppress all output (except errors)')
    display_group.add_argument('--quiet', action='store_true',
                             help='Only show final results')
    display_group.add_argument('--verbose', action='store_true',
                             help='Show verbose output')
    
    # Other arguments
    parser.add_argument('--version', action='version',
                       version=f'livehttpx v{__version__}')
    
    args = parser.parse_args()
    
    # Set environment variables for display options
    if args.no_banner:
        os.environ['NO_BANNER'] = '1'
    
    # Prepare hosts list
    hosts = []
    
    if args.domain:
        hosts = [args.domain.strip()]
    elif args.list:
        try:
            hosts = parse_subdomains_from_file(args.list)
        except InputError as e:
            print(f"{Color.RED}[!]{Color.RESET} {e}")
            sys.exit(1)
    elif args.stdin:
        try:
            hosts = [line.strip() for line in sys.stdin if line.strip()]
            # Clean domains
            from core.utils import clean_domain, validate_domain
            hosts = [clean_domain(h) for h in hosts]
            hosts = [h for h in hosts if validate_domain(h)]
            if not hosts:
                print(f"{Color.RED}[!]{Color.RESET} No valid domains provided via stdin")
                sys.exit(1)
        except Exception as e:
            print(f"{Color.RED}[!]{Color.RESET} Error reading from stdin: {e}")
            sys.exit(1)
    
    # Create config
    config = create_config_from_args(args)
    
    # Get terminal info
    terminal = get_terminal_info(args.no_color)
    
    # Setup progress display
    progress = None
    if not args.silent and not args.no_progress and not args.quiet:
        progress = ProgressDisplay(
            total=len(hosts),
            show_progress=True,
            style=args.progress_style,
            no_color=args.no_color
        )
        
        if args.verbose:
            print(f"{Color.CYAN}[*]{Color.RESET} Starting scan of {len(hosts)} hosts...")
            print(f"{Color.CYAN}[*]{Color.RESET} Workers: {config.max_workers}, "
                  f"Timeout: {config.timeout}s, Retries: {config.retries}")
            if config.rate_limit:
                print(f"{Color.CYAN}[*]{Color.RESET} Rate limit: {config.rate_limit}/s")
            if config.tech_detection:
                print(f"{Color.CYAN}[*]{Color.RESET} Technology detection enabled")
            if config.detect_cms:
                print(f"{Color.CYAN}[*]{Color.RESET} CMS detection enabled")
            if config.detect_waf:
                print(f"{Color.CYAN}[*]{Color.RESET} WAF detection enabled")
    
    # Create checker
    checker = SubdomainChecker(config)
    
    # Progress callback
    def progress_callback(checked, found, errors):
        if progress:
            progress.update(checked, found, errors)
    
    # Run checks
    try:
        results = checker.run_checks(hosts, progress_callback)
        
        # Complete progress display
        if progress:
            progress.complete(checker.stats)
        
        # Display results if not silent
        if not args.silent and not args.quiet:
            show_details = (
                config.show_title or config.show_size or config.show_ip or 
                config.show_time or config.show_tech or config.detect_cms or
                config.detect_waf or config.detect_cdn or config.extract_headers or
                config.extract_cookies or config.find_forms or config.find_logins
            )
            
            display = ResultDisplay(
                terminal=terminal,
                no_color=args.no_color,
                show_details=show_details,
                max_title_length=args.verbose and 80 or 50
            )
            display.display(results, checker.stats)
        
        # Save results if requested
        if args.output:
            try:
                if args.format == 'json':
                    config_dict = {
                        'timeout': config.timeout,
                        'max_workers': config.max_workers,
                        'match_codes': config.match_codes,
                        'verify_ssl': config.verify_ssl,
                        'rate_limit': config.rate_limit,
                        'retries': config.retries,
                    }
                    OutputParser.save_to_json(results, args.output, config_dict, checker.stats)
                elif args.format == 'csv':
                    OutputParser.save_to_csv(results, args.output, show_details)
                elif args.format == 'md':
                    OutputParser.save_to_markdown(results, args.output, checker.stats)
                else:  # txt
                    OutputParser.save_to_txt(results, args.output, show_details, checker.stats)
                
                if not args.silent:
                    print(f"{Color.GREEN}[+]{Color.RESET} Results saved to: {args.output}")
            except Exception as e:
                if not args.silent:
                    print(f"{Color.RED}[!]{Color.RESET} Error saving results: {e}")
        
        # Exit with appropriate code
        sys.exit(0 if results else 1)
            
    except KeyboardInterrupt:
        if not args.silent:
            print(f"\n\n{Color.YELLOW}[!]{Color.RESET} Scan interrupted")
        sys.exit(130)
    except Exception as e:
        if not args.silent:
            print(f"\n{Color.RED}[!]{Color.RESET} Error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    try:
        import requests
    except ImportError:
        print(f"{Color.RED}[!]{Color.RESET} The 'requests' library is required.")
        print(f"{Color.CYAN}[*]{Color.RESET} Install it with: pip install requests")
        sys.exit(1)
    
    main()