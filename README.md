LIVE HTTPX
text

             LIVE HTTPX
           livehttpx v0.1.0
Written by: gc137001e | License: MIT
-------------------------------------

livehttpx is a fast, feature-rich live host discovery tool written in Python. It checks a list of domains/subdomains and identifies which ones that are live (responding to HTTP/HTTPS requests) with comprehensive detection capabilities.
✨ Features

    ⚡ Fast & Concurrent: Multi-threaded scanning with configurable worker count

    🔍 Comprehensive Detection:

        HTTP status code analysis

        Page title extraction

        Content size measurement

        Response time tracking

        IP address resolution

    🌐 Network Options:

        Proxy support

        Custom headers

        Rate limiting

    🎯 Flexible Filtering: Filter by HTTP status codes, content types, and more

    💾 Multiple Output Formats:

        TXT

        JSON

        CSV

        Markdown export

    🎨 Beautiful Output: Colored terminal output with progress indicators

Technology Stack Analysis

    Web technology detection (frameworks, libraries)

    CMS detection (WordPress, Joomla, Drupal, etc.)

    WAF (Web Application Firewall) detection

    CDN identification

📦 Installation
Prerequisites

    Python 3.6 or higher

    pip (Python package manager)

Quick Install
bash

# Clone the repository
git clone https://github.com/gc137001e/livehttpx.git
cd livehttpx

# Install dependencies
pip install -r requirements.txt

# Make it executable (optional)
chmod +x livehttpx.py

Dependencies

The tool requires the following Python packages:

    requests - HTTP requests library

    Additional dependencies listed in requirements.txt

🚀 Usage
Basic Usage
bash

# Scan domains from a file
python livehttpx.py -l domains.txt

# Scan a single domain
python livehttpx.py -d example.com

# Read from stdin
cat domains.txt | python livehttpx.py -i

Advanced Examples
bash

# Comprehensive scan with all details
python livehttpx.py -l domains.txt --all-details

# Technology detection only
python livehttpx.py -l domains.txt --tech --cms --waf

# HTTPS-only scan
python livehttpx.py -l domains.txt --only-https

# Save results to JSON
python livehttpx.py -l domains.txt --tech -o results.json --format json

# High-performance scan (100 workers, rate limited)
python livehttpx.py -l domains.txt -w 100 --rate-limit 20

# Filter out 404 and 500 errors
python livehttpx.py -l domains.txt --exclude-404 --exclude-500

# Use proxy server
python livehttpx.py -l domains.txt --proxy http://proxy:8080

📋 Command Line Options
Input Options
text

-l, --list FILE      File containing list of subdomains/domains
-d, --domain DOMAIN  Single domain to check
-i, --stdin          Read domains from stdin

Output Options
text

-o, --output FILE    Output file to save results
--format FORMAT      Output format: txt, json, csv, md (default: txt)
--output-all         Output all results (not just live)

Detail Options
text

--detailed           Show detailed output
--all-details        Show all possible details
--simple             Force simple output (URLs only)
--status             Show HTTP status codes
--title              Show page titles
--size               Show content sizes
--ip                 Show IP addresses
--time               Show response times
--tech               Show detected technologies
--cms                Show detected CMS
--waf                Show detected WAF
--cdn                Show detected CDN
--headers            Show response headers
--cookies            Show cookies
--forms              Show if page has forms
--logins             Show if page has login forms

Performance Options
text

-w, --workers N      Number of concurrent workers (default: 50)
-t, --timeout N      Timeout in seconds (default: 5)
-r, --retries N      Number of retries for failed requests (default: 1)
--rate-limit N       Limit requests to N per second
--no-user-agent-rotation  Disable user agent rotation
--user-agent AGENT   Custom user agent string

Filtering Options
text

-mc, --match-codes CODE [CODE ...]  HTTP status codes to consider as live
--exclude-codes CODE [CODE ...]     HTTP status codes to exclude
--only-codes CODE [CODE ...]        Only include these HTTP status codes
--exclude-404                       Exclude 404 responses
--exclude-500                       Exclude 5xx server errors
--only-200                          Only show 200 OK responses
--only-success                      Only show successful responses (2xx)
--only-redirect                     Only show redirect responses (3xx)
--only-auth                         Only show auth/forbidden responses (401, 403)
--only-https                        Only check HTTPS URLs
--only-http                         Only check HTTP URLs

Network Options
text

--no-ssl-verify      Disable SSL certificate verification
--no-redirects       Do not follow HTTP redirects
--proxy URL          Use proxy server (http://proxy:port)
--headers-output     Include headers in output
--custom-headers HEADER [HEADER ...]  Custom headers (format: "Header: Value")

Display Options
text

--progress-style STYLE  Progress display style: bar, spinner, detailed, simple
--no-progress        Disable progress display
--no-color           Disable colored output
--no-banner          Do not display banner
--silent             Suppress all output (except errors)
--quiet              Only show final results
--verbose            Show verbose output

📖 Examples
Example 1: Basic Domain Discovery
bash

# Check which subdomains are live
python livehttpx.py -l subdomains.txt

# Output:
# [+] Found 15/100 live hosts
# https://www.example.com [200] [4.2KB] [WordPress] [123ms]
# https://api.example.com [200] [1.1KB] [REST API] [89ms]
# https://blog.example.com [301 → https://www.example.com/blog] [2.3KB] [87ms]

Example 2: Technology Stack Analysis
bash

# Discover technologies used by live hosts
python livehttpx.py -l targets.txt --tech --cms --waf --output tech_report.json --format json

Example 3: Security-Oriented Scan
bash

# Find authentication endpoints and admin panels
python livehttpx.py -l domains.txt --only-auth --forms --logins --timeout 10

⚙️ Configuration
Custom Headers
bash

# Add custom headers to requests
python livehttpx.py -l domains.txt --custom-headers "X-API-Key: mykey" "Authorization: Bearer token"

Rate Limiting
bash

# Avoid rate limiting by target servers
python livehttpx.py -l domains.txt --rate-limit 10 -w 20

Proxy Usage
bash

# Scan through a proxy
python livehttpx.py -l domains.txt --proxy http://127.0.0.1:8080

📊 Output Formats
Text Format (Default)
text

https://example.com [200 OK] [Welcome Page] [15.2KB] [192.0.2.1] [234ms]

JSON Format
json

{
  "config": {
    "timeout": 5,
    "max_workers": 50,
    "match_codes": [200, 201, 202, 204, 301, 302, 307, 308, 401, 403]
  },
  "stats": {
    "total": 100,
    "checked": 100,
    "live": 23,
    "errors": 4,
    "time_taken": 12.5
  },
  "results": [
    {
      "url": "https://example.com",
      "status": 200,
      "title": "Welcome Page",
      "size": 15564,
      "ip": "192.0.2.1",
      "response_time": 0.234,
      "technologies": ["nginx", "PHP", "jQuery"],
      "cms": "WordPress",
      "waf": "Cloudflare"
    }
  ]
}

CSV Format
csv

URL,Status,Title,Size,IP,Response Time,Technologies,CMS,WAF
https://example.com,200,Welcome Page,15564,192.0.2.1,0.234,"nginx,PHP,jQuery",WordPress,Cloudflare

🤝 Contributing

Contributions are welcome! Here's how you can help:

    Fork the repository

    Create a feature branch

    Commit your changes

    Push to the branch

    Open a Pull Request

Development Setup
bash

# Clone and setup development environment
git clone https://github.com/gc137001e/livehttpx.git
cd livehttpx
pip install -r requirements.txt

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
🙏 Acknowledgments

    Inspired by various host discovery and web reconnaissance tools

    Thanks to the open-source community for libraries and tools

    Special thanks to contributors and users

⚠️ Disclaimer

This tool is intended for legal security testing and reconnaissance purposes only. The user is responsible for complying with all applicable laws and regulations. Use this tool only on systems you own or have explicit permission to test.

DO NOT use this tool for:

    Unauthorized penetration testing

    Scanning systems without permission

    Any illegal activities

The author assumes no liability and is not responsible for any misuse or damage caused by this tool.

Author: gc137001e
Project Link: https://github.com/Juru-Christopher/livehttpx0.1.0

⭐ If you find this tool useful, please consider giving it a star on GitHub! ⭐
