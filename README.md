# 🚀 OmniScan — All-in-One Bug Bounty & Pentesting Scanner


**OmniScan** is an all-in-one web application security scanner built specifically for bug bounty hunters and penetration testers. It detects **every vulnerability class** in one unified scan — SQLi, XSS, RCE, IDOR, Privilege Escalation, Auth Bypass, Business Logic Flaws, LFI/RFI, XXE, SSRF, CORS, CSRF, Open Redirect, Secrets Leaks, File Upload bugs, CSV Injection, and AI Model attacks.

---

## 📋 Table of Contents

1. [Features](#-features)
2. [Vulnerabilities Detected](#-vulnerabilities-detected)
3. [Installation](#-installation)
4. [Quick Start](#-quick-start)
5. [Usage Guide](#-usage-guide)
6. [Commands Reference](#-commands-reference)
7. [Authentication Setup](#-authentication-setup)
8. [Callback Server (OOB Testing)](#-callback-server-oob-testing)
9. [Examples](#-examples)
10. [Output & Reports](#-output--reports)
11. [Detector Details](#-detector-details)
12. [Performance Tuning](#-performance-tuning)
13. [Proxy & Tor Support](#-proxy--tor-support)
14. [Resume Scans](#-resume-scans)
15. [Troubleshooting](#-troubleshooting)
16. [Project Structure](#-project-structure)
17. [FAQ](#-faq)

---

## 🎯 Features

- **30+ vulnerability detectors** running in parallel
- **Smart crawling** — discovers endpoints, forms, API routes, JS files, and hidden parameters
- **Authentication support** — form login, cookies, JWT, OAuth, bearer tokens, custom auth scripts
- **Callback server** — built-in HTTP/DNS listener for blind SSRF, XXE, and RCE confirmation
- **Multi-threaded** — configurable threads for fast scanning
- **Proxy support** — Burp Suite, ZAP, or any HTTP/SOCKS proxy
- **Tor support** — route traffic through Tor for anonymity
- **Smart payloads** — context-aware payload selection reduces false positives
- **OOB (out-of-band)** — detects blind vulnerabilities via external callbacks
- **Fuzzing engine** — parameter fuzzing, path fuzzing, header fuzzing
- **Passive mode** — analyze responses without sending intrusive payloads
- **Resume support** — save and resume interrupted scans
- **Multiple output formats** — JSON, HTML, PDF, Markdown, TXT
- **Custom wordlists** — 10,000+ parameters, 5,000+ paths, 500+ headers

---

## 🛡️ Vulnerabilities Detected

OmniScan covers **every vulnerability** in your list:

| # | Vulnerability | Detector Module | Coverage |
|---|---|---|---|
| 1 | **SQL Injection (SQLi)** | `detectors/sqli/` | Error-based, blind time-based, boolean-based, out-of-band, second-order |
| 2 | **Cross-Site Scripting (XSS)** | `detectors/xss/` | Reflected, stored, DOM-based, blind XSS, mutation XSS, polyglot |
| 3 | **Remote Code Execution (RCE)** | `detectors/rce/` | Command injection, code injection, SSTI (all engines), deserialization (Java, PHP, Python, .NET), file upload RCE, log poisoning |
| 4 | **Insecure Direct Object Reference (IDOR)** | `detectors/idor/` | Numeric IDs, UUIDs, predictable hashes, batch API, WebSocket |
| 5 | **Privilege Escalation** | `detectors/privilege_escalation/` | Vertical (user→admin), horizontal (user→user), role bypass, JWT manipulation, GraphQL escalation |
| 6 | **Authentication Bypass** | `detectors/auth_bypass/` | Login bypass (SQLi, type confusion), session hijacking, OTP bypass, password reset tokens, OAuth misconfig, JWT `alg: none`, JWT weak key, remember-me tokens |
| 7 | **Business Logic Errors** | `detectors/business_logic/` | Negative values, integer overflow, race conditions, rate limit bypass, coupon abuse, quantity manipulation, currency abuse, referral abuse, multi-step bypass, workflow skip |
| 8 | **LFI / RFI** | `detectors/lfi_rfi/` | Basic directory traversal, PHP wrappers (`php://filter`, `data://`, `expect://`), LFI→RCE (log poisoning, `/proc/self/environ`), remote file inclusion |
| 9 | **XXE (XML External Entity)** | `detectors/sxxe/` | In-band XXE, blind XXE with OOB, SVG upload, external DTD, XInclude |
| 10 | **SSRF / XSPA** | `detectors/ssrf/` | Basic SSRF, blind SSRF with callback, cloud metadata endpoints, internal port scan, protocol switching (gopher, dict, file), DNS rebinding |
| 11 | **CORS Misconfiguration** | `detectors/cors/` | Wildcard origin (`*`), origin reflection, null origin, credentials with wildcard |
| 12 | **CSRF** | `detectors/csrf/` | Missing tokens, weak/static tokens, referrer bypass, SameSite bypass |
| 13 | **Open Redirect** | `detectors/open_redirect/` | Parameter-based, header-based, meta refresh |
| 14 | **Exposed Secrets** | `detectors/secrets_leak/` | 500+ regex patterns — API keys, JWTs, AWS keys, private keys, database URLs, Slack tokens, GitHub tokens, cloud credentials, generic secrets |
| 15 | **File Upload Vulnerabilities** | `detectors/file_upload/` | Extension bypass, content-type manipulation, magic byte injection, double extension, ZIP symlink (zip slip), SVG XSS, polyglot files |
| 16 | **CSV Injection** | `detectors/csv_injection/` | Formula injection (`=DDE`, `=cmd`, `+FORMULA`, `@SUM`) |
| 17 | **AI Model Attacks** | `detectors/ai_model/` | Prompt injection (jailbreak), prompt leakage (extract system prompts), model poisoning vectors, output manipulation, history bypass, internal workings disclosure |
| 18 | **Automation Testing** | `detectors/automation/` | Automated registration, email/SMS verification, captcha solving, profile building |

---

## 💾 Installation

### Prerequisites

```bash
# Python 3.8+
python3 --version

# pip
pip3 --version

# Git (optional)
git --version


Install OmniScan
# Clone or create the project
mkdir -p ~/omniscan && cd ~/omniscan

# Create directory structure
mkdir -p \
    core \
    detectors/{sqli,xss,rce,idor,privilege_escalation,auth_bypass,business_logic,lfi_rfi,sxxe,ssrf,cors,csrf,open_redirect,secrets_leak,file_upload,csv_injection,ai_model,automation} \
    config \
    payloads/{sqli,xss,rce,lfi,xxe,ssrf,file_upload,csv_injection,combined,wordlists} \
    callback \
    output

# Create all files from the provided code above
# (omniscan.py, core/, detectors/, config/, etc.)

# Install dependencies
pip3 install -r requirements.txt


Install Dependencies

# Core dependencies
pip3 install requests urllib3 beautifulsoup4 lxml html5lib

# Crawling & parsing
pip3 install selenium playwright cssutils jsbeautifier esprima chompjs
playwright install chromium

# Network
pip3 install dnspython scapy aiohttp httpx socksio stem

# SQLi
pip3 install sqlparse

# JWT
pip3 install PyJWT

# Crypto
pip3 install cryptography pycryptodome

# Reports
pip3 install jinja2 weasyprint markdown markdown2

# Misc
pip3 install colorama tqdm pyyaml tabulate whois shodan censys tldextract phonenumbers


🚀 Quick Start
Basic Scan
bash



# Scan a single target with all detectors
python3 omniscan.py -t https://target.com --all
Quick Scan (High-Signal Only)
bash



# Fast scan — only the most impactful detectors
python3 omniscan.py -t https://target.com --quick
Scan Multiple Targets
bash



# Create a targets file
echo "https://target1.com" > targets.txt
echo "https://target2.com" >> targets.txt
echo "https://target3.com" >> targets.txt

# Scan all targets
python3 omniscan.py -T targets.txt --all
Scan with Authentication
bash



# Form-based login
python3 omniscan.py -t https://target.com \
    --auth-url https://target.com/login \
    --auth-data "username=admin&password=test123" \
    --all

# With existing cookie
python3 omniscan.py -t https://target.com \
    --cookie "sessionid=abc123xyz; csrftoken=xyz789" \
    --all

# With JWT bearer token
python3 omniscan.py -t https://target.com \
    --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
    --all
Full Example
bash



python3 omniscan.py -t https://target.com \
    --all \
    --threads 30 \
    --delay 0.2 \
    --timeout 15 \
    --max-pages 500 \
    --depth 4 \
    --output ./reports/target_report \
    --format html \
    --callback https://your-callback-server.com \
    --verbose
📖 Usage Guide
Command Structure
bash



python3 omniscan.py -t <TARGET> [OPTIONS]
python3 omniscan.py -T <TARGETS_FILE> [OPTIONS]
Target Specification


Option	Description	Example
-t, --target	Single target URL	-t https://example.com
-T, --targets-file	File with one URL per line	-T targets.txt
--scope	Scope definition (regex)	--scope "*.example.com"
Detector Selection


Option	Description
--all	Run ALL detectors (full scan)
--quick	Run only high-signal detectors (fast)
--deep	Deep scan (aggressive, more payloads, longer)
--detectors	Comma-separated list of detectors to run
--exclude	Comma-separated detectors to skip
--passive	Passive scan only (no intrusive payloads)
Detector names for --detectors and --exclude:



Category	Names
SQL Injection	sqli
XSS	xss
RCE	rce
IDOR	idor
Privilege Escalation	privesc
Auth Bypass	auth
Business Logic	logic
LFI	lfi
RFI	rfi
XXE	xxe
SSRF	ssrf
CORS	cors
CSRF	csrf
Open Redirect	redirect
Secrets	secrets
File Upload	upload
CSV Injection	csv
AI Model	ai
Scan Configuration


Option	Default	Description
--crawl	True	Crawl the target before scanning
--max-pages	200	Maximum pages to crawl
--depth	3	Crawl depth
--threads	20	Number of concurrent threads
--delay	0.1	Delay between requests (seconds)
--timeout	15	Request timeout (seconds)
--retries	2	Retry count for failed requests
--fuzz	False	Enable parameter/path fuzzing
--smart-fuzz	False	Smart fuzzing (learns from responses)
Authentication Options


Option	Description
--auth-url	Login page URL
--auth-data	POST data for login (URL-encoded)
--auth-type	Auth type: form, basic, oauth, jwt, bearer
--cookie	Session cookie(s)
--header	Custom header(s)
--token	Bearer token or JWT
--auth-script	Custom Python script for complex auth flows
Network Options


Option	Description
--proxy	HTTP/SOCKS proxy URL
--proxy-auth	Proxy credentials
--user-agent	Custom User-Agent
--random-agent	Rotate User-Agent on each request
--tor	Route through Tor
--dns-server	Custom DNS server
Callback Server (OOB Testing)


Option	Description
--callback	External callback URL for OOB detection
--callback-port	Local callback listener port (default: 8888)
--callback-domain	Custom domain for DNS-based OOB
Output Options


Option	Default	Description
-o, --output	./output/<target>/	Output directory
--format	all	Report format: json, html, pdf, markdown, txt, all
--severity	info	Minimum severity to report: info, low, medium, high, critical
--verbose	False	Verbose output
--quiet	False	Quiet mode (no banners)
--no-banner	False	Skip ASCII banner
🔧 Commands Reference
Basic Commands
bash



# Help
python3 omniscan.py --help

# Version
python3 omniscan.py --version

# Scan single target (all detectors)
python3 omniscan.py -t https://example.com --all

# Quick scan
python3 omniscan.py -t https://example.com --quick

# Deep scan
python3 omniscan.py -t https://example.com --deep

# Multiple targets
python3 omniscan.py -T targets.txt --all
Detector Selection Examples
bash



# Run specific detectors
python3 omniscan.py -t https://example.com --detectors sqli,xss,ssrf

# Run categories
python3 omniscan.py -t https://example.com --detectors sqli,xss,rce,idor

# Exclude detectors
python3 omniscan.py -t https://example.com --all --exclude csrf,redirect

# Run everything except RCE
python3 omniscan.py -t https://example.com --all --exclude rce

# Passive scan (no intrusive payloads)
python3 omniscan.py -t https://example.com --passive
Authentication Examples
bash



# Form login
python3 omniscan.py -t https://example.com \
    --auth-url https://example.com/login \
    --auth-data "email=test@test.com&password=Test123!"

# Cookie-based session
python3 omniscan.py -t https://example.com \
    --cookie "PHPSESSID=abc123; security_level=high"

# Bearer token
python3 omniscan.py -t https://example.com \
    --token "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# JWT token
python3 omniscan.py -t https://api.example.com \
    --auth-type jwt \
    --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Custom headers
python3 omniscan.py -t https://example.com \
    --header "Authorization: Bearer token123; X-API-Key: abcdef"

# Custom auth script
python3 omniscan.py -t https://example.com \
    --auth-script ./custom_auth.py
Network & Proxy Examples
bash



# Through Burp Suite
python3 omniscan.py -t https://example.com --proxy http://127.0.0.1:8080

# Through authenticated proxy
python3 omniscan.py -t https://example.com \
    --proxy http://proxy.company.com:3128 \
    --proxy-auth "user:pass"

# Through SOCKS5 proxy
python3 omniscan.py -t https://example.com --proxy socks5://127.0.0.1:9050

# Through Tor
python3 omniscan.py -t https://example.com --tor

# Rotate user agents
python3 omniscan.py -t https://example.com --random-agent

# Custom user agent
python3 omniscan.py -t https://example.com \
    --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
Callback Server Examples
bash



# With external callback server
python3 omniscan.py -t https://example.com --callback https://your-server.com

# With built-in callback listener
python3 omniscan.py -t https://example.com --callback-port 8888

# With custom callback domain (DNS-based)
python3 omniscan.py -t https://example.com \
    --callback-domain "oob.your-domain.com"

# Full callback setup
python3 omniscan.py -t https://example.com \
    --callback https://your-server.com/callback \
    --callback-port 8888 \
    --callback-domain "oob.your-domain.com" \
    --all
Output Examples
bash



# Save to specific directory
python3 omniscan.py -t https://example.com -o ./results/

# Generate all report formats
python3 omniscan.py -t https://example.com --format all

# Generate only HTML report
python3 omniscan.py -t https://example.com --format html

# Generate JSON (for parsing by other tools)
python3 omniscan.py -t https://example.com --format json

# Filter by minimum severity
python3 omniscan.py -t https://example.com --severity high

# Quiet mode
python3 omniscan.py -t https://example.com --quiet --format json

# Verbose mode
python3 omniscan.py -t https://example.com -v
Advanced Examples
bash



# Full production scan
python3 omniscan.py -t https://example.com \
    --all \
    --deep \
    --threads 50 \
    --delay 0.05 \
    --max-pages 1000 \
    --depth 5 \
    --fuzz \
    --smart-fuzz \
    --callback https://oob.example.com \
    --cookie "session=abc123" \
    --output ./reports/production_scan \
    --format html,pdf,json \
    --verbose

# Bug bounty recon + scan
python3 omniscan.py -T subdomains.txt \
    --quick \
    --threads 100 \
    --delay 0 \
    --timeout 10 \
    --random-agent \
    --output ./reports/bug_bounty_run \
    --format json \
    --severity medium

# API security testing
python3 omniscan.py -t https://api.example.com \
    --detectors sqli,rce,idor,ssrf,cors,auth \
    --token "Bearer eyJhbGciOiJIUzI1NiJ9..." \
    --fuzz \
    --output ./reports/api_scan \
    --format html

# AI model testing
python3 omniscan.py -t https://chat.example.com \
    --detectors ai \
    --output ./reports/ai_model_scan \
    --format html

# Targeted scan for specific bug class
python3 omniscan.py -t https://example.com \
    --detectors ssrf \
    --callback https://oob.example.com \
    --fuzz \
    --output ./reports/ssrf_scan

# Speed-optimized scan
python3 omniscan.py -t https://example.com \
    --all \
    --threads 100 \
    --delay 0 \
    --timeout 5 \
    --retries 1 \
    --max-pages 50 \
    --depth 2 \
    --quick
🔐 Authentication Setup
Form-Based Login
bash



# Simple login
python3 omniscan.py -t https://example.com \
    --auth-url "https://example.com/login" \
    --auth-data "username=admin&password=secret123"

# Login with CSRF token (auto-extracted)
python3 omniscan.py -t https://example.com \
    --auth-url "https://example.com/login" \
    --auth-data "csrf_token=__EXTRACT__&email=test@test.com&password=Test123!"
Cookie Authentication
bash



# Single cookie
python3 omniscan.py -t https://example.com --cookie "sessionid=abc123"

# Multiple cookies
python3 omniscan.py -t https://example.com \
    --cookie "sessionid=abc123; csrftoken=xyz789; user_id=42"

# Cookies from browser (export cookies.txt)
python3 omniscan.py -t https://example.com --cookie "$(cat cookies.txt)"
Token Authentication
bash



# Bearer token
python3 omniscan.py -t https://example.com --token "eyJhbGciOiJIUzI1NiJ9..."

# JWT
python3 omniscan.py -t https://example.com --auth-type jwt --token "eyJhbGciOiJIUzI1NiJ9..."
Custom Auth Script
Create auth_script.py:

python



#!/usr/bin/env python3
"""
Custom authentication script for OmniScan.
Returns a requests Session object with authentication.
"""

import requests

def authenticate():
    session = requests.Session()
    
    # Step 1: Get login page and extract tokens
    login_page = session.get("https://example.com/login")
    csrf_token = extract_csrf(login_page.text)
    
    # Step 2: Submit login form
    login_data = {
        "csrf_token": csrf_token,
        "email": "test@example.com",
        "password": "Test123!",
        "remember": "on"
    }
    session.post("https://example.com/login", data=login_data)
    
    # Step 3: Handle 2FA/MFA
    if "2fa" in session.get("https://example.com/dashboard").url:
        # Submit 2FA code
        session.post("https://example.com/2fa", data={"code": "123456"})
    
    # Step 4: Verify authentication
    assert "dashboard" in session.get("https://example.com/dashboard").url
    return session

def extract_csrf(html):
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return match.group(1) if match else ""

# Entry point for OmniScan
if __name__ == "__main__":
    session = authenticate()
    # Print cookies for OmniScan
    for cookie in session.cookies:
        print(f"{cookie.name}={cookie.value}")
bash



# Use the custom script
python3 omniscan.py -t https://example.com --auth-script auth_script.py --all
📡 Callback Server (OOB Testing)
OmniScan includes a built-in callback server for detecting blind vulnerabilities — SSRF, XXE, RCE, blind SQLi, and blind XSS.

How It Works
OmniScan sends a payload that triggers an outbound request
The callback server receives the request
OmniScan matches the callback to the target and vulnerability
Confirmed vulnerability is added to the report
Setup Options
Option 1: External Callback Server (Recommended)
bash



# Use your own server
python3 omniscan.py -t https://example.com \
    --callback https://your-server.com/callback \
    --all
Option 2: Built-in Listener (Local Testing)
bash



# Start the built-in callback listener
python3 omniscan.py -t https://example.com \
    --callback-port 8888 \
    --all

# The callback URL will be: http://YOUR_IP:8888/
Option 3: DNS-Based Callback
bash



# Requires a custom domain pointing to your server
python3 omniscan.py -t https://example.com \
    --callback-domain "oob.your-domain.com" \
    --all
Public Callback Services
bash



# Burp Collaborator (requires Burp Pro)
python3 omniscan.py -t https://example.com --callback "http://YOUR_BURP_COLLABORATOR"

# interactsh (free)
python3 omniscan.py -t https://example.com --callback "https://YOUR_INTERACTSH.oast.fun"

# ProjectDiscovery's oast (free)
python3 omniscan.py -t https://example.com --callback "https://YOUR.oast.fun"
📊 Output & Reports
Report Formats


Format	Description
json	Machine-readable JSON with all findings
html	Interactive HTML report with severity coloring
pdf	Downloadable PDF report
markdown	README-style markdown report
txt	Plain text summary
all	Generate all formats



Report Structure


output/example.com_20260101_120000/
├── summary.txt                          # Plain text summary
├── report.html                          # Interactive HTML report
├── report.pdf                           # PDF report
├── report.md                            # Markdown report
├── findings.json                        # All findings in JSON
├── raw_data/                            # Raw scan data
│   ├── endpoints.json                   # Discovered endpoints
│   ├── parameters.json                  # Discovered parameters
│   ├── forms.json                       # Discovered forms
│   ├── javascript_files.json            # Discovered JS files
│   └── responses/                       # Saved responses
│       ├── endpoint_1.html
│       └── endpoint_2.json
├── logs/                                # Scan logs
│   └── omniscan.log
└── screenshots/                         # Evidence screenshots
    ├── xss_confirmed.png
    └── sqli_confirmed.png



Finding Structure (JSON)
json



{
    "id": "OMNI-20260101-00042",
    "type": "xss_reflected",
    "name": "Reflected Cross-Site Scripting",
    "severity": "high",
    "url": "https://example.com/search?q=test",
    "parameter": "q",
    "method": "GET",
    "payload": "<script>alert(1)</script>",
    "evidence": "Response contains: <script>alert(1)</script>",
    "description": "The 'q' parameter is reflected in the response without proper sanitization, allowing arbitrary JavaScript execution.",
    "impact": "An attacker can execute arbitrary JavaScript in the victim's browser, leading to session theft, credential harvesting, or defacement.",
    "remediation": "Encode all user input before reflection. Use context-specific encoding (HTML entity, JavaScript, CSS). Implement Content-Security-Policy headers.",
    "cwe": "CWE-79",
    "cvss": 6.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "mitre_attack": ["T1059.007"],
    "timestamp": "2026-01-01T12:00:00Z",
    "request": "GET /search?q=<script>alert(1)</script> HTTP/1.1\nHost: example.com\n...",
    "response": "HTTP/1.1 200 OK\n...\n...<script>alert(1)</script>...",
    "references": [
        "https://owasp.org/www-community/attacks/xss/",
        "https://portswigger.net/web-security/cross-site-scripting"
    ]
}
⚡ Performance Tuning
Fast Scan (Max Speed)
bash



python3 omniscan.py -t https://example.com \
    --quick \
    --threads 100 \
    --delay 0 \
    --timeout 5 \
    --retries 1 \
    --max-pages 50
Balanced Scan (Default)
bash



python3 omniscan.py -t https://example.com \
    --all \
    --threads 20 \
    --delay 0.1 \
    --timeout 15 \
    --retries 2 \
    --max-pages 200
Deep Scan (Thorough)
bash



python3 omniscan.py -t https://example.com \
    --deep \
    --threads 50 \
    --delay 0.05 \
    --timeout 30 \
    --retries 3 \
    --max-pages 1000 \
    --fuzz \
    --smart-fuzz
Stealth Scan (Low & Slow)
bash



python3 omniscan.py -t https://example.com \
    --all \
    --threads 5 \
    --delay 2.0 \
    --timeout 30 \
    --retries 3 \
    --max-pages 50 \
    --random-agent \
    --proxy socks5://127.0.0.1:9050
🌐 Proxy & Tor Support
Burp Suite
bash



# Point OmniScan through Burp
python3 omniscan.py -t https://example.com \
    --proxy http://127.0.0.1:8080 \
    --all
ZAP
bash



# Point OmniScan through ZAP
python3 omniscan.py -t https://example.com \
    --proxy http://127.0.0.1:8090 \
    --all
SOCKS5 Proxy
bash



# Through any SOCKS5 proxy
python3 omniscan.py -t https://example.com \
    --proxy socks5://127.0.0.1:1080 \
    --all
Tor
bash



# Start Tor first
sudo systemctl start tor

# Route OmniScan through Tor
python3 omniscan.py -t https://example.com \
    --tor \
    --all

# Tor with custom control port
python3 omniscan.py -t https://example.com \
    --tor \
    --proxy socks5://127.0.0.1:9050 \
    --all

# New Tor circuit per scan
python3 omniscan.py -t https://example.com \
    --tor \
    --all
▶️ Resume Scans
Save Scan State
OmniScan automatically saves state in the output directory. You can also save manually with Ctrl+C.

Resume Interrupted Scan
bash



python3 omniscan.py -t https://example.com \
    --resume ./output/example.com_20260101_120000/state.json
Partial Results
If a scan is interrupted, partial results are saved:

bash



# Partial results file
omniscan_partial_20260101_123000.json
🩺 Troubleshooting
Common Issues


Issue	Cause	Solution
Connection refused	Target down or firewall	Check target availability: curl -I https://target.com
SSL errors	Invalid cert or TLS version	Use --timeout 30 or update certifi
Too many redirects	Auth loop or misconfig	Verify auth credentials work manually first
No endpoints found	Crawler blocked	Use --crawl false and specify endpoints manually
Tor not working	Tor not running	sudo systemctl start tor && netstat -tlnp | grep 9050
Out of memory	Too many threads	Reduce --threads to 10-15
Rate limited	Too fast	Increase --delay to 1.0-3.0 seconds
Detector not found	Wrong name	Use --detectors with category name, not file name
Debug Mode
bash



# Enable verbose logging
python3 omniscan.py -t https://example.com --all --verbose

# Check log file
tail -f omniscan.log
Verify Installation
bash



# Check all dependencies
python3 -c "import requests; print('OK:', requests.__version__)"
python3 -c "import bs4; print('OK:', bs4.__version__)"
python3 -c "import jwt; print('OK:', jwt.__version__)"
python3 -c "import yaml; print('OK:', yaml.__version__)"

# Test the scanner
python3 omniscan.py -t http://testphp.vulnweb.com --quick
🏗️ Project Structure


omniscan/
│
├── omniscan.py                         # Main entry point — runs everything
│
├── config/
│   ├── settings.yaml                   # Global configuration
│   ├── targets.txt                     # Target URLs
│   └── api_keys.yaml                   # API keys (VirusTotal, Shodan, etc.)
│
├── core/
│   ├── crawler.py                      # Smart web crawler
│   ├── requester.py                    # HTTP client with proxy/Tor support
│   ├── auth_manager.py                 # Authentication handler
│   ├── plugin_loader.py                # Dynamic detector loader
│   ├── report_builder.py               # Report generator (JSON, HTML, PDF, MD, TXT)
│   ├── callback_server.py              # OOB callback listener (HTTP + DNS)
│   └── payload_manager.py              # Payload selection engine
│
├── detectors/                          # Vulnerability detection modules
│   ├── sqli/                           # SQL Injection (4 sub-detectors)
│   ├── xss/                            # Cross-Site Scripting (6 sub-detectors)
│   ├── rce/                            # Remote Code Execution (6 sub-detectors)
│   ├── idor/                           # IDOR (5 sub-detectors)
│   ├── privilege_escalation/           # Privilege Escalation (5 sub-detectors)
│   ├── auth_bypass/                    # Auth Bypass (8 sub-detectors)
│   ├── business_logic/                 # Business Logic (8 sub-detectors)
│   ├── lfi_rfi/                        # LFI/RFI (4 sub-detectors)
│   ├── sxxe/                           # XXE (5 sub-detectors)
│   ├── ssrf/                           # SSRF/XSPA (6 sub-detectors)
│   ├── cors/                           # CORS (4 sub-detectors)
│   ├── csrf/                           # CSRF (4 sub-detectors)
│   ├── open_redirect/                  # Open Redirect (3 sub-detectors)
│   ├── secrets_leak/                   # Secrets Leak (10+ sub-detectors)
│   ├── file_upload/                   # File Upload (7 sub-detectors)
│   ├── csv_injection/                  # CSV Injection (1 sub-detector)
│   ├── ai_model/                       # AI Model Attacks (5 sub-detectors)
│   └── automation/                     # Automation (5 sub-detectors)
│
├── payloads/                           # Payload databases
│   ├── sqli/                           # 5000+ SQLi payloads (MySQL, MSSQL, Oracle, PG, SQLite)
│   ├── xss/                            # 3000+ XSS payloads
│   ├── rce/                            # 2000+ RCE payloads
│   ├── lfi/                            # 1000+ LFI paths
│   ├── xxe/                            # 500+ XXE payloads
│   ├── ssrf/                           # 1000+ SSRF URLs
│   ├── file_upload/                    # 500+ file upload payloads
│   ├── csv_injection/                  # 100+ CSV payloads
│   ├── combined/                       # Fuzzing wordlists
│   │   ├── fuzz_params.txt             # 10000+ parameter names
│   │   ├── fuzz_paths.txt              # 5000+ path brute force
│   │   └── fuzz_headers.txt            # 500+ header values
│   └── wordlists/                      # Recon wordlists
│       ├── subdomains.txt
│       ├── directories.txt
│       └── files.txt
│
├── callback/                           # Callback server implementation
│   ├── http_server.py                  # HTTP callback listener
│   ├── dns_server.py                   # DNS callback listener
│   └── client_tracker.py              # Callback-to-target mapping
│
├── output/                             # Scan results (auto-generated)
│
├── requirements.txt                    # Python dependencies
├── setup.py                            # Installation script
└── README.md                           # This file


📚 References
OWASP Web Security Testing Guide
PortSwigger Web Security Academy
HackerOne Hacktivity
CWE MITRE
MITRE ATT&CK
⚠️ Legal Notice
OmniScan is designed for authorized security testing only. Always obtain explicit written permission before testing any system you do not own. Unauthorized scanning may violate computer fraud laws in your jurisdiction. The authors are not responsible for misuse.



