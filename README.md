# 🚀 OmniScan — All-in-One Bug Bounty & Pentesting Scanner

**Developed by JOJIN JOHN**

---

**OmniScan** is an all-in-one web application security scanner built specifically for bug bounty hunters and penetration testers. It detects **18 vulnerability classes** in one unified scan — SQLi, XSS, RCE, IDOR, Privilege Escalation, Auth Bypass, Business Logic Flaws, LFI/RFI, XXE, SSRF, CORS, CSRF, Open Redirect, Secrets Leaks, File Upload bugs, CSV Injection, and AI Model attacks.

---

## 📋 Table of Contents

1. [Features](#-features)
2. [Vulnerabilities Detected](#-vulnerabilities-detected)
3. [Installation](#-installation)
4. [Quick Start](#-quick-start)
5. [Usage Guide](#-usage-guide)
6. [Commands Reference](#-commands-reference)
7. [Project Structure](#-project-structure)
8. [License](#-license)

---

## 🎯 Features

- **40+ vulnerability detectors** running in parallel
- **Smart crawling** — discovers endpoints, forms, API routes, JS files, and hidden parameters
- **Authentication support** — form login, cookies, JWT, OAuth, bearer tokens, custom auth scripts
- **Callback server** — built-in HTTP/DNS listener for blind SSRF, XXE, and RCE confirmation
- **Multi-threaded** — configurable threads for fast scanning
- **Proxy support** — Burp Suite, ZAP, or any HTTP/SOCKS proxy
- **Tor support** — route traffic through Tor for anonymity
- **Multiple output formats** — JSON, HTML, Markdown, TXT

---

## 🛡️ Vulnerabilities Detected

| # | Vulnerability | Category |
|---|---------------|----------|
| 1 | SQL Injection | sqli |
| 2 | Cross-Site Scripting | xss |
| 3 | Remote Code Execution | rce |
| 4 | IDOR | idor |
| 5 | Privilege Escalation | privesc |
| 6 | Auth Bypass | auth |
| 7 | Business Logic Errors | logic |
| 8 | LFI/RFI | lfi/rfi |
| 9 | XXE | xxe |
| 10 | SSRF | ssrf |
| 11 | CORS | cors |
| 12 | CSRF | csrf |
| 13 | Open Redirect | redirect |
| 14 | Secrets Leak | secrets |
| 15 | File Upload | upload |
| 16 | CSV Injection | csv |
| 17 | AI Model Attacks | ai |

---

## 💾 Installation

### Prerequisites

```bash
# Python 3.8+
python3 --version

# pip
pip3 --version

# Git
git --version
```

### Install on Kali Linux

```bash
# Clone the repository
git clone https://github.com/jojin1709/OMNI-SCAN.git
cd OMNI-SCAN

# Install all dependencies
pip3 install -r requirements.txt
```

### Install on Ubuntu/Debian

```bash
git clone https://github.com/jojin1709/OMNI-SCAN.git
cd OMNI-SCAN
pip3 install -r requirements.txt
```

### Core Dependencies

```bash
pip3 install requests urllib3 beautifulsoup4 lxml html5lib colorama tqdm pyyaml
```

### Crawling & Parsing

```bash
pip3 install selenium playwright cssutils jsbeautifier
playwright install chromium
```

### Network

```bash
pip3 install dnspython aiohttp httpx
```

---

## 🚀 Quick Start

### Basic Scan

```bash
python3 omniscan.py -t https://target.com --all
```

### Quick Scan (High-Signal Only)

```bash
python3 omniscan.py -t https://target.com --quick
```

### With Authentication

```bash
python3 omniscan.py -t https://target.com --cookie "sessionid=abc123" --all
```

### Multiple Targets

```bash
echo "https://target1.com" > targets.txt
echo "https://target2.com" >> targets.txt
python3 omniscan.py -T targets.txt --all
```

---

## 📖 Usage Guide

### Command Structure

```bash
python3 omniscan.py -t <TARGET> [OPTIONS]
python3 omniscan.py -T <TARGETS_FILE> [OPTIONS]
```

### Target Options

| Option | Description | Example |
|--------|-------------|---------|
| `-t, --target` | Single target URL | `-t https://example.com` |
| `-T, --targets-file` | File with target URLs | `-T targets.txt` |
| `--scope` | Scope definition (regex) | `--scope "*.example.com"` |

### Detector Selection Options

| Option | Description |
|--------|-------------|
| `--all` | Run ALL detectors (full scan) |
| `--quick` | Run only high-signal detectors (fast) |
| `--detectors` | Comma-separated list: sqli,xss,rce,idor,privesc,auth,logic,lfi,xxe,ssrf,cors,csrf,redirect,secrets,upload,csv,ai |
| `--exclude` | Comma-separated detectors to skip |
| `--passive` | Passive scan only |

### Scan Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--crawl` | True | Crawl the target before scanning |
| `--max-pages` | 200 | Maximum pages to crawl |
| `--depth` | 3 | Crawl depth |
| `--threads` | 20 | Number of concurrent threads |
| `--delay` | 0.1 | Delay between requests (seconds) |
| `--timeout` | 15 | Request timeout (seconds) |

---

## 🔧 Commands Reference

### Basic Commands

```bash
# Help
python3 omniscan.py --help

# Version
python3 omniscan.py --version

# Scan single target
python3 omniscan.py -t https://example.com --all
```

### Detector Selection Examples

```bash
# Run specific detectors
python3 omniscan.py -t https://example.com --detectors sqli,xss,ssrf

# Exclude detectors
python3 omniscan.py -t https://example.com --all --exclude csrf,redirect
```

### Authentication Examples

```bash
# Form login
python3 omniscan.py -t https://example.com \
    --auth-url https://example.com/login \
    --auth-data "email=test@test.com&password=Test123!"

# Cookie-based session
python3 omniscan.py -t https://example.com \
    --cookie "PHPSESSID=abc123; security_level=high"
```

### Proxy Examples

```bash
# Through Burp Suite
python3 omniscan.py -t https://example.com --proxy http://127.0.0.1:8080

# Through SOCKS5 proxy
python3 omniscan.py -t https://example.com --proxy socks5://127.0.0.1:9050
```

### Output Examples

```bash
# Save to specific directory
python3 omniscan.py -t https://example.com -o ./results/

# Generate JSON report
python3 omniscan.py -t https://example.com --format json

# Filter by minimum severity
python3 omniscan.py -t https://example.com --severity high
```

---

## 🏗️ Project Structure

```
omniscan/
├── omniscan.py             # Main entry point
├── core/                   # Core modules
│   ├── crawler.py
│   ├── requester.py
│   ├── auth_manager.py
│   ├── report_builder.py
│   └── callback_server.py
├── detectors/              # 40 vulnerability detectors
│   ├── sqli/
│   ├── xss/
│   ├── rce/
│   └── ...
├── payloads/               # Payload databases
└── README.md
```

---

## 📄 License

**Copyright (c) 2026 JOJIN JOHN. All Rights Reserved.**

OmniScan is proprietary software. Unauthorized copying, modification, or distribution is prohibited. See LICENSE file for full terms.

---

## ⚠️ Legal Notice

OmniScan is designed for authorized security testing only. Always obtain explicit written permission before testing any system you do not own. Unauthorized scanning may violate computer fraud laws in your jurisdiction.