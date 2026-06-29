#!/usr/bin/env python3
"""
OmniScan — All-in-One Bug Bounty & Pentesting Scanner
Targets: SQLi, XSS, RCE, IDOR, PrivEsc, Auth Bypass, Business Logic,
         LFI, RFI, XXE, SSRF, CORS, CSRF, Open Redirect, Secrets Leak,
         File Upload, CSV Injection, AI Model Attacks, and more.

Usage:
    python3 omniscan.py -t https://target.com
    python3 omniscan.py -t targets.txt --all
    python3 omniscan.py -t https://target.com --detectors sqli,xss,ssrf
    python3 omniscan.py -t https://target.com --auth cookie="session=abc123"
    python3 omniscan.py -t https://target.com --callback your-server.com
    python3 omniscan.py -t https://target.com --proxy http://127.0.0.1:8080
"""

import os
import sys
import json
import time
import signal
import logging
import argparse
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init as colorama_init

# Core modules
from core.crawler import SmartCrawler
from core.requester import Requester
from core.auth_manager import AuthManager
from core.plugin_loader import PluginLoader
from core.report_builder import ReportBuilder
from core.callback_server import CallbackServer

# Plugin imports
from detectors.sqli.error_based import SQLErrorBasedDetector
from detectors.sqli.blind_based import SQLBlindDetector
from detectors.sqli.boolean_based import SQLBooleanDetector
from detectors.xss.reflected import XSSReflectedDetector
from detectors.xss.stored import XSSStoredDetector
from detectors.xss.dom_based import XSSDOMDetector
from detectors.rce.command_injection import CommandInjectionDetector
from detectors.rce.template_injection import SSTIDetector
from detectors.rce.deserialization import DeserializationDetector
from detectors.idor.numeric_idor import NumericIDORDetector
from detectors.privilege_escalation.vertical import VerticalPrivEscDetector
from detectors.privilege_escalation.horizontal import HorizontalPrivEscDetector
from detectors.privilege_escalation.jwt_escalation import JWTPrivEscDetector
from detectors.auth_bypass.login_bypass import LoginBypassDetector
from detectors.auth_bypass.otp_bypass import OTPBypassDetector
from detectors.auth_bypass.jwt_none import JWTNoneDetector
from detectors.business_logic.race_condition import RaceConditionDetector
from detectors.business_logic.negative_values import NegativeValueDetector
from detectors.business_logic.rate_limit_bypass import RateLimitBypassDetector
from detectors.lfi_rfi.lfi_basic import LFIBasicDetector
from detectors.lfi_rfi.lfi_wrapper import LFIWrapperDetector
from detectors.lfi_rfi.rfi import RFIDetector
from detectors.sxxe.in_band import XXEInBandDetector
from detectors.sxxe.blind_oob import XXEBlindDetector
from detectors.ssrf.basic_ssrf import SSRFBasicDetector
from detectors.ssrf.blind_ssrf import SSRFBlindDetector
from detectors.ssrf.cloud_metadata import SSRFCloudMetadataDetector
from detectors.cors.wildcard_origin import CORSWildcardDetector
from detectors.cors.origin_reflection import CORSRelfectionDetector
from detectors.csrf.csrf_detector import CSRFDetector
from detectors.open_redirect.param_based import OpenRedirectParamDetector
from detectors.secrets_leak.js_secrets import JSSecretsDetector
from detectors.secrets_leak.git_exposed import GitExposedDetector
from detectors.secrets_leak.source_map import SourceMapDetector
from detectors.file_upload.extension_bypass import FileUploadExtensionDetector
from detectors.file_upload.polyglot import FileUploadPolyglotDetector
from detectors.csv_injection.formula_injection import CSVInjectionDetector
from detectors.ai_model.prompt_injection import PromptInjectionDetector
from detectors.ai_model.prompt_leak import PromptLeakDetector
from detectors.automation.register_bot import RegistrationBot

colorama_init()

# ===== CONFIGURATION =====
VERSION = "1.0.0"
BANNER = f"""
{Fore.RED}
   ____  _   _ __  __ ____  _   _ ____   ____
  / __ _| | | |  \\/  / ___|| | | / ___| / ___|
 | |  | | | | | |\\/| \\___ \\| |_| \\___ \\| |
 | |  | | | | | |  | |___) |  _  |___) | |___
 | \\__/ /_|_|_|_|  |_|____/|_| |_|____/ \\____|
  \\____/        {Fore.CYAN}OmniScan v{VERSION}{Fore.RED}
           The All-in-One Bug Bounty Scanner
{Style.RESET_ALL}
"""

# ===== ARGUMENT PARSER =====
def parse_args():
    parser = argparse.ArgumentParser(
        description="OmniScan — All-in-One Bug Bounty & Pentesting Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        usage="python3 omniscan.py -t <target> [options]"
    )
    parser.add_argument("--version", action="store_true", help="Show version")

    # Target
    target_group = parser.add_argument_group("Target")
    target_group.add_argument("-t", "--target", help="Target URL (e.g., https://target.com)")
    target_group.add_argument("-T", "--targets-file", help="File containing target URLs (one per line)")
    target_group.add_argument("--scope", help="Scope definition file (regex patterns for allowed targets)")

    # Detector selection
    detector_group = parser.add_argument_group("Detector Selection")
    detector_group.add_argument("--all", action="store_true", help="Run ALL detectors")
    detector_group.add_argument("--detectors", help="Comma-separated list: sqli,xss,rce,idor,privesc,auth,logic,lfi,xxe,ssrf,cors,csrf,redirect,secrets,upload,csv,ai")
    detector_group.add_argument("--exclude", help="Comma-separated detectors to exclude")
    detector_group.add_argument("--quick", action="store_true", help="Run only high-signal detectors (fast scan)")
    detector_group.add_argument("--deep", action="store_true", help="Deep scan (all detectors, aggressive)")

    # Authentication
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("--auth-url", help="Login URL")
    auth_group.add_argument("--auth-data", help="Login POST data (user=admin&pass=test)")
    auth_group.add_argument("--auth-type", choices=["form", "basic", "oauth", "jwt", "bearer"], default="form", help="Authentication type")
    auth_group.add_argument("--cookie", help="Session cookie (name=value; name2=value2)")
    auth_group.add_argument("--header", help="Custom header (Name: Value; Name2: Value2)")
    auth_group.add_argument("--token", help="Bearer token or JWT")
    auth_group.add_argument("--auth-script", help="Python script for custom authentication")

    # Scan configuration
    scan_group = parser.add_argument_group("Scan Configuration")
    scan_group.add_argument("--crawl", action="store_true", default=True, help="Crawl the target (default: True)")
    scan_group.add_argument("--max-pages", type=int, default=200, help="Maximum pages to crawl (default: 200)")
    scan_group.add_argument("--depth", type=int, default=3, help="Crawl depth (default: 3)")
    scan_group.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")
    scan_group.add_argument("--delay", type=float, default=0.1, help="Delay between requests in seconds (default: 0.1)")
    scan_group.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    scan_group.add_argument("--retries", type=int, default=2, help="Request retries (default: 2)")

    # Network
    network_group = parser.add_argument_group("Network")
    network_group.add_argument("--proxy", help="Proxy URL (http://127.0.0.1:8080)")
    network_group.add_argument("--proxy-auth", help="Proxy authentication (user:pass)")
    network_group.add_argument("--user-agent", help="Custom user agent")
    network_group.add_argument("--random-agent", action="store_true", help="Rotate user agents")
    network_group.add_argument("--tor", action="store_true", help="Route through Tor")
    network_group.add_argument("--dns-server", help="Custom DNS server")

    # Callback (OOB testing)
    callback_group = parser.add_argument_group("Callback Server (for blind SSRF, XXE, RCE)")
    callback_group.add_argument("--callback", help="External callback server URL (e.g., https://your-server.com)")
    callback_group.add_argument("--callback-port", type=int, default=8888, help="Callback listener port (default: 8888)")
    callback_group.add_argument("--callback-domain", help="Callback domain for DNS-based OOB")

    # Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", "--output", help="Output directory (default: ./output/<target>/)")
    output_group.add_argument("--format", choices=["json", "html", "pdf", "markdown", "txt", "all"], default="all",
                              help="Report format (default: all)")
    output_group.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    output_group.add_argument("--quiet", "-q", action="store_true", help="Quiet mode (no banners)")
    output_group.add_argument("--no-banner", action="store_true", help="Skip banner display")

    # Advanced
    advanced_group = parser.add_argument_group("Advanced")
    advanced_group.add_argument("--fuzz", action="store_true", help="Enable parameter/path fuzzing")
    advanced_group.add_argument("--fuzz-wordlist", help="Custom fuzz wordlist")
    advanced_group.add_argument("--smart-fuzz", action="store_true", help="Smart fuzzing (learns from responses)")
    advanced_group.add_argument("--passive", action="store_true", help="Passive scan only (no intrusive tests)")
    advanced_group.add_argument("--resume", help="Resume scan from saved state file")
    advanced_group.add_argument("--config", help="Custom YAML config file")
    advanced_group.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"], default="info",
                                help="Minimum severity to report (default: info)")
    advanced_group.add_argument("--no-interactive", action="store_true", help="Non-interactive mode")
    advanced_group.add_argument("--update", action="store_true", help="Update payload databases")

    return parser.parse_args()


# ===== MAIN SCANNER ENGINE =====
class OmniScanEngine:
    def __init__(self, args):
        self.args = args
        self.start_time = datetime.now()
        self.targets = []
        self.results = {
            "scan_info": {
                "tool": "OmniScan",
                "version": VERSION,
                "start_time": self.start_time.isoformat(),
                "targets": [],
                "detectors_run": [],
                "total_requests": 0,
                "duration": 0
            },
            "vulnerabilities": [],
            "statistics": {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "by_type": {}
            },
            "raw_findings": []
        }
        self.detectors = []
        self.session = None
        self.crawler = None
        self.requester = None
        self.auth_manager = None
        self.callback_server = None
        self.request_count = 0
        self.should_stop = False

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)

        # Setup logging
        self._setup_logging()

        # Print banner
        if not args.no_banner and not args.quiet:
            print(BANNER)

    def _setup_logging(self):
        level = logging.DEBUG if self.args.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler("omniscan.log")
            ]
        )
        self.log = logging.getLogger("OmniScan")

    def _signal_handler(self, sig, frame):
        self.log.warning("\n[!] Interrupt received. Saving results and exiting...")
        self.should_stop = True
        self._save_partial_results()
        sys.exit(0)

    def load_targets(self):
        if self.args.targets_file:
            with open(self.args.targets_file, "r") as f:
                self.targets = [line.strip() for line in f.readlines() if line.strip() and not line.startswith("#")]
            self.log.info(f"Loaded {len(self.targets)} targets from {self.args.targets_file}")
        elif self.args.target:
            self.targets = [self.args.target]
        else:
            self.log.error("No target specified. Use -t or -T")
            sys.exit(1)

        # Normalize URLs
        self.targets = [t if t.startswith("http") else f"https://{t}" for t in self.targets]

        # Validate
        for t in self.targets:
            parsed = urlparse(t)
            if not parsed.netloc:
                self.log.warning(f"Invalid target URL: {t}")

        self.results["scan_info"]["targets"] = self.targets
        return self.targets

    def initialize_core(self):
        """Initialize core components"""
        self.log.info("Initializing core components...")

        # Requester
        self.requester = Requester(
            proxy=self.args.proxy,
            timeout=self.args.timeout,
            retries=self.args.retries,
            delay=self.args.delay,
            random_agent=self.args.random_agent,
            tor=self.args.tor
        )

        # Auth manager
        self.auth_manager = AuthManager(
            auth_url=self.args.auth_url,
            auth_data=self.args.auth_data,
            auth_type=self.args.auth_type,
            cookie=self.args.cookie,
            header=self.args.header,
            token=self.args.token,
            auth_script=self.args.auth_script
        )

        # Crawler
        self.crawler = SmartCrawler(
            requester=self.requester,
            max_pages=self.args.max_pages,
            depth=self.args.depth,
            threads=self.args.threads
        )

        # Callback server (for OOB attacks)
        if self.args.callback or self.args.callback_domain:
            self.callback_server = CallbackServer(
                callback_url=self.args.callback,
                port=self.args.callback_port,
                domain=self.args.callback_domain
            )
            self.callback_server.start()
            self.log.info(f"Callback server running at {self.args.callback or f'http://0.0.0.0:{self.args.callback_port}'}")

    def load_detectors(self):
        """Load selected detectors based on arguments"""
        self.log.info("Loading detectors...")

        # Determine which detectors to run
        detector_map = self._build_detector_map()
        selected = self._parse_detector_selection()

        for key, detector_class in detector_map.items():
            if key in selected and key not in self._parse_excluded():
                try:
                    detector = detector_class(self)
                    self.detectors.append(detector)
                    self.results["scan_info"]["detectors_run"].append(key)
                    self.log.debug(f"  Loaded detector: {key}")
                except Exception as e:
                    self.log.warning(f"  Failed to load detector {key}: {e}")

        self.log.info(f"Loaded {len(self.detectors)} detectors: {', '.join([d.__class__.__name__ for d in self.detectors])}")

    def _build_detector_map(self):
        """Build complete detector registry"""
        return {
            # SQL Injection
            "sqli_error": SQLErrorBasedDetector,
            "sqli_blind": SQLBlindDetector,
            "sqli_boolean": SQLBooleanDetector,

            # XSS
            "xss_reflected": XSSReflectedDetector,
            "xss_stored": XSSStoredDetector,
            "xss_dom": XSSDOMDetector,

            # RCE
            "rce_cmd": CommandInjectionDetector,
            "rce_ssti": SSTIDetector,
            "rce_deserialize": DeserializationDetector,

            # IDOR
            "idor_numeric": NumericIDORDetector,

            # Privilege Escalation
            "privesc_vertical": VerticalPrivEscDetector,
            "privesc_horizontal": HorizontalPrivEscDetector,
            "privesc_jwt": JWTPrivEscDetector,

            # Auth Bypass
            "auth_login": LoginBypassDetector,
            "auth_otp": OTPBypassDetector,
            "auth_jwt_none": JWTNoneDetector,

            # Business Logic
            "logic_race": RaceConditionDetector,
            "logic_negative": NegativeValueDetector,
            "logic_rate_limit": RateLimitBypassDetector,

            # File Inclusion
            "lfi_basic": LFIBasicDetector,
            "lfi_wrapper": LFIWrapperDetector,
            "rfi": RFIDetector,

            # XXE
            "xxe_inband": XXEInBandDetector,
            "xxe_blind": XXEBlindDetector,

            # SSRF
            "ssrf_basic": SSRFBasicDetector,
            "ssrf_blind": SSRFBlindDetector,
            "ssrf_cloud": SSRFCloudMetadataDetector,

            # CORS
            "cors_wildcard": CORSWildcardDetector,
            "cors_reflection": CORSRelfectionDetector,

            # CSRF
            "csrf": CSRFDetector,

            # Open Redirect
            "redirect": OpenRedirectParamDetector,

            # Secrets
            "secrets_js": JSSecretsDetector,
            "secrets_git": GitExposedDetector,
            "secrets_sourcemap": SourceMapDetector,

            # File Upload
            "upload_ext": FileUploadExtensionDetector,
            "upload_polyglot": FileUploadPolyglotDetector,

            # CSV Injection
            "csv_injection": CSVInjectionDetector,

            # AI Model
            "ai_prompt_injection": PromptInjectionDetector,
            "ai_prompt_leak": PromptLeakDetector,

            # Automation
            "auto_register": RegistrationBot,
        }

    def _parse_detector_selection(self):
        """Parse which detectors to run"""
        # Mapping for human-readable detector categories
        category_map = {
            "sqli": ["sqli_error", "sqli_blind", "sqli_boolean"],
            "xss": ["xss_reflected", "xss_stored", "xss_dom"],
            "rce": ["rce_cmd", "rce_ssti", "rce_deserialize"],
            "idor": ["idor_numeric"],
            "privesc": ["privesc_vertical", "privesc_horizontal", "privesc_jwt"],
            "auth": ["auth_login", "auth_otp", "auth_jwt_none"],
            "logic": ["logic_race", "logic_negative", "logic_rate_limit"],
            "lfi": ["lfi_basic", "lfi_wrapper"],
            "rfi": ["rfi"],
            "xxe": ["xxe_inband", "xxe_blind"],
            "ssrf": ["ssrf_basic", "ssrf_blind", "ssrf_cloud"],
            "cors": ["cors_wildcard", "cors_reflection"],
            "csrf": ["csrf"],
            "redirect": ["redirect"],
            "secrets": ["secrets_js", "secrets_git", "secrets_sourcemap"],
            "upload": ["upload_ext", "upload_polyglot"],
            "csv": ["csv_injection"],
            "ai": ["ai_prompt_injection", "ai_prompt_leak"],
            "auto": ["auto_register"],
        }

        if self.args.all or self.args.deep:
            # Return ALL detectors
            all_detectors = []
            for detectors in category_map.values():
                all_detectors.extend(detectors)
            return all_detectors

        if self.args.quick:
            # High-signal only
            return [
                "sqli_error", "sqli_blind",
                "xss_reflected", "xss_stored",
                "rce_cmd",
                "idor_numeric",
                "secrets_js", "secrets_git",
                "ssrf_basic",
                "cors_wildcard", "cors_reflection",
                "redirect"
            ]

        if self.args.detectors:
            selected = []
            for det in self.args.detectors.split(","):
                det = det.strip().lower()
                if det in category_map:
                    selected.extend(category_map[det])
                elif det in self._build_detector_map():
                    selected.append(det)
            return selected

        # Default: run everything
        all_detectors = []
        for detectors in category_map.values():
            all_detectors.extend(detectors)
        return all_detectors

    def _parse_excluded(self):
        if not self.args.exclude:
            return []
        excluded = []
        for det in self.args.exclude.split(","):
            det = det.strip().lower()
            category_map = {
                "sqli": ["sqli_error", "sqli_blind", "sqli_boolean"],
                "xss": ["xss_reflected", "xss_stored", "xss_dom"],
                "rce": ["rce_cmd", "rce_ssti", "rce_deserialize"],
                "idor": ["idor_numeric"],
                "privesc": ["privesc_vertical", "privesc_horizontal", "privesc_jwt"],
                "auth": ["auth_login", "auth_otp", "auth_jwt_none"],
                "logic": ["logic_race", "logic_negative", "logic_rate_limit"],
                "lfi": ["lfi_basic", "lfi_wrapper"],
                "xxe": ["xxe_inband", "xxe_blind"],
                "ssrf": ["ssrf_basic", "ssrf_blind", "ssrf_cloud"],
                "cors": ["cors_wildcard", "cors_reflection"],
                "csrf": ["csrf"],
                "redirect": ["redirect"],
                "secrets": ["secrets_js", "secrets_git", "secrets_sourcemap"],
                "upload": ["upload_ext", "upload_polyglot"],
                "csv": ["csv_injection"],
                "ai": ["ai_prompt_injection", "ai_prompt_leak"],
                "auto": ["auto_register"],
            }
            if det in category_map:
                excluded.extend(category_map[det])
            else:
                excluded.append(det)
        return excluded

    def run_scan(self):
        """Main scan orchestration"""
        self.log.info(f"Starting scan against {len(self.targets)} target(s)")
        self.log.info(f"Running {len(self.detectors)} detectors")

        # Step 1: Authenticate (if needed)
        if self.args.auth_url or self.args.cookie or self.args.token:
            self.log.info("Authenticating...")
            self.auth_manager.authenticate()
            self.requester.set_session(self.auth_manager.get_session())
            self.log.info("Authentication complete")

        # Step 2: Crawl targets
        endpoints = []
        if self.args.crawl:
            self.log.info(f"Crawling targets (max {self.args.max_pages} pages, depth {self.args.depth})...")
            for target in self.targets:
                crawled = self.crawler.crawl(target)
                endpoints.extend(crawled)
                self.log.info(f"  Crawled {len(crawled)} endpoints from {target}")
        else:
            # Just use the target URLs directly
            endpoints = self.targets

        # Deduplicate endpoints
        endpoints = list(set(endpoints))
        self.log.info(f"Total unique endpoints: {len(endpoints)}")

        # Step 3: Run detectors
        self.log.info("Running detectors...")
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = []
            for detector in self.detectors:
                self.log.info(f"  Starting {detector.__class__.__name__}...")
                future = executor.submit(detector.run, endpoints)
                futures.append((detector.__class__.__name__, future))

            for name, future in futures:
                try:
                    findings = future.result(timeout=3600)  # 1 hour max per detector
                    for finding in findings:
                        self._add_finding(finding)
                    self.log.info(f"  {name} complete: {len(findings)} findings")
                except Exception as e:
                    self.log.error(f"  {name} failed: {e}")

        # Step 4: Stop callback server
        if self.callback_server:
            self.callback_server.stop()

        # Step 5: Generate report
        self._finalize_results()
        self._generate_report()

        # Step 6: Print summary
        self._print_summary()

    def _add_finding(self, finding):
        """Add a vulnerability finding to results"""
        severity = finding.get("severity", "info").lower()
        vuln_type = finding.get("type", "unknown")

        self.results["vulnerabilities"].append(finding)
        self.results["statistics"]["total"] += 1
        self.results["statistics"]["by_type"][vuln_type] = self.results["statistics"]["by_type"].get(vuln_type, 0) + 1

        if severity == "critical":
            self.results["statistics"]["critical"] += 1
        elif severity == "high":
            self.results["statistics"]["high"] += 1
        elif severity == "medium":
            self.results["statistics"]["medium"] += 1
        elif severity == "low":
            self.results["statistics"]["low"] += 1
        else:
            self.results["statistics"]["info"] += 1

        # Print finding immediately
        severity_colors = {
            "critical": Fore.RED + Style.BRIGHT,
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.BLUE,
            "info": Fore.CYAN
        }
        color = severity_colors.get(severity, Fore.WHITE)
        print(f"\n{color}[{severity.upper()}]{Style.RESET_ALL} {finding.get('name', 'Unknown')}")
        print(f"     URL: {finding.get('url', 'N/A')}")
        print(f"     Type: {vuln_type}")
        print(f"     Description: {finding.get('description', 'N/A')}")
        if finding.get("payload"):
            print(f"     Payload: {finding.get('payload')}")
        if finding.get("evidence"):
            print(f"     Evidence: {finding.get('evidence')[:200]}")

    def _finalize_results(self):
        """Finalize scan results"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        self.results["scan_info"]["end_time"] = end_time.isoformat()
        self.results["scan_info"]["duration"] = duration
        self.results["scan_info"]["total_requests"] = self.requester.request_count if self.requester else 0

    def _generate_report(self):
        """Generate output reports"""
        self.log.info("Generating reports...")
        report_builder = ReportBuilder(self.results, self.args)
        report_builder.generate()

    def _print_summary(self):
        """Print scan summary"""
        s = self.results["statistics"]
        duration = self.results["scan_info"]["duration"]
        requests = self.results["scan_info"]["total_requests"]

        print(f"\n{'='*60}")
        print(f"{Fore.GREEN}SCAN COMPLETE{Style.RESET_ALL}")
        print(f"{'='*60}")
        print(f"  Targets:         {len(self.targets)}")
        print(f"  Detectors Run:   {len(self.detectors)}")
        print(f"  Total Requests:  {requests}")
        print(f"  Duration:        {duration:.1f}s")
        print(f"  Vulnerabilities: {s['total']}")
        print(f"    {Fore.RED}{Style.BRIGHT}Critical:{Style.RESET_ALL} {s['critical']}")
        print(f"    {Fore.RED}High:{Style.RESET_ALL}     {s['high']}")
        print(f"    {Fore.YELLOW}Medium:{Style.RESET_ALL}   {s['medium']}")
        print(f"    {Fore.BLUE}Low:{Style.RESET_ALL}      {s['low']}")
        print(f"    {Fore.CYAN}Info:{Style.RESET_ALL}     {s['info']}")
        print(f"  By Type:")
        for vuln_type, count in sorted(s["by_type"].items(), key=lambda x: x[1], reverse=True):
            print(f"    - {vuln_type}: {count}")
        print(f"{'='*60}")
        print(f"  Report saved to: {self.args.output or f'./output/{urlparse(self.targets[0]).netloc}/'}")
        print(f"{'='*60}")

    def _save_partial_results(self):
        """Save partial results on interrupt"""
        self._finalize_results()
        partial_path = f"omniscan_partial_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(partial_path, "w") as f:
            json.dump(self.results, f, indent=2)
        self.log.info(f"Partial results saved to {partial_path}")


# ===== ENTRY POINT =====
def main():
    args = parse_args()

    if args.version:
        print(f"OmniScan v{VERSION}")
        sys.exit(0)

    # Validate
    if not args.target and not args.targets_file:
        print(f"{Fore.RED}[!] Error: No target specified. Use -t or -T{Style.RESET_ALL}")
        print(f"    Usage: python3 omniscan.py -t https://target.com")
        sys.exit(1)

    # Create engine and run
    engine = OmniScanEngine(args)
    engine.load_targets()
    engine.initialize_core()
    engine.load_detectors()
    engine.run_scan()


if __name__ == "__main__":
    main()