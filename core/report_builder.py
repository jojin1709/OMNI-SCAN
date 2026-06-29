import os
import json
from datetime import datetime
from colorama import Fore, Style

class ReportBuilder:
    def __init__(self, results, args):
        self.results = results
        self.args = args
        self.output_dir = args.output or f"./output/{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def generate(self):
        os.makedirs(self.output_dir, exist_ok=True)
        formats = self.args.format
        if formats == 'all':
            formats = ['json', 'html', 'markdown', 'txt']
        else:
            formats = [formats] if isinstance(formats, str) else ['json']
        if self.args.verbose:
            print(f"{Fore.CYAN}[*] Generating reports to {self.output_dir}{Style.RESET_ALL}")
        for fmt in formats:
            if fmt == 'json':
                self._generate_json()
            elif fmt == 'html':
                self._generate_html()
            elif fmt == 'markdown':
                self._generate_markdown()
            elif fmt == 'txt':
                self._generate_txt()

    def _generate_json(self):
        json_path = os.path.join(self.output_dir, 'findings.json')
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2)

    def _generate_html(self):
        html_path = os.path.join(self.output_dir, 'report.html')
        vulns = self.results.get('vulnerabilities', [])
        stats = self.results.get('statistics', {})
        scan_info = self.results.get('scan_info', {})
        vulns_html = ''
        for v in vulns[:100]:
            severity = v.get("severity", "info")
            vulns_html += f'''
            <div class="finding {severity}">
                <h3>{v.get("name", "Unknown")}</h3>
                <table>
                    <tr><td><b>Type:</b></td><td>{v.get("type", "unknown")}</td></tr>
                    <tr><td><b>Severity:</b></td><td><span class="badge {severity}">{severity.upper()}</span></td></tr>
                    <tr><td><b>URL:</b></td><td><a href="{v.get("url", "#")}">{v.get("url", "N/A")}</a></td></tr>
                    <tr><td><b>Parameter:</b></td><td>{v.get("parameter", "N/A")}</td></tr>
                    <tr><td><b>Description:</b></td><td>{v.get("description", "N/A")}</td></tr>
                </table>
                {f'<p><b>Payload:</b> <code>{v.get("payload")}</code></p>' if v.get("payload") else ''}
                {f'<p><b>Evidence:</b> <code>{v.get("evidence")}</code></p>' if v.get("evidence") else ''}
            </div>'''
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>OmniScan Report - Security Scan Results</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .stats {{ display: flex; gap: 20px; margin-top: 10px; }}
        .stat-box {{ flex: 1; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-critical {{ background: #e74c3c; color: white; }}
        .stat-high {{ background: #e67e22; color: white; }}
        .stat-medium {{ background: #f1c40f; color: #333; }}
        .stat-low {{ background: #3498db; color: white; }}
        .stat-info {{ background: #95a5a6; color: white; }}
        .finding {{ border: 1px solid #ddd; padding: 20px; margin: 15px 0; border-radius: 5px; }}
        .finding.critical {{ background: #fee; border-left: 5px solid #e74c3c; }}
        .finding.high {{ background: #fff3f0; border-left: 5px solid #e67e22; }}
        .finding.medium {{ background: #fffde6; border-left: 5px solid #f1c40f; }}
        .finding.low {{ background: #ebf5fb; border-left: 5px solid #3498db; }}
        .finding.info {{ background: #f8f9fa; border-left: 5px solid #95a5a6; }}
        table {{ width: 100%; border-collapse: collapse; }}
        td {{ padding: 8px; border-bottom: 1px solid #eee; }}
        td:first-child {{ width: 150px; font-weight: bold; color: #555; }}
        code {{ background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }}
        .badge {{ padding: 3px 10px; border-radius: 10px; font-size: 12px; }}
        .badge.critical {{ background: #e74c3c; color: white; }}
        .badge.high {{ background: #e67e22; color: white; }}
        .badge.medium {{ background: #f1c40f; color: #333; }}
        .badge.low {{ background: #3498db; color: white; }}
        .badge.info {{ background: #95a5a6; color: white; }}
        .no-findings {{ color: #27ae60; font-size: 18px; text-align: center; padding: 40px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔒 OmniScan Report</h1>
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Target(s):</strong> {', '.join(scan_info.get('targets', []))}</p>
        <p><strong>Duration:</strong> {scan_info.get('duration', 0):.1f}s</p>
        <p><strong>Total Requests:</strong> {scan_info.get('total_requests', 0)}</p>
        <p><strong>Detectors Run:</strong> {len(scan_info.get('detectors_run', []))}</p>
        <div class="stats">
            <div class="stat-box stat-critical"><h3>{stats.get("critical", 0)}</h3><p>Critical</p></div>
            <div class="stat-box stat-high"><h3>{stats.get("high", 0)}</h3><p>High</p></div>
            <div class="stat-box stat-medium"><h3>{stats.get("medium", 0)}</h3><p>Medium</p></div>
            <div class="stat-box stat-low"><h3>{stats.get("low", 0)}</h3><p>Low</p></div>
            <div class="stat-box stat-info"><h3>{stats.get("info", 0)}</h3><p>Info</p></div>
        </div>
    </div>
    <h2>🎯 Findings ({len(vulns)})</h2>
    {''.join([f'<div class="no-findings">✅ No vulnerabilities detected</div>' if not vulns else ''])}
    {vulns_html}
    <p style="text-align: center; color: #7f8c8d; margin-top: 30px;">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
</div>
</body>
</html>'''
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def _generate_markdown(self):
        md_path = os.path.join(self.output_dir, 'report.md')
        vulns = self.results.get('vulnerabilities', [])
        md = f'''# OmniScan Report

Generated: {datetime.now().isoformat()}

Total vulnerabilities: {len(vulns)}

## Findings

'''
        for v in vulns[:100]:
            md += f'''### {v.get("name", "Unknown")}

- **Type:** {v.get("type", "unknown")}
- **Severity:** {v.get("severity", "info")}
- **URL:** {v.get("url", "N/A")}
- **Description:** {v.get("description", "N/A")}

'''
        with open(md_path, 'w') as f:
            f.write(md)

    def _generate_txt(self):
        txt_path = os.path.join(self.output_dir, 'summary.txt')
        stats = self.results.get('statistics', {})
        txt = f'''OmniScan Report
===============
Generated: {datetime.now().isoformat()}

Total: {stats.get("total", 0)}
Critical: {stats.get("critical", 0)}
High: {stats.get("high", 0)}
Medium: {stats.get("medium", 0)}
Low: {stats.get("low", 0)}
Info: {stats.get("info", 0)}
'''
        with open(txt_path, 'w') as f:
            f.write(txt)