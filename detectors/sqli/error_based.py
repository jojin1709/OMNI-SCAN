from detectors.__init__ import DetectorBase

class SQLErrorBasedDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        sqli_payloads = ["' OR '1'='1", "' OR '1'='1'--", "' UNION SELECT NULL--", "' AND '1'='1"]
        error_patterns = ["SQL syntax", "MySQL server", "ORA-", "sqlite_", "PG::", "syntax error"]
        for endpoint in endpoints[:50]:
            for payload in sqli_payloads[:5]:
                test_url = f"{endpoint}?id={payload}" if '?' not in endpoint else endpoint + payload
                try:
                    resp = self.engine.requester.get(test_url) if self.engine.requester else None
                    if resp and resp.status_code == 200:
                        for pattern in error_patterns:
                            if pattern.lower() in resp.text.lower():
                                findings.append({
                                    "type": "sqli_error",
                                    "name": "SQL Injection (Error-based)",
                                    "severity": "high",
                                    "url": test_url,
                                    "parameter": "id",
                                    "payload": payload,
                                    "evidence": f"Found pattern: {pattern}",
                                    "description": "SQL injection vulnerability detected via error messages"
                                })
                                break
                except Exception:
                    pass
        return findings