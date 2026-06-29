from detectors.__init__ import DetectorBase

class SQLBooleanDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        payloads = ["' AND 1=1--", "' AND 1=2--", "' OR 1=1--"]
        for endpoint in endpoints[:30]:
            try:
                resp1 = self.engine.requester.get(f"{endpoint}?id=' AND 1=1--") if self.engine.requester else None
                resp2 = self.engine.requester.get(f"{endpoint}?id=' AND 1=2--") if self.engine.requester else None
                if resp1 and resp2:
                    if resp1.status_code == resp2.status_code and len(resp1.text) != len(resp2.text):
                        findings.append({
                            "type": "sqli_boolean",
                            "name": "SQL Injection (Boolean-based)",
                            "severity": "high",
                            "url": endpoint,
                            "description": "Boolean-based SQL injection detected via response differences"
                        })
            except Exception:
                pass
        return findings