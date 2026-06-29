from detectors.__init__ import DetectorBase

class SSTIDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]
        for endpoint in endpoints[:50]:
            for payload in payloads:
                test_url = f"{endpoint}?input={payload}"
                try:
                    resp = self.engine.requester.get(test_url) if self.engine.requester else None
                    if resp and ("49" in resp.text or "49" in resp.text):
                        findings.append({
                            "type": "rce_ssti",
                            "name": "Server-Side Template Injection",
                            "severity": "critical",
                            "url": test_url,
                            "payload": payload,
                            "description": "SSTI vulnerability detected"
                        })
                except Exception:
                    pass
        return findings