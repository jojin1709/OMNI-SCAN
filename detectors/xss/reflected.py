from detectors.__init__ import DetectorBase

class XSSReflectedDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        xss_payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><script>alert(1)</script>']
        for endpoint in endpoints[:50]:
            for payload in xss_payloads:
                test_url = f"{endpoint}?q={payload}"
                try:
                    resp = self.engine.requester.get(test_url) if self.engine.requester else None
                    if resp and payload in resp.text:
                        findings.append({
                            "type": "xss_reflected",
                            "name": "Reflected XSS",
                            "severity": "high",
                            "url": test_url,
                            "parameter": "q",
                            "payload": payload,
                            "evidence": f"Payload reflected in response",
                            "description": "Reflected XSS vulnerability detected"
                        })
                except Exception:
                    pass
        return findings