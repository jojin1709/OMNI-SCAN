from detectors.__init__ import DetectorBase

class SSRFBasicDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        ssrf_payloads = ["http://127.0.0.1:80", "http://localhost:80", "file:///etc/passwd", "http://metadata.google.internal"]
        for endpoint in endpoints[:50]:
            for payload in ssrf_payloads:
                test_url = f"{endpoint}?url={payload}"
                try:
                    resp = self.engine.requester.get(test_url) if self.engine.requester else None
                    if resp and resp.status_code == 200:
                        pass
                except Exception:
                    pass
        return findings