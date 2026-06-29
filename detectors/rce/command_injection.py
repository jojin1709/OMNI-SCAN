from detectors.__init__ import DetectorBase

class CommandInjectionDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        payloads = ["; id", "| id", "$(id)", "`id`"]
        for endpoint in endpoints[:50]:
            for payload in payloads:
                test_url = f"{endpoint}?cmd={payload}"
                try:
                    resp = self.engine.requester.get(test_url) if self.engine.requester else None
                    if resp and "uid=" in resp.text and "gid=" in resp.text:
                        findings.append({
                            "type": "rce_cmd",
                            "name": "Command Injection",
                            "severity": "critical",
                            "url": test_url,
                            "payload": payload,
                            "evidence": "uid= found in response",
                            "description": "OS command injection detected"
                        })
                except Exception:
                    pass
        return findings