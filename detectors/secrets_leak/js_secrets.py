import re
from detectors.__init__ import DetectorBase

class JSSecretsDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        patterns = [
            r'["\'](AKIA[0-9A-Z]{16})["\']',
            r'["\']([a-z0-9]{32})["\']',
            r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
        ]
        for endpoint in endpoints[:100]:
            try:
                resp = self.engine.requester.get(endpoint) if self.engine.requester else None
                if resp and resp.status_code == 200:
                    for pattern in patterns:
                        matches = re.findall(pattern, resp.text, re.I)
                        if matches:
                            findings.append({
                                "type": "secrets_js",
                                "name": "Exposed Secrets in JavaScript",
                                "severity": "high",
                                "url": endpoint,
                                "description": f"Found potential secrets in JS response"
                            })
                            break
            except Exception:
                pass
        return findings