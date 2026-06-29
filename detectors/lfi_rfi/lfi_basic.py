import re
from detectors.__init__ import DetectorBase

class LFIBasicDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        lfi_payloads = ["../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd", "..%2f..%2f..%2fetc/passwd"]
        for endpoint in endpoints[:50]:
            for payload in lfi_payloads:
                test_url = f"{endpoint}?file={payload}"
                try:
                    resp = self.engine.requester.get(test_url) if self.engine.requester else None
                    if resp and any(ind in resp.text for ind in ["root:x:", "nobody:x:", "daemon:x:"]):
                        findings.append({
                            "type": "lfi_basic",
                            "name": "Local File Inclusion",
                            "severity": "critical",
                            "url": test_url,
                            "payload": payload,
                            "description": "LFI vulnerability detected - can read sensitive files"
                        })
                except Exception:
                    pass
        return findings