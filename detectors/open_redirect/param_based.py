from detectors.__init__ import DetectorBase

class OpenRedirectParamDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        payloads = ["https://evil.com", "//evil.com"]
        for endpoint in endpoints[:50]:
            for param in ["url", "redirect", "next", "return", "goto", "dest"]:
                for payload in payloads:
                    test_url = f"{endpoint}?{param}={payload}"
                    try:
                        resp = self.engine.requester.get(test_url) if self.engine.requester else None
                        if resp:
                            final_url = resp.url
                            orig_netloc = endpoint.split("//")[-1].split("/")[0] if "//" in endpoint else endpoint
                            if "evil.com" in final_url and orig_netloc not in final_url:
                                findings.append({
                                    "type": "open_redirect",
                                    "name": "Open Redirect",
                                    "severity": "medium",
                                    "url": test_url,
                                    "payload": payload,
                                    "description": "Open redirect vulnerability detected"
                                })
                                break
                    except Exception:
                        pass
        return findings