from detectors.__init__ import DetectorBase

class GitExposedDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        paths = [".git/config", ".git/HEAD", ".git/objects/pack/pack-*.idx"]
        for endpoint in endpoints[:50]:
            for path in paths:
                test_url = endpoint.rstrip('/') + '/' + path
                try:
                    resp = self.engine.requester.get(test_url) if self.engine.requester else None
                    if resp and resp.status_code == 200 and ("git" in resp.text or "ref:" in resp.text):
                        findings.append({
                            "type": "secrets_git",
                            "name": "Exposed .git Directory",
                            "severity": "high",
                            "url": test_url,
                            "description": "Git directory exposed - sensitive information disclosure"
                        })
                except Exception:
                    pass
        return findings