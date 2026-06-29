from detectors.__init__ import DetectorBase

class SourceMapDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        for endpoint in endpoints[:100]:
            if endpoint.endswith('.js'):
                sourcemap_url = endpoint + '.map'
                try:
                    resp = self.engine.requester.get(sourcemap_url) if self.engine.requester else None
                    if resp and resp.status_code == 200 and 'sourceMappingURL' in resp.text:
                        findings.append({
                            "type": "secrets_sourcemap",
                            "name": "Exposed Source Map",
                            "severity": "medium",
                            "url": sourcemap_url,
                            "description": "Source map file exposed - can reveal sensitive code"
                        })
                except Exception:
                    pass
        return findings