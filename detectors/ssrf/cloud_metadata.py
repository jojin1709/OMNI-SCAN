from detectors.__init__ import DetectorBase

class SSRFCloudMetadataDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        metadata_payloads = ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/"]
        for endpoint in endpoints[:30]:
            for payload in metadata_payloads:
                test_url = f"{endpoint}?url={payload}"
                try:
                    resp = self.engine.requester.get(test_url) if self.engine.requester else None
                    if resp and resp.status_code == 200:
                        if "instance-id" in resp.text or "project-id" in resp.text:
                            findings.append({
                                "type": "ssrf_cloud",
                                "name": "SSRF Cloud Metadata",
                                "severity": "critical",
                                "url": test_url,
                                "description": "Cloud metadata endpoint accessible via SSRF"
                            })
                except Exception:
                    pass
        return findings