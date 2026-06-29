import re
from detectors.__init__ import DetectorBase

class NumericIDORDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        for endpoint in endpoints[:100]:
            if any(c.isdigit() for c in endpoint):
                for i in range(1, 5):
                    test_url = re.sub(r'\d+', str(i), endpoint)
                    try:
                        resp = self.engine.requester.get(test_url) if self.engine.requester else None
                        if resp and resp.status_code == 200:
                            pass
                    except Exception:
                        pass
        return findings