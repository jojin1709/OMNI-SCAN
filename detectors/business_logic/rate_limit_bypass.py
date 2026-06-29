from detectors.__init__ import DetectorBase

class RateLimitBypassDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings