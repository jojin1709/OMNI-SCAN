from detectors.__init__ import DetectorBase

class SSRFBlindDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings