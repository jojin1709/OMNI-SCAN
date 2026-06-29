from detectors.__init__ import DetectorBase

class CSRFDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings