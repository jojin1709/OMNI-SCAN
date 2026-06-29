from detectors.__init__ import DetectorBase

class XSSStoredDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings