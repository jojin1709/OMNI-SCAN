from detectors.__init__ import DetectorBase

class RFIDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings