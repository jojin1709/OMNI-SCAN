from detectors.__init__ import DetectorBase

class NegativeValueDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings