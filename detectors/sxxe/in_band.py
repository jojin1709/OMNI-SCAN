from detectors.__init__ import DetectorBase

class XXEInBandDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings