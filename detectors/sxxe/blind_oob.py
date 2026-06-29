from detectors.__init__ import DetectorBase

class XXEBlindDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings