from detectors.__init__ import DetectorBase

class JWTNoneDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings