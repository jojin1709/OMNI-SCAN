from detectors.__init__ import DetectorBase

class JWTPrivEscDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings