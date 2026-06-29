from detectors.__init__ import DetectorBase

class LoginBypassDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings