from detectors.__init__ import DetectorBase

class OTPBypassDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings