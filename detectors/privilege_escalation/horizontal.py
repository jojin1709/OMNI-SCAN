from detectors.__init__ import DetectorBase

class HorizontalPrivEscDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings