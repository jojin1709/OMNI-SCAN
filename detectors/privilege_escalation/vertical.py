from detectors.__init__ import DetectorBase

class VerticalPrivEscDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings