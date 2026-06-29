from detectors.__init__ import DetectorBase

class CSVInjectionDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings