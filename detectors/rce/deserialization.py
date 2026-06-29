from detectors.__init__ import DetectorBase

class DeserializationDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings