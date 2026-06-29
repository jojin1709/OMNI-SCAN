from detectors.__init__ import DetectorBase

class RaceConditionDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings