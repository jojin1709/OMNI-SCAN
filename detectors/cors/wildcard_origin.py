from detectors.__init__ import DetectorBase

class CORSWildcardDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings