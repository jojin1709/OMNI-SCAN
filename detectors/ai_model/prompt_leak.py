from detectors.__init__ import DetectorBase

class PromptLeakDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings