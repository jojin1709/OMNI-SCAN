from detectors.__init__ import DetectorBase

class FileUploadPolyglotDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings