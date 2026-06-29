from detectors.__init__ import DetectorBase

class FileUploadExtensionDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        return findings