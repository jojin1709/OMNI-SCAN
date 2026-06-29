# Detector base module
class DetectorBase:
    def __init__(self, engine):
        self.engine = engine

    def run(self, endpoints):
        return []