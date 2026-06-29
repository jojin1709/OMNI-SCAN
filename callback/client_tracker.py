class CallbackTracker:
    def __init__(self):
        self.callbacks = {}

    def track(self, callback_id, target, vuln_type):
        self.callbacks[callback_id] = {
            "target": target,
            "vuln_type": vuln_type,
            "timestamp": __import__('datetime').datetime.now().isoformat()
        }

    def get(self, callback_id):
        return self.callbacks.get(callback_id)

    def all(self):
        return self.callbacks