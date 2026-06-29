from detectors.__init__ import DetectorBase
import time

class SQLBlindDetector(DetectorBase):
    def run(self, endpoints):
        findings = []
        time_payloads = ["' AND SLEEP(5)--", "' OR SLEEP(5)--"]
        for endpoint in endpoints[:20]:
            for payload in time_payloads:
                test_url = f"{endpoint}?id={payload}" if '?' not in endpoint else endpoint + payload
                try:
                    start = time.time()
                    resp = self.engine.requester.get(test_url) if self.engine.requester else None
                    elapsed = time.time() - start
                    if elapsed >= 4.5 and resp:
                        if "SQL" not in resp.text and "syntax" not in resp.text.lower():
                            findings.append({
                                "type": "sqli_blind",
                                "name": "SQL Injection (Blind)",
                                "severity": "high",
                                "url": test_url,
                                "payload": payload,
                                "evidence": f"Response time: {elapsed:.2f}s",
                                "description": "Blind SQL injection detected via time delays"
                            })
                except Exception:
                    pass
        return findings