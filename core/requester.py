import requests
from urllib.parse import urlparse, urljoin
import time
import random
from colorama import Fore

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

class Requester:
    def __init__(self, proxy=None, timeout=15, retries=2, delay=0.1, random_agent=False, tor=False):
        self.proxy = proxy
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.random_agent = random_agent
        self.tor = tor
        self.session = requests.Session()
        self.request_count = 0
        self._setup_proxy()

    def _setup_proxy(self):
        if self.proxy:
            if self.proxy.startswith('socks'):
                self.session.proxies = {'http': self.proxy, 'https': self.proxy}
            else:
                self.session.proxies = {'http': self.proxy, 'https': self.proxy}

    def get(self, url, **kwargs):
        time.sleep(self.delay)
        self.request_count += 1
        for attempt in range(self.retries):
            try:
                headers = kwargs.get('headers', {})
                if self.random_agent:
                    headers['User-Agent'] = random.choice(USER_AGENTS)
                resp = self.session.get(url, timeout=self.timeout, headers=headers, **kwargs)
                return resp
            except Exception as e:
                if attempt == self.retries - 1:
                    return None
        return None

    def post(self, url, data=None, **kwargs):
        time.sleep(self.delay)
        self.request_count += 1
        for attempt in range(self.retries):
            try:
                headers = kwargs.get('headers', {})
                if self.random_agent:
                    headers['User-Agent'] = random.choice(USER_AGENTS)
                resp = self.session.post(url, data=data, timeout=self.timeout, headers=headers, **kwargs)
                return resp
            except Exception:
                if attempt == self.retries - 1:
                    return None
        return None

    def set_session(self, session):
        self.session = session