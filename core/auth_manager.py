import requests
from urllib.parse import urlparse
import re

class AuthManager:
    def __init__(self, auth_url=None, auth_data=None, auth_type='form', cookie=None, header=None, token=None, auth_script=None):
        self.auth_url = auth_url
        self.auth_data = auth_data
        self.auth_type = auth_type
        self.cookie = cookie
        self.header = header
        self.token = token
        self.auth_script = auth_script
        self.session = requests.Session()

    def authenticate(self):
        if self.token:
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
        if self.cookie:
            cookies = {}
            for c in self.cookie.split(';'):
                c = c.strip()
                if '=' in c:
                    name, value = c.split('=', 1)
                    cookies[name] = value
            self.session.cookies.update(cookies)
        if self.header:
            for h in self.header.split(';'):
                h = h.strip()
                if ':' in h:
                    name, value = h.split(':', 1)
                    self.session.headers.update({name.strip(): value.strip()})
        if self.auth_url and self.auth_data:
            self._do_login()
        return self.session

    def _do_login(self):
        data = {}
        for pair in self.auth_data.split('&'):
            if '=' in pair:
                name, value = pair.split('=', 1)
                data[name] = value.replace('__EXTRACT__', '')
        self.session.post(self.auth_url, data=data)

    def get_session(self):
        return self.session