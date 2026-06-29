import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import time
from colorama import Fore, Style

class SmartCrawler:
    def __init__(self, requester=None, max_pages=200, depth=3, threads=20):
        self.requester = requester
        self.max_pages = max_pages
        self.depth = depth
        self.threads = threads
        self.visited = set()
        self.endpoints = []

    def crawl(self, target):
        urls = [target]
        self.endpoints.append(target)
        for _ in range(self.depth):
            new_urls = []
            for url in urls:
                if len(self.endpoints) >= self.max_pages:
                    break
                try:
                    if self.requester:
                        resp = self.requester.get(url)
                    else:
                        resp = requests.get(url, timeout=15)
                    if resp and resp.status_code == 200:
                        links = self._extract_links(resp.text, url)
                        for link in links:
                            if link not in self.visited and len(self.endpoints) < self.max_pages:
                                self.visited.add(link)
                                self.endpoints.append(link)
                                new_urls.append(link)
                except Exception:
                    pass
            urls = new_urls
        return self.endpoints

    def _extract_links(self, html, base_url):
        links = []
        soup = BeautifulSoup(html, 'html.parser')
        for tag in soup.find_all(['a', 'script', 'link'], href=True):
            href = tag.get('href')
            if href:
                links.append(urljoin(base_url, href))
        for tag in soup.find_all('a', href=True):
            href = tag.get('href')
            if href:
                links.append(urljoin(base_url, href))
        for tag in soup.find_all('script', src=True):
            src = tag.get('src')
            if src:
                links.append(urljoin(base_url, src))
        forms = soup.find_all('form', action=True)
        for form in forms:
            action = form.get('action')
            if action:
                links.append(urljoin(base_url, action))
        return links

    def get_forms(self, url):
        forms = []
        try:
            if self.requester:
                resp = self.requester.get(url)
            else:
                resp = requests.get(url, timeout=15)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for form in soup.find_all('form'):
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    for inp in form.find_all('input'):
                        form_data['inputs'].append({
                            'name': inp.get('name', ''),
                            'type': inp.get('type', 'text')
                        })
                    forms.append(form_data)
        except Exception:
            pass
        return forms

    def get_params(self, url):
        params = []
        try:
            if self.requester:
                resp = self.requester.get(url)
            else:
                resp = requests.get(url, timeout=15)
            if resp and resp.status_code == 200:
                parsed = urlparse(url)
                if parsed.query:
                    params.extend(parsed.query.split('&'))
        except Exception:
            pass
        return params