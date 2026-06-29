import http.server
import threading
import json
import time
from datetime import datetime

class CallbackServer:
    def __init__(self, callback_url=None, port=8888, domain=None):
        self.callback_url = callback_url
        self.port = port
        self.domain = domain
        self.server = None
        self.thread = None
        self.callbacks = []

    def start(self):
        if self.callback_url:
            return
        self.server = http.server.HTTPServer(('0.0.0.0', self.port), CallbackHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()

    def get_callbacks(self):
        return self.callbacks


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        pass