import http.server
import threading
import json
from datetime import datetime

class HTTPCallbackServer:
    def __init__(self, port=8888):
        self.port = port
        self.server = None
        self.callbacks = []

    def start(self):
        self.server = http.server.HTTPServer(('0.0.0.0', self.port), self._handler)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.daemon = True
        thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()

    def _handler(self, request):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK')
            def log_message(self, format, *args):
                pass
        return Handler(request)