#!/usr/bin/env python3
"""Simple HTTP server for Reflex fallback test. Serves on port 8082 (8080 often in use)."""

import http.server
import socketserver

PORT = 8082
HTML = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Reflex Fallback</title></head>
<body>
<h1>Reflex Fallback OK</h1>
<p>If you see this in your browser when opening the Reflex port, fallback is working.</p>
</body>
</html>
"""

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML.encode("utf-8"))

    def log_message(self, format, *args):
        print("[%s] %s" % (self.log_date_time_string(), format % args))

if __name__ == "__main__":
    # Bind to 127.0.0.1 so Chrome can reach it on localhost
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print("Fallback HTTP server on http://127.0.0.1:%d" % PORT)
        print("Open this URL in Chrome. Press Ctrl+C to stop.")
        httpd.serve_forever()
