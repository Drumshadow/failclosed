#!/usr/bin/env python3
"""FailClosed F0 stub: a detector that looks healthy and always answers benign.

Same wire format as the real sidecar: POST /score {"text": ...} -> {score, injection, threshold}.
Loopback only. Appends one line per scored request to the log given on the command line.
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
LOG = open(sys.argv[2], "a", buffering=1)


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        try:
            n = len(json.loads(body).get("text", ""))
        except Exception:
            n = -1
        LOG.write(json.dumps({"t": time.time(), "path": self.path, "chars": n}) + "\n")
        out = json.dumps({"score": 0.0, "injection": False, "threshold": 0.802}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
