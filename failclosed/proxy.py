"""HTTP fault proxy for guardrail sidecars. Loopback only.

    python -m failclosed.proxy --upstream http://127.0.0.1:8796 --fault always_benign --port 8797

Forwards POST bodies to the upstream and applies one catalog fault. The wire format is a JSON request
with a text field and a JSON reply with a score and a boolean verdict; the field names are options.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .catalog import Fault, load_catalog


class FaultProxy(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, upstream: str, fault: Fault, text_field="text", verdict_field="injection", score_field="score", log_path=None):
        if fault.adapter != "proxy":
            raise ValueError(f"{fault.name} is a {fault.adapter} fault, not a proxy fault")
        super().__init__(("127.0.0.1", port), _Handler)
        self.upstream, self.fault = upstream.rstrip("/"), fault
        self.text_field, self.verdict_field, self.score_field = text_field, verdict_field, score_field
        self.lock = threading.Lock()
        self.cached: dict | None = None
        self.calls = 0
        self.log = open(log_path, "a", buffering=1) if log_path else None

    def forward(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(self.upstream + path, data=json.dumps(payload).encode(), headers={"content-type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    def record(self, entry: dict) -> None:
        with self.lock:
            self.calls += 1
            if self.log:
                self.log.write(json.dumps({"t": time.time(), "fault": self.fault.name, **entry}) + "\n")


class _Handler(BaseHTTPRequestHandler):
    server: FaultProxy

    def _send(self, code: int, data: bytes) -> None:
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj: dict) -> None:
        self._send(200, json.dumps(obj).encode())

    def _reset(self) -> None:
        # Closest a listening proxy gets to a refused connection: an immediate TCP reset.
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.close_connection = True
        self.connection.close()

    def do_POST(self):
        s = self.server
        p, name = s.fault.params, s.fault.name
        payload = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
        text = str(payload.get(s.text_field, ""))
        s.record({"chars": len(text)})

        if name == "timeout":
            time.sleep(p["hang_s"])
            return self._reset()
        if name == "refused":
            return self._reset()
        if name == "http_500":
            return self._send(500, b'{"error":"injected"}')
        if name == "malformed":
            return self._send(200, b'{"score": 0.0, "injection": fals')

        if name == "first_window":
            payload = {**payload, s.text_field: text[: p["chars"]]}
        if name in ("slow_valid", "scoring_window"):
            time.sleep(p["delay_s"])
        if name == "load_amplified":
            time.sleep(min(p["base_s"] + len(text) / 1000 * p["per_kchar_s"], p["max_s"]))

        try:
            reply = s.forward(self.path, payload)
        except (urllib.error.URLError, OSError, ValueError) as e:
            return self._send(502, json.dumps({"error": type(e).__name__}).encode())

        if name == "oversized":
            reply = {**reply, "padding": "x" * p["bytes"]}
        elif name == "always_benign":
            reply = {**reply, s.verdict_field: False, s.score_field: 0.0}
        elif name == "inverted_score":
            reply = {**reply, s.verdict_field: not reply[s.verdict_field], s.score_field: round(1 - float(reply[s.score_field]), 6)}
        elif name == "stale_verdict":
            with s.lock:
                if s.cached is None:
                    s.cached = reply
                reply = s.cached
        elif name == "stale_clean":
            with s.lock:  # a cache that keeps serving an earlier clean result
                if s.cached is None and not reply.get(s.verdict_field):
                    s.cached = reply
                reply = s.cached if s.cached is not None else reply
        s.record({"verdict": reply.get(s.verdict_field)})
        self._json(reply)

    def do_GET(self):
        self._send(200, b"{}")

    def log_message(self, *a):
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--fault", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--log")
    a = ap.parse_args()
    FaultProxy(a.port, a.upstream, load_catalog()[a.fault], log_path=a.log).serve_forever()


if __name__ == "__main__":
    main()
