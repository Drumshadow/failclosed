#!/usr/bin/env python3
"""FailClosed: loopback proxy that adds the OpenRouter key, for a gateway with no model auth.

usage: or_proxy.py PORT KEYFILE MODEL BUDGET_USD LOG [--dry DUMPFILE]

Only MODEL may be requested. Stops with HTTP 429 once logged cost reaches BUDGET_USD. --dry forwards
nothing: it writes the first request body to DUMPFILE and answers 503. The key is never logged.
"""
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, KEYFILE, MODEL, BUDGET, LOGPATH = int(sys.argv[1]), sys.argv[2], sys.argv[3], float(sys.argv[4]), sys.argv[5]
DRY = sys.argv[7] if len(sys.argv) > 7 and sys.argv[6] == "--dry" else None
KEY = open(KEYFILE).read().strip()
URL = "https://openrouter.ai/api/v1/chat/completions"
LOCK = threading.Lock()
SPENT = 0.0
UNMEASURED = 0
MAX_UNMEASURED = 60  # some providers drop usage on a few percent of calls; the provider's key limit still applies
LOG = open(LOGPATH, "a", buffering=1)


class H(BaseHTTPRequestHandler):
    def _reply(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        global SPENT, UNMEASURED
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
        if DRY:
            with LOCK:
                try:
                    with open(DRY, "x") as f:
                        json.dump(body, f)
                except FileExistsError:
                    pass
            return self._reply(503, {"error": "dry run"})
        if body.get("model") != MODEL:
            return self._reply(400, {"error": "model not allowed"})
        with LOCK:
            over = SPENT >= BUDGET
        if over:
            LOG.write(json.dumps({"t": time.time(), "status": "local_budget_halt"}) + "\n")
            return self._reply(429, {"error": "local budget reached"})
        body.pop("chat_template_kwargs", None)  # vLLM-only field
        if body.get("stream"):
            body["stream_options"] = {"include_usage": True}  # streams omit usage unless asked
        req = urllib.request.Request(URL, data=json.dumps(body).encode(), method="POST", headers={
            "Authorization": "Bearer " + KEY, "Content-Type": "application/json", "X-Title": "failclosed-benchmark"})
        t0 = time.time()
        try:
            resp = urllib.request.urlopen(req, timeout=300)
        except urllib.error.HTTPError as e:
            detail = e.read()[:600].decode("utf8", "replace")
            LOG.write(json.dumps({"t": t0, "status": e.code, "detail": detail}) + "\n")
            return self._reply(e.code, {"error": detail})
        except Exception as e:
            LOG.write(json.dumps({"t": t0, "status": "exception", "detail": type(e).__name__}) + "\n")
            return self._reply(502, {"error": type(e).__name__})
        self.send_response(200)
        self.send_header("content-type", resp.getheader("content-type") or "application/json")
        self.end_headers()
        usage = None
        client_open = True
        whole = bytearray()  # tool-calling requests are not streamed: one JSON body, usage at top level
        try:
            for raw in resp:
                if not body.get("stream"):
                    whole += raw
                if raw.startswith(b":"):  # OpenRouter keep-alive comments
                    continue
                if raw.startswith(b"data:") and b'"usage"' in raw:
                    try:
                        usage = json.loads(raw[5:]).get("usage") or usage
                    except ValueError:
                        pass
                if client_open:  # the gateway may hang up at finish_reason, before the usage chunk
                    try:
                        self.wfile.write(raw)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        client_open = False
        finally:
            if whole:
                try:
                    usage = json.loads(bytes(whole)).get("usage") or usage
                except ValueError:
                    pass
            cost = float((usage or {}).get("cost") or 0)
            with LOCK:
                UNMEASURED += usage is None
                SPENT = BUDGET if UNMEASURED > MAX_UNMEASURED else SPENT + cost  # repeated unmeasured spend halts the run
                total = SPENT
            LOG.write(json.dumps({"t": t0, "dt": round(time.time() - t0, 2), "status": 200, "usage": usage, "cost": cost, "total": round(total, 5), "unmeasured": usage is None}) + "\n")

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
