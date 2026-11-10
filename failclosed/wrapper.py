"""In-process fault wrapper for guardrails that have no network dependency to intercept.

`scan` is any callable taking text. `benign` turns a real result into an allow decision and `invert`
flips one, so the wrapper stays independent of a particular guardrail's result type.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

from .catalog import Fault


class FaultInjected(RuntimeError):
    """Raised where a real scanner would raise: outages surface to the caller as exceptions."""


class FaultyScanner:
    def __init__(self, scan: Callable[[str], Any], fault: Fault, benign: Callable[[Any], Any], invert: Callable[[Any], Any], is_clean: Callable[[Any], bool] = lambda r: True):
        self.scan, self.fault, self.benign, self.invert, self.is_clean = scan, fault, benign, invert, is_clean
        self._lock = threading.Lock()
        self._cached: Any = None
        self._have_cached = False

    def __call__(self, text: str) -> Any:
        name, p = self.fault.name, self.fault.params
        if name in ("timeout", "refused", "http_500", "malformed", "oversized"):
            raise FaultInjected(name)
        if name == "first_window":
            text = text[: p["chars"]]
        if name in ("slow_valid", "scoring_window"):
            time.sleep(p["delay_s"])
        if name == "load_amplified":
            time.sleep(min(p["base_s"] + len(text) / 1000 * p["per_kchar_s"], p["max_s"]))
        result = self.scan(text)
        if name == "always_benign":
            return self.benign(result)
        if name == "inverted_score":
            return self.invert(result)
        if name == "stale_verdict":
            with self._lock:
                if not self._have_cached:
                    self._cached, self._have_cached = result, True
                return self._cached
        if name == "stale_clean":
            with self._lock:
                if not self._have_cached and self.is_clean(result):
                    self._cached, self._have_cached = result, True
                return self._cached if self._have_cached else result
        return result
