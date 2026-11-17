"""
observability.py - dependency-free metrics, event window and HTTP endpoints for the PQC storage service.

* Registry     : counters, gauges, histograms (Prometheus text exposition format) + an event ring buffer
                 used to compute SLIs over arbitrary time windows (SRE burn-rate alerting).
* serve()      : tiny HTTP server exposing /metrics, /healthz (liveness) and /readyz (readiness).
* log_json()   : structured one-line JSON logs.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterable, Optional

DEFAULT_BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


@dataclass(frozen=True)
class Event:
    t: float            # timestamp from the registry clock
    op: str             # encrypt | decrypt | list | migrate | rollback | login | verify_audit | scrub
    status: str         # ok | client_error | integrity_error | error
    seconds: float      # wall-clock duration of the operation


def _key(labels: Optional[dict]) -> tuple:
    return tuple(sorted((labels or {}).items()))


def _fmt_labels(key: tuple, extra: tuple = ()) -> str:
    items = list(key) + list(extra)
    return "{" + ",".join(f'{k}="{v}"' for k, v in items) + "}" if items else ""


class Registry:
    def __init__(self, clock: Callable[[], float] = time.time, buckets: Iterable[float] = DEFAULT_BUCKETS,
                 max_events: int = 200_000):
        self.clock = clock
        self.buckets = tuple(buckets)
        self._lock = threading.Lock()
        self._counters: dict[tuple, float] = {}
        self._gauges: dict[tuple, float] = {}
        self._hist: dict[tuple, list] = {}      # (name, labels) -> [bucket counts..., +Inf count, sum]
        self._help: dict[str, tuple[str, str]] = {}
        self.events: deque[Event] = deque(maxlen=max_events)

    def describe(self, name: str, kind: str, help_: str) -> None:
        self._help[name] = (kind, help_)

    def inc(self, name: str, labels: Optional[dict] = None, v: float = 1.0) -> None:
        with self._lock:
            k = (name, _key(labels)); self._counters[k] = self._counters.get(k, 0.0) + v

    def set_gauge(self, name: str, v: float, labels: Optional[dict] = None) -> None:
        with self._lock:
            self._gauges[(name, _key(labels))] = float(v)

    def get_gauge(self, name: str, labels: Optional[dict] = None, default: float | None = None):
        return self._gauges.get((name, _key(labels)), default)

    def get_counter(self, name: str, labels: Optional[dict] = None) -> float:
        return self._counters.get((name, _key(labels)), 0.0)

    def observe(self, name: str, seconds: float, labels: Optional[dict] = None) -> None:
        with self._lock:
            k = (name, _key(labels))
            h = self._hist.setdefault(k, [0] * (len(self.buckets) + 1) + [0.0])
            for i, b in enumerate(self.buckets):
                if seconds <= b:
                    h[i] += 1
            h[len(self.buckets)] += 1       # +Inf / count
            h[-1] += seconds

    def record(self, op: str, status: str, seconds: float, nbytes: int = 0, t: float | None = None) -> None:
        self.inc("pqc_operations_total", {"op": op, "status": status})
        self.observe("pqc_operation_duration_seconds", seconds, {"op": op})
        if nbytes:
            self.inc("pqc_bytes_total", {"op": op}, nbytes)
        with self._lock:
            self.events.append(Event(self.clock() if t is None else t, op, status, seconds))

    def window(self, seconds: float, now: float | None = None) -> list[Event]:
        now = self.clock() if now is None else now
        lo = now - seconds
        with self._lock:
            return [e for e in self.events if lo < e.t <= now]

    def quantile(self, op: str, q: float, now: float | None = None, seconds: float | None = None) -> float:
        ev = self.window(seconds, now) if seconds else list(self.events)
        xs = sorted(e.seconds for e in ev if e.op == op and e.status == "ok")
        if not xs:
            return 0.0
        return xs[min(len(xs) - 1, int(q * len(xs)))]

    def render(self) -> str:
        out = []
        with self._lock:
            names = sorted({n for n, _ in self._counters} | {n for n, _ in self._gauges} | {n for n, _ in self._hist})
            hist_names = {a for a, _ in self._hist}
            for n in names:
                kind, help_ = self._help.get(n, ("untyped", n))
                if n in hist_names:
                    kind = "histogram"
                out.append(f"# HELP {n} {help_}"); out.append(f"# TYPE {n} {kind}")
                for (name, lk), v in sorted(self._counters.items()):
                    if name == n: out.append(f"{n}{_fmt_labels(lk)} {v:g}")
                for (name, lk), v in sorted(self._gauges.items()):
                    if name == n: out.append(f"{n}{_fmt_labels(lk)} {v:g}")
                for (name, lk), h in sorted(self._hist.items()):
                    if name != n: continue
                    for i, b in enumerate(self.buckets):
                        out.append(f"{n}_bucket{_fmt_labels(lk, (('le', f'{b:g}'),))} {h[i]}")
                    out.append(f"{n}_bucket{_fmt_labels(lk, (('le', '+Inf'),))} {h[len(self.buckets)]}")
                    out.append(f"{n}_sum{_fmt_labels(lk)} {h[-1]:.6f}"); out.append(f"{n}_count{_fmt_labels(lk)} {h[len(self.buckets)]}")
        return "\n".join(out) + "\n"


def log_json(logger: logging.Logger, level: str, event: str, **fields) -> None:
    logger.log(getattr(logging, level.upper()), json.dumps({"event": event, **fields}, sort_keys=True, default=str))


def serve(registry: Registry, ready_fn: Callable[[], dict], host: str = "127.0.0.1", port: int = 0):
    """Start /metrics, /healthz and /readyz in a daemon thread. Returns (server, port)."""
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="text/plain; version=0.0.4"):
            b = body.encode(); self.send_response(code); self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            if self.path == "/metrics": self._send(200, registry.render())
            elif self.path == "/healthz": self._send(200, "ok\n")
            elif self.path == "/readyz":
                rep = ready_fn(); self._send(200 if rep["status"] != "fail" else 503, json.dumps(rep, indent=2), "application/json")
            else: self._send(404, "not found\n")
        def log_message(self, *a): pass
    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]
