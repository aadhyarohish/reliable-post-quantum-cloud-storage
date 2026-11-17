"""Metrics registry, engine instrumentation and HTTP endpoints."""
import json
import os
import urllib.request
import urllib.error
import pytest
from crypto_engine import Actor, Engine, IntegrityError, PermissionDenied, UnknownObject
from observability import Registry, serve
import sre
from conftest import PASS


def test_registry_counter_gauge_histogram_render():
    r = Registry()
    r.inc("x_total", {"a": "1"}); r.inc("x_total", {"a": "1"}, 2); r.set_gauge("g", 5)
    r.observe("lat", 0.003, {"op": "t"}); r.observe("lat", 0.3, {"op": "t"})
    txt = r.render()
    assert 'x_total{a="1"} 3' in txt and "g 5" in txt
    assert 'lat_bucket{op="t",le="0.005"} 1' in txt and 'lat_bucket{op="t",le="+Inf"} 2' in txt
    assert 'lat_count{op="t"} 2' in txt


def test_window_uses_injected_clock():
    t = [1000.0]; r = Registry(clock=lambda: t[0])
    r.record("encrypt", "ok", 0.01); t[0] = 1500.0; r.record("encrypt", "ok", 0.01)
    assert len(r.window(100)) == 1 and len(r.window(1000)) == 2


def test_engine_operations_are_instrumented_with_status_classes(engine, admin, alice):
    m = engine.encrypt_file(admin, "a.txt", b"hello", "rsa")
    engine.decrypt_file(admin, m["object_id"])
    with pytest.raises(PermissionDenied):
        engine.decrypt_file(alice, m["object_id"])
    with pytest.raises(UnknownObject):
        engine.decrypt_file(admin, "0" * 32)
    bp = engine.storage / f"{m['object_id']}.bin"; raw = bytearray(bp.read_bytes()); raw[-1] ^= 1; bp.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        engine.decrypt_file(admin, m["object_id"])
    g = engine.metrics.get_counter
    assert g("pqc_operations_total", {"op": "encrypt", "status": "ok"}) == 1
    assert g("pqc_operations_total", {"op": "decrypt", "status": "ok"}) == 1
    assert g("pqc_operations_total", {"op": "decrypt", "status": "client_error"}) == 2   # denied + unknown
    assert g("pqc_operations_total", {"op": "decrypt", "status": "integrity_error"}) == 1
    assert g("pqc_bytes_total", {"op": "encrypt"}) == 5


def test_http_endpoints(engine, admin, monkeypatch):
    engine.encrypt_file(admin, "a.txt", b"x")
    srv, port = serve(engine.metrics, lambda: sre.health(engine))
    try:
        base = f"http://127.0.0.1:{port}"
        assert urllib.request.urlopen(base + "/healthz").read() == b"ok\n"
        body = urllib.request.urlopen(base + "/metrics").read().decode()
        assert "pqc_operations_total" in body and "pqc_operation_duration_seconds_bucket" in body
        rep = json.loads(urllib.request.urlopen(base + "/readyz").read())
        assert rep["status"] in ("ok", "degraded")
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(base + "/nope")
        assert e.value.code == 404
        # readiness turns 503 when a dependency fails (injected storage write failure)
        def boom(*a, **k): raise OSError(28, "No space left on device")
        monkeypatch.setattr(sre.tempfile, "mkstemp", boom)
        with pytest.raises(urllib.error.HTTPError) as e2:
            urllib.request.urlopen(base + "/readyz")
        assert e2.value.code == 503
    finally:
        srv.shutdown()


def test_audit_tail_cache_avoids_rescanning_log_and_keeps_chain_valid(tmp_path):
    def run(cache):
        e = Engine(tmp_path / f"c{cache}", PASS, kdf_n=2 ** 10, cache_tail=cache); e.bootstrap_admin("admin", "adminpass1")
        a = Actor("admin", "admin"); calls = {"n": 0}; real = e._scan_tail
        def counting():
            calls["n"] += 1; return real()
        e._scan_tail = counting
        for _ in range(50): e._audit("noop", a)
        assert e._verify_audit_raw().ok
        return calls["n"]
    assert run(False) == 50          # v2 behaviour: O(n) scan on every append
    assert run(True) <= 1            # cached tail: at most one scan (first use)
