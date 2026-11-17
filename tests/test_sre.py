"""SLOs, burn-rate alerts, health, scrubber, backup/restore and staged migration."""
import json
import os
import pytest
import sre
from crypto_engine import Actor, Engine, IntegrityError, PermissionDenied
from observability import Registry
from conftest import PASS

AV = sre.DEFAULT_SLOS[0]; LAT = sre.DEFAULT_SLOS[1]


# ------------------------------------------------------------------ SLO maths
def test_sli_excludes_client_errors_and_counts_server_failures():
    r = Registry(clock=lambda: 100.0)
    for _ in range(97): r.record("decrypt", "ok", 0.01)
    r.record("decrypt", "error", 0.01); r.record("decrypt", "integrity_error", 0.01); r.record("decrypt", "error", 0.01)
    for _ in range(50): r.record("decrypt", "client_error", 0.001)           # must not count
    e = sre.evaluate(r, AV)
    assert (e["good"], e["total"]) == (97, 100) and e["sli"] == pytest.approx(0.97)
    assert e["burn_rate"] == pytest.approx(0.03 / 0.001) and not e["meeting_slo"]


def test_latency_sli_uses_threshold():
    r = Registry(clock=lambda: 0.0)
    for s in (0.01, 0.1, 0.2, 0.3, 0.9): r.record("encrypt", "ok", s)
    assert sre.sli_counts(r.events, LAT) == (3, 5)


def test_error_budget_example_999_over_30_days():
    assert AV.error_budget == pytest.approx(0.001)
    assert AV.window_s * AV.error_budget / 60 == pytest.approx(43.2)        # 43.2 minutes of allowed downtime


def test_multiwindow_burn_alert_fires_and_clears_with_fake_clock():
    t = [0.0]; r = Registry(clock=lambda: t[0])
    def traffic(n, fail_every=0):
        for i in range(n):
            t[0] += 1.0
            r.record("decrypt", "error" if fail_every and i % fail_every == 0 else "ok", 0.01)
    traffic(3000)                                     # 50 min healthy
    assert sre.burn_alerts(r, AV, t[0]) == []
    traffic(400, fail_every=5)                        # 20 % failures for ~6.7 min
    sev = [a["severity"] for a in sre.burn_alerts(r, AV, t[0])]
    assert "page" in sev
    traffic(900)                                      # 15 min healthy again: short windows clear
    fast = [a for a in sre.burn_alerts(r, AV, t[0]) if a["threshold"] == 14.4]
    assert fast == []


# ------------------------------------------------------------------ health
def test_health_ok_degraded_and_fail(engine, admin):
    rep = sre.health(engine)
    rep = sre.health(engine, min_free_fraction=0.01)
    assert rep["status"] == "degraded"                                       # never scrubbed / never backed up
    sre.scrub(engine, admin); sre.backup(engine, admin, engine.home.parent / "bk_h")
    assert sre.health(engine, min_free_fraction=0.01)["status"] == "ok"
    # truncate the audit log: O(1) head check must fail readiness
    lines = engine.audit_path.read_text().splitlines()[:-2]
    engine.audit_path.write_text("\n".join(lines) + "\n")
    rep = sre.health(engine)
    assert rep["status"] == "fail" and any(c["check"] == "audit_head" and c["status"] == "fail" for c in rep["checks"])


def test_health_flags_pending_journal_and_stale_scrub(engine, admin):
    sre.scrub(engine, admin)
    (engine.journal / ("a" * 32 + ".json")).write_text("{}")
    rep = sre.health(engine, now=engine.metrics.clock() + 2 * 86400)
    names = {c["check"]: c["status"] for c in rep["checks"]}
    assert names["pending_journals"] == "warn" and names["integrity"] == "warn"


# ------------------------------------------------------------------ scrubber
def _make(engine, admin, n=6):
    return [engine.encrypt_file(admin, f"f{i}.bin", os.urandom(5000 + i), "rsa")["object_id"] for i in range(n)]


def test_scrubber_clean_store_reports_zero_corrupt(engine, admin):
    _make(engine, admin)
    rep = sre.scrub(engine, admin)
    assert rep["checked"] == 6 and rep["ok"] == 6 and rep["corrupt"] == []
    assert engine.metrics.get_gauge("pqc_scrub_objects_corrupt") == 0


def test_scrubber_detects_bitflip_header_damage_and_deletion(engine, admin):
    ids = _make(engine, admin)
    p0 = engine.storage / f"{ids[0]}.bin"; b = bytearray(p0.read_bytes()); b[len(b) // 2] ^= 0x80; p0.write_bytes(bytes(b))   # body
    p1 = engine.storage / f"{ids[1]}.bin"; b = bytearray(p1.read_bytes()); b[2] ^= 0x01; p1.write_bytes(bytes(b))              # header
    (engine.storage / f"{ids[2]}.bin").unlink()                                                                              # lost file
    rep = sre.scrub(engine, admin)
    assert {c["object_id"] for c in rep["corrupt"]} == set(ids[:3]) and rep["ok"] == 3
    assert engine.metrics.get_gauge("pqc_scrub_objects_corrupt") == 3
    assert any(r["event"] == "object_corrupt" for r in engine.read_audit(admin))
    slo = sre.DEFAULT_SLOS[3]; e = sre.evaluate(engine.metrics, slo)
    assert not e["meeting_slo"] and e["good"] == 3 and e["total"] == 6


def test_scrub_requires_permission(engine, alice):
    with pytest.raises(PermissionDenied):
        sre.scrub(engine, alice)


# ------------------------------------------------------------------ backup / restore
def test_backup_restore_roundtrip(engine, admin, tmp_path):
    ids = _make(engine, admin, 5); data = {i: engine.decrypt_file(admin, i) for i in ids}
    bk = sre.backup(engine, admin, tmp_path / "bk")
    assert bk["objects"] == 5
    new_home = tmp_path / "restored"
    sre.restore(bk["archive"], new_home)
    e2 = Engine(new_home, PASS, kdf_n=2 ** 10)
    for i in ids:
        assert e2.decrypt_file(admin, i) == data[i]
    assert e2._verify_audit_raw().ok
    assert sre.scrub(e2, admin)["corrupt"] == []


def test_restore_detects_modified_backup(engine, admin, tmp_path):
    import tarfile, io
    _make(engine, admin, 2)
    bk = sre.backup(engine, admin, tmp_path / "bk")
    src = tarfile.open(bk["archive"]); out = tmp_path / "evil.tar"
    with tarfile.open(out, "w") as dst:
        for m in src.getmembers():
            d = src.extractfile(m).read()
            if m.name.endswith(".bin"): d = bytes([d[0] ^ 1]) + d[1:]
            ti = tarfile.TarInfo(m.name); ti.size = len(d); dst.addfile(ti, io.BytesIO(d))
    with pytest.raises(IntegrityError):
        sre.restore(out, tmp_path / "r2")


def test_restore_refuses_non_empty_target(engine, admin, tmp_path):
    _make(engine, admin, 1); bk = sre.backup(engine, admin, tmp_path / "bk")
    (tmp_path / "t").mkdir(); (tmp_path / "t" / "x").write_text("1")
    with pytest.raises(Exception):
        sre.restore(bk["archive"], tmp_path / "t")


def test_backup_requires_permission(engine, alice, tmp_path):
    with pytest.raises(PermissionDenied):
        sre.backup(engine, alice, tmp_path / "bk")


# ------------------------------------------------------------------ staged migration
def test_staged_migration_completes_and_all_objects_readable(engine, admin):
    ids = _make(engine, admin, 10)
    rep = sre.staged_migration(engine, admin, "mlkem")
    assert rep["status"] == "completed" and rep["migrated"] == 10
    assert [s["size"] for s in rep["stages"]] == [1, 1, 3, 5]                # canary, 10 %, 50 %, 100 % (cumulative 1, 2, 5, 10)
    assert all(m["key_protection"]["algorithm"].startswith("ML-KEM") for m in engine.list_objects(admin))
    assert sre.scrub(engine, admin)["corrupt"] == []


def test_staged_migration_halts_and_rolls_back_failed_stage(engine, admin, monkeypatch):
    ids = _make(engine, admin, 10)
    cands = [m["object_id"] for m in engine.list_objects(admin)]
    real = engine.migrate
    def flaky(actor, oid, target="mlkem", **k):
        if oid == cands[3]: raise RuntimeError("injected failure")
        return real(actor, oid, target, **k)
    monkeypatch.setattr(engine, "migrate", flaky)
    rep = sre.staged_migration(engine, admin, "mlkem")
    assert rep["status"] == "halted"
    halted = rep["stages"][-1]
    assert halted["halted"] and halted["failed"] == 1 and halted["rolled_back"] == halted["migrated"]
    monkeypatch.undo()
    algs = [m["key_protection"]["algorithm"] for m in engine.list_objects(admin)]
    assert sum(a.startswith("ML-KEM") for a in algs) == 2                    # only the earlier, healthy stages stay migrated
    assert sre.scrub(engine, admin)["corrupt"] == []                          # nothing damaged
    assert any(r["event"] == "rollout_halted" for r in engine.read_audit(admin))


def test_staged_migration_halts_on_slo_gate(engine, admin):
    _make(engine, admin, 8)
    rep = sre.staged_migration(engine, admin, "mlkem", gate=lambda: (False, "burn rate 20x"))
    assert rep["status"] == "halted" and rep["stages"][0]["halted"] and "burn rate" in rep["stages"][0]["reason"]
    assert all(m["key_protection"]["algorithm"].startswith("RSA") for m in engine.list_objects(admin))


def test_fast_scrub_mode_relies_on_sha256_and_still_detects_corruption(engine, admin):
    """authenticate=False skips AEAD; the SHA-256 comparison is then the only line of defence."""
    ids = _make(engine, admin, 4)
    p = engine.storage / f"{ids[1]}.bin"; b = bytearray(p.read_bytes()); b[len(b) // 2] ^= 0x01; p.write_bytes(bytes(b))
    rep = sre.scrub(engine, admin, authenticate=False)
    assert [c["object_id"] for c in rep["corrupt"]] == [ids[1]] and rep["ok"] == 3
