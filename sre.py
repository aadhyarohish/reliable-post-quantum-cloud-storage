"""
sre.py - Site Reliability Engineering layer for the PQC cloud-storage prototype.

* SLOs / SLIs / error budgets / multi-window burn-rate alerts  (Google SRE book + workbook practice)
* health(): liveness/readiness style checks with ok / warn / fail
* scrub(): background-style integrity scrubber (bit-rot / loss detection without releasing plaintext)
* backup() / restore(): consistent snapshots with a SHA-256 manifest (RPO / RTO measurable)
* staged_migration(): canary -> progressive fleet migration that halts and rolls back on failure
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import os
import shutil
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from crypto_engine import Actor, Engine, EngineError, IntegrityError, UnknownObject, now_utc
from observability import Registry

DAY = 86_400


# ----------------------------------------------------------------------------- SLOs
@dataclass(frozen=True)
class SLO:
    name: str
    description: str
    objective: float                    # e.g. 0.999
    kind: str                           # availability | latency | integrity
    ops: tuple                          # operations that count
    threshold_s: Optional[float] = None  # latency SLOs only
    window_s: float = 30 * DAY

    @property
    def error_budget(self) -> float:
        return 1.0 - self.objective


DEFAULT_SLOS = (
    SLO("data_plane_availability", "Valid encrypt/decrypt/list requests succeed (client errors excluded)",
        0.999, "availability", ("encrypt", "decrypt", "list")),
    SLO("data_plane_latency", "Successful encrypt/decrypt requests complete within 250 ms",
        0.99, "latency", ("encrypt", "decrypt"), threshold_s=0.25),
    SLO("migration_success", "Key-protection migrations complete without error or integrity failure",
        0.999, "availability", ("migrate",)),
    SLO("data_integrity", "Scrubbed objects are intact (SHA-256 and AEAD authentication)",
        0.99999, "integrity", ("scrub",)),
)


def sli_counts(events, slo: SLO) -> tuple[int, int]:
    """Return (good, valid) for the events that count towards this SLO."""
    ev = [e for e in events if e.op in slo.ops]
    if slo.kind == "latency":
        ok = [e for e in ev if e.status == "ok"]
        return sum(1 for e in ok if e.seconds <= slo.threshold_s), len(ok)
    valid = [e for e in ev if e.status != "client_error"]
    return sum(1 for e in valid if e.status == "ok"), len(valid)


def evaluate(reg: Registry, slo: SLO, window_s: Optional[float] = None, now: Optional[float] = None) -> dict:
    events = reg.window(window_s or slo.window_s, now)
    good, total = sli_counts(events, slo)
    sli = (good / total) if total else 1.0
    bad_frac = 1.0 - sli
    burn = bad_frac / slo.error_budget if slo.error_budget > 0 else (math.inf if bad_frac else 0.0)
    return {"slo": slo.name, "objective": slo.objective, "good": good, "total": total, "sli": sli,
            "burn_rate": burn, "budget_consumed": burn if total else 0.0,
            "budget_remaining": max(0.0, 1.0 - burn) if total else 1.0, "meeting_slo": sli >= slo.objective}


# multi-window, multi-burn-rate alerts: (long window, short window, burn threshold, severity)  [SRE Workbook, ch. 5]
BURN_ALERTS = ((3600, 300, 14.4, "page"), (6 * 3600, 1800, 6.0, "page"), (3 * DAY, 6 * 3600, 1.0, "ticket"))


def burn_alerts(reg: Registry, slo: SLO, now: Optional[float] = None) -> list[dict]:
    fired = []
    for long_w, short_w, thr, sev in BURN_ALERTS:
        bl = evaluate(reg, slo, long_w, now)["burn_rate"]
        bs = evaluate(reg, slo, short_w, now)["burn_rate"]
        if bl >= thr and bs >= thr:
            fired.append({"slo": slo.name, "severity": sev, "threshold": thr, "long_window_s": long_w,
                          "short_window_s": short_w, "burn_long": bl, "burn_short": bs})
    return fired


def slo_report(reg: Registry, slos=DEFAULT_SLOS, now: Optional[float] = None) -> list[dict]:
    out = []
    for s in slos:
        r = evaluate(reg, s, None, now); r["alerts"] = [a["severity"] for a in burn_alerts(reg, s, now)]
        out.append(r)
    return out


# ----------------------------------------------------------------------------- health
def health(engine: Engine, min_free_fraction: float = 0.10, max_scrub_age_s: float = DAY,
           max_backup_age_s: float = DAY, now: Optional[float] = None) -> dict:
    """Readiness-style report. status: ok | degraded | fail."""
    now = engine.metrics.clock() if now is None else now
    checks = []

    def add(name, status, detail):
        checks.append({"check": name, "status": status, "detail": detail})

    # storage writable
    try:
        fd, tmp = tempfile.mkstemp(dir=str(engine.storage), prefix="health.", suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(b"x"); f.flush(); os.fsync(f.fileno())
        os.unlink(tmp); add("storage_writable", "ok", "write + fsync + delete succeeded")
    except OSError as e:
        add("storage_writable", "fail", str(e))
    # disk space
    du = shutil.disk_usage(engine.storage)
    free = du.free / du.total
    add("disk_free", "ok" if free >= min_free_fraction else ("warn" if free >= 0.02 else "fail"), f"{free:.1%} free")
    # pending migration journals
    pend = len(list(engine.journal.glob("*.json")))
    add("pending_journals", "ok" if pend == 0 else "warn", f"{pend} unresolved migration journal(s)")
    # O(1) audit head consistency
    try:
        count, last = engine._scan_tail()
        head = json.loads(engine.head_path.read_text()) if engine.head_path.exists() else {"count": 0, "last_hash": "0" * 64}
        if head["count"] > count:
            add("audit_head", "fail", f"log truncated: head={head['count']} log={count}")
        elif head["count"] < count - 1:
            add("audit_head", "fail", "log has records beyond the signed head")
        else:
            add("audit_head", "ok", f"{count} records, head consistent")
    except (OSError, ValueError) as e:
        add("audit_head", "fail", f"unreadable: {e}")
    # scrub freshness
    ts = engine.metrics.get_gauge("pqc_scrub_last_timestamp_seconds")
    corrupt = engine.metrics.get_gauge("pqc_scrub_objects_corrupt", default=0)
    if corrupt:
        add("integrity", "fail", f"last scrub found {int(corrupt)} corrupt object(s)")
    elif ts is None:
        add("integrity", "warn", "no scrub has run yet")
    elif now - ts > max_scrub_age_s:
        add("integrity", "warn", f"last scrub {(now - ts) / 3600:.1f} h ago")
    else:
        add("integrity", "ok", f"last scrub {(now - ts):.0f} s ago, 0 corrupt")
    # backup freshness (RPO)
    bts = engine.metrics.get_gauge("pqc_last_backup_timestamp_seconds")
    if bts is None:
        add("backup_age", "warn", "no backup has been taken")
    elif now - bts > max_backup_age_s:
        add("backup_age", "warn", f"last backup {(now - bts) / 3600:.1f} h ago (RPO exceeded)")
    else:
        add("backup_age", "ok", f"last backup {(now - bts):.0f} s ago")
    status = "fail" if any(c["status"] == "fail" for c in checks) else ("degraded" if any(c["status"] == "warn" for c in checks) else "ok")
    engine.metrics.set_gauge("pqc_health_status", {"ok": 1, "degraded": 0.5, "fail": 0}[status])
    return {"status": status, "checks": checks}


# ----------------------------------------------------------------------------- scrubber
def scrub(engine: Engine, actor: Actor, authenticate: bool = True, object_ids: Optional[list[str]] = None) -> dict:
    """Verify every object (or a subset). Never releases plaintext. Updates gauges and writes an audit summary."""
    engine._require(actor, "scrub")
    t0 = time.perf_counter()
    objs = [m["object_id"] for m in engine.list_objects(actor)] if object_ids is None else list(object_ids)
    corrupt, ok = [], 0
    for oid in objs:
        try:
            engine.verify_object(actor, oid, authenticate)
            ok += 1
        except (IntegrityError, UnknownObject) as e:
            corrupt.append({"object_id": oid, "reason": str(e)})
    dur = time.perf_counter() - t0
    m = engine.metrics
    m.set_gauge("pqc_scrub_objects_checked", len(objs)); m.set_gauge("pqc_scrub_objects_corrupt", len(corrupt))
    m.set_gauge("pqc_scrub_last_timestamp_seconds", m.clock()); m.set_gauge("pqc_scrub_duration_seconds", dur)
    engine._audit("scrub_completed", actor, objects_checked=len(objs), objects_corrupt=len(corrupt), seconds=round(dur, 4))
    return {"checked": len(objs), "ok": ok, "corrupt": corrupt, "seconds": dur}


# ----------------------------------------------------------------------------- backup / restore
def backup(engine: Engine, actor: Actor, dest_dir: str | os.PathLike) -> dict:
    """Consistent snapshot (engine lock held) as an uncompressed tar with a SHA-256 manifest."""
    engine._require(actor, "backup")
    dest_dir = Path(dest_dir); dest_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    with engine._lock:
        engine.recover_pending()
        files = [p for p in engine.home.rglob("*") if p.is_file() and "backups_archive" not in p.parts
                 and p.suffix != ".tmp" and dest_dir not in p.parents]
        manifest = {"created_utc": now_utc(), "files": {}}
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        archive = dest_dir / f"pqc_backup_{stamp}_{int(time.time() * 1000) % 100000}.tar"
        with tarfile.open(archive, "w") as tar:
            for p in sorted(files):
                rel = str(p.relative_to(engine.home)).replace("\\", "/")
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for blk in iter(lambda: f.read(1 << 20), b""):
                        h.update(blk)
                manifest["files"][rel] = {"sha256": h.hexdigest(), "size": p.stat().st_size}
                tar.add(p, arcname=rel)
            data = json.dumps(manifest, sort_keys=True).encode()
            ti = tarfile.TarInfo("MANIFEST.json"); ti.size = len(data); tar.addfile(ti, io.BytesIO(data))
        objects = len(list(engine.storage.glob("*.json")))
    dur = time.perf_counter() - t0
    engine.metrics.set_gauge("pqc_last_backup_timestamp_seconds", engine.metrics.clock())
    engine.metrics.set_gauge("pqc_backup_duration_seconds", dur)
    engine._audit("backup_created", actor, archive=archive.name, files=len(manifest["files"]), objects=objects, seconds=round(dur, 4))
    return {"archive": str(archive), "files": len(manifest["files"]), "objects": objects, "seconds": dur,
            "bytes": archive.stat().st_size}


def restore(archive: str | os.PathLike, new_home: str | os.PathLike) -> dict:
    """Restore into an empty folder after verifying every file against the manifest."""
    t0 = time.perf_counter()
    new_home = Path(new_home); new_home.mkdir(parents=True, exist_ok=True)
    if any(new_home.iterdir()):
        raise EngineError("Restore target must be empty.")
    with tarfile.open(archive, "r") as tar:
        manifest = json.loads(tar.extractfile("MANIFEST.json").read())
        names = [m.name for m in tar.getmembers() if m.name != "MANIFEST.json"]
        if set(names) != set(manifest["files"]):
            raise IntegrityError("Backup members do not match its manifest.")
        for m in tar.getmembers():
            if m.name == "MANIFEST.json":
                continue
            if m.name.startswith("/") or ".." in Path(m.name).parts:
                raise IntegrityError("Unsafe path in backup.")
            data = tar.extractfile(m).read()
            exp = manifest["files"][m.name]
            if hashlib.sha256(data).hexdigest() != exp["sha256"] or len(data) != exp["size"]:
                raise IntegrityError(f"Backup file failed verification: {m.name}")
            out = new_home / m.name; out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(data)
    return {"files": len(manifest["files"]), "seconds": time.perf_counter() - t0, "created_utc": manifest["created_utc"]}


# ----------------------------------------------------------------------------- staged migration
def staged_migration(engine: Engine, actor: Actor, target: str = "mlkem", stages=(None, 0.10, 0.50, 1.0),
                     max_error_rate: float = 0.0, bake_seconds: float = 0.0,
                     gate: Optional[Callable[[], tuple[bool, str]]] = None) -> dict:
    """Progressive delivery of a key-protection change.

    Stage sizes are cumulative fractions of the candidate set (None = a single canary object). After every
    stage each migrated object is verified (integrity scrub). If the failure rate exceeds `max_error_rate`, or the
    optional `gate()` (e.g. an SLO burn-rate check) says no, the stage is rolled back and the rollout halts, leaving
    the remaining objects untouched.
    """
    target_alg = engine._norm(target)
    cands = [m["object_id"] for m in engine.list_objects(actor) if m["key_protection"]["algorithm"] != target_alg]
    n = len(cands); done = 0; report = {"candidates": n, "stages": [], "status": "completed", "target": target_alg}
    engine._audit("rollout_started", actor, candidates=n, target=target_alg)
    for i, frac in enumerate(stages, 1):
        upto = 1 if frac is None else max(done + 1, math.ceil(frac * n))
        upto = min(upto, n)
        batch = cands[done:upto]
        if not batch:
            continue
        t0 = time.perf_counter(); migrated, failed = [], []
        for oid in batch:
            try:
                engine.migrate(actor, oid, target)
                engine.verify_object(actor, oid, True)
                migrated.append(oid)
            except Exception as e:                       # noqa: BLE001 - any failure counts against the stage
                failed.append({"object_id": oid, "error": type(e).__name__})
        rate = len(failed) / len(batch)
        st = {"stage": i, "size": len(batch), "migrated": len(migrated), "failed": len(failed),
              "error_rate": rate, "seconds": time.perf_counter() - t0}
        gate_ok, why = (True, "") if gate is None else gate()
        if rate > max_error_rate or not gate_ok:
            rolled = 0
            for oid in migrated:
                try:
                    engine.rollback_migration(actor, oid); rolled += 1
                except EngineError:
                    pass
            st.update(halted=True, rolled_back=rolled, reason=("gate: " + why) if not gate_ok else f"error rate {rate:.0%} > {max_error_rate:.0%}")
            report["stages"].append(st); report["status"] = "halted"
            engine._audit("rollout_halted", actor, stage=i, failed=len(failed), rolled_back=rolled, reason=st["reason"])
            return report
        report["stages"].append(st); done = upto
        if bake_seconds:
            time.sleep(bake_seconds)
    engine._audit("rollout_completed", actor, migrated=done, target=target_alg)
    report["migrated"] = done
    return report
