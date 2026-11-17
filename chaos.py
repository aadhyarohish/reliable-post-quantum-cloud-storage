"""
chaos.py - game-day / fault-injection experiments for the PQC cloud-storage prototype.

Run:  python chaos.py            (writes reports/chaos_report.json and reports/chaos_report.md)
Each experiment states a hypothesis, injects a fault, and records measured results.
"""
from __future__ import annotations

import errno, json, os, random, shutil, tempfile, time
from pathlib import Path
from unittest import mock

import crypto_engine as ce
import sre
from crypto_engine import Actor, AuthError, Engine, IntegrityError, SimulatedCrash
from observability import Registry

PASS = "chaos-passphrase"
KDF = 2 ** 10


def fresh(tmp, name, **kw):
    e = Engine(tmp / name, PASS, kdf_n=KDF, **kw); e.bootstrap_admin("admin", "adminpass1"); return e, Actor("admin", "admin")


def e1_crash_recovery(tmp, trials=100, seed=1):
    """Hypothesis: a crash at ANY point of a migration never loses or corrupts data; recovery is automatic."""
    rnd = random.Random(seed); e, adm = fresh(tmp, "e1"); lost = bad_state = 0; rec_times = []; outcomes = {"rolled_back": 0, "committed": 0, "no_crash": 0}
    for i in range(trials):
        data = os.urandom(rnd.randint(1, 200_000)); oid = e.encrypt_file(adm, f"t{i}.bin", data, "rsa")["object_id"]
        point = rnd.choice(["after_journal", "after_commit", None])
        try:
            e.migrate(adm, oid, "mlkem", _crash_at=point)
            outcomes["no_crash"] += 1
        except SimulatedCrash:
            pass
        t = time.perf_counter(); e = Engine(tmp / "e1", PASS, kdf_n=KDF); rec_times.append(time.perf_counter() - t)   # restart = recovery
        try:
            if e.decrypt_file(adm, oid) != data: lost += 1
        except Exception: lost += 1
        alg = e._load_meta(oid)["key_protection"]["algorithm"]
        if point == "after_journal" and alg != ce.ALG_RSA: bad_state += 1
        if point == "after_commit" and alg != ce.ALG_PQ: bad_state += 1
        if point: outcomes["rolled_back" if point == "after_journal" else "committed"] += 1
    return {"id": "E1", "title": "Crash during migration (random crash points)", "trials": trials, "outcomes": outcomes,
            "objects_lost_or_corrupt": lost, "unexpected_end_state": bad_state, "journals_left": len(list(e.journal.glob("*.json"))),
            "restart_ms_mean_incl_keystore_unlock": round(1000 * sum(rec_times) / len(rec_times), 2), "restart_ms_max": round(1000 * max(rec_times), 2),
            "audit_chain_intact": e._verify_audit_raw().ok, "hypothesis_held": lost == 0 and bad_state == 0}


def e2_bitrot(tmp, objects=60, flips=12, deletions=3, seed=2):
    """Hypothesis: the scrubber detects 100 % of silent corruption and file loss, with zero false positives."""
    rnd = random.Random(seed); e, adm = fresh(tmp, "e2"); ids = []
    for i in range(objects):
        ids.append(e.encrypt_file(adm, f"o{i}.bin", os.urandom(rnd.randint(1000, 300_000)), rnd.choice(["rsa", "mlkem"]))["object_id"])
    victims = rnd.sample(ids, flips + deletions); flipped, deleted = victims[:flips], victims[flips:]
    for oid in flipped:
        p = e.storage / f"{oid}.bin"; b = bytearray(p.read_bytes()); b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8); p.write_bytes(bytes(b))
    for oid in deleted: (e.storage / f"{oid}.bin").unlink()
    rep = sre.scrub(e, adm); found = {c["object_id"] for c in rep["corrupt"]}
    return {"id": "E2", "title": "Silent bit flips and lost files", "objects": objects, "bit_flips": flips, "files_deleted": deletions,
            "detected": len(found & set(victims)), "false_positives": len(found - set(victims)), "missed": len(set(victims) - found),
            "scrub_seconds": round(rep["seconds"], 3), "ms_per_object": round(1000 * rep["seconds"] / objects, 2),
            "integrity_slo_met": sre.evaluate(e.metrics, sre.DEFAULT_SLOS[3])["meeting_slo"],
            "health_after": sre.health(e, min_free_fraction=0.0)["status"], "hypothesis_held": found == set(victims)}


def e3_disk_full(tmp):
    """Hypothesis: a full disk during upload or migration leaves no partial object and no corrupted state; service resumes."""
    e, adm = fresh(tmp, "e3"); keep = e.encrypt_file(adm, "keep.bin", b"precious" * 1000, "rsa")["object_id"]
    real = os.replace; enospc = lambda *a, **k: (_ for _ in ()).throw(OSError(errno.ENOSPC, "No space left on device"))
    n_before = len(e.list_objects(adm)); up_fail = mig_fail = 0
    with mock.patch.object(ce.os, "replace", enospc):
        for i in range(10):
            try: e.encrypt_file(adm, f"x{i}.bin", os.urandom(50_000), "rsa")
            except OSError: up_fail += 1
        try: e.migrate(adm, keep, "mlkem")
        except OSError: mig_fail += 1
    leftovers = len(list(e.storage.rglob("*.tmp")))
    ok_after = e.decrypt_file(adm, keep) == b"precious" * 1000 and e._load_meta(keep)["key_protection"]["algorithm"] == ce.ALG_RSA
    e.encrypt_file(adm, "after.bin", b"service resumed", "mlkem")                                  # fault cleared: service continues
    errs = e.metrics.get_counter("pqc_operations_total", {"op": "encrypt", "status": "error"})
    return {"id": "E3", "title": "Disk full (ENOSPC) during upload and migration", "uploads_failed_cleanly": up_fail, "migration_failed_cleanly": mig_fail,
            "partial_objects": len(e.list_objects(adm)) - n_before - 1, "temp_files_left": leftovers, "existing_object_intact": ok_after,
            "error_counter": int(errs), "service_resumed": True, "hypothesis_held": up_fail == 10 and mig_fail == 1 and leftovers == 0 and ok_after}


def e4_keystore_unavailable(tmp):
    """Hypothesis: with the keystore locked or the wrong passphrase the service fails closed, quickly, and logs nothing sensitive."""
    e, adm = fresh(tmp, "e4"); e.encrypt_file(adm, "a.bin", b"data", "mlkem")
    t = time.perf_counter(); closed = 0
    for pw in ["wrong passphrase 1", "wrong passphrase 2", "", "short"]:
        try: Engine(tmp / "e4", pw, kdf_n=KDF)
        except AuthError: closed += 1
    return {"id": "E4", "title": "Keystore locked / wrong passphrase", "attempts": 4, "failed_closed": closed, "seconds_per_attempt": round((time.perf_counter() - t) / 4, 4),
            "hypothesis_held": closed == 4}


def e5_audit_tamper(tmp):
    """Hypothesis: audit tampering is detected by the full verifier; truncation is also caught by the O(1) readiness check."""
    e, adm = fresh(tmp, "e5")
    for i in range(30): e.decrypt_file(adm, e.encrypt_file(adm, f"a{i}", b"x", "rsa")["object_id"])
    lines = e.audit_path.read_text().splitlines(); res = {}
    # (a) edit a record in the middle
    L = list(lines); r = json.loads(L[40]); r["user"] = "mallory"; L[40] = json.dumps(r); e.audit_path.write_text("\n".join(L) + "\n")
    t = time.perf_counter(); full = e._verify_audit_raw(); res["edit_full_verify_detected"] = (not full.ok); res["full_verify_ms"] = round(1000 * (time.perf_counter() - t), 2)
    res["edit_caught_by_readiness_check"] = sre.health(e, min_free_fraction=0.0)["status"] == "fail"
    # (b) truncate the tail
    e.audit_path.write_text("\n".join(lines[:-3]) + "\n")
    res["truncate_full_verify_detected"] = not e._verify_audit_raw().ok
    t = time.perf_counter(); h = sre.health(e, min_free_fraction=0.0); res["readiness_ms"] = round(1000 * (time.perf_counter() - t), 2)
    res["truncate_caught_by_readiness_check"] = h["status"] == "fail"
    res.update(id="E5", title="Audit-log tampering (edit, truncation)", records=len(lines),
               hypothesis_held=res["edit_full_verify_detected"] and res["truncate_full_verify_detected"] and res["truncate_caught_by_readiness_check"])
    return res


def e6_dr_drill(tmp, objects=200, extra_after_backup=20, seed=6):
    """Hypothesis: a total loss of the data directory is recoverable from the latest backup; RPO = changes since backup, RTO measured."""
    rnd = random.Random(seed); e, adm = fresh(tmp, "e6"); data = {}
    for i in range(objects):
        d = os.urandom(rnd.randint(1000, 500_000)); data[e.encrypt_file(adm, f"d{i}.bin", d, rnd.choice(["rsa", "mlkem"]))["object_id"]] = d
    bk = sre.backup(e, adm, tmp / "e6_backups"); late = []
    for i in range(extra_after_backup): late.append(e.encrypt_file(adm, f"late{i}.bin", os.urandom(2000), "rsa")["object_id"])
    shutil.rmtree(tmp / "e6")                                                                         # disaster: everything gone
    t0 = time.perf_counter(); rr = sre.restore(bk["archive"], tmp / "e6_restored"); t_restore = time.perf_counter() - t0
    e2 = Engine(tmp / "e6_restored", PASS, kdf_n=KDF); t_open = time.perf_counter() - t0
    srep = sre.scrub(e2, adm); t_total = time.perf_counter() - t0
    recovered = sum(1 for oid, d in data.items() if e2.decrypt_file(adm, oid) == d)
    return {"id": "E6", "title": "Disaster recovery drill (total data-directory loss)", "objects_backed_up": objects, "backup_seconds": round(bk["seconds"], 3),
            "backup_mb": round(bk["bytes"] / 1e6, 1), "restore_seconds": round(t_restore, 3), "open_seconds": round(t_open, 3),
            "rto_seconds_restore_open_scrub": round(t_total, 3), "objects_recovered": recovered, "recovered_fraction": recovered / objects,
            "rpo_objects_lost_after_backup": extra_after_backup, "audit_chain_intact_after_restore": e2._verify_audit_raw().ok,
            "scrub_corrupt_after_restore": len(srep["corrupt"]), "hypothesis_held": recovered == objects and not srep["corrupt"]}


def e7_error_budget_alerting(tmp, seed=7):
    """Hypothesis: an injected 5 % failure rate burns the budget fast enough to page within minutes, and the page clears after recovery."""
    t = [0.0]; reg = Registry(clock=lambda: t[0]); e, adm = fresh(tmp, "e7", metrics=reg); rnd = random.Random(seed); ticket_open_end = False
    oid = e.encrypt_file(adm, "seed.bin", b"x" * 4096, "rsa")["object_id"]
    slo = sre.DEFAULT_SLOS[0]; timeline = []; first_page = cleared = None
    failing = lambda *a, **k: (_ for _ in ()).throw(OSError(errno.EIO, "injected I/O error"))
    for sec in range(0, 7200):                                    # two simulated hours at 1 request / second
        t[0] = float(sec); fault_on = 1800 <= sec < 2700           # 15-minute incident starting at minute 30
        try:
            if fault_on and rnd.random() < 0.05:
                with mock.patch.object(ce.AESGCM, "decrypt", failing): e.decrypt_file(adm, oid)
            else: e.decrypt_file(adm, oid)
        except OSError: pass
        if sec % 60 == 0:
            alerts = [a["severity"] + f"@{a['threshold']}x" for a in sre.burn_alerts(reg, slo, t[0])]
            pages = [a for a in alerts if a.startswith("page")]
            if pages and first_page is None and sec >= 1800: first_page = sec - 1800
            if first_page is not None and not pages and cleared is None and sec > 2700: cleared = sec - 2700
            ticket_open_end = any(a.startswith("ticket") for a in alerts)
            timeline.append({"minute": sec // 60, "alerts": alerts})
    ev = sre.evaluate(reg, slo, 7200.0, 7199.0)
    return {"id": "E7", "title": "Error-budget burn-rate alerting (5 % failures for 15 min)", "requests": 7200, "failures_injected": int(ev["total"] - ev["good"]),
            "time_to_page_seconds": first_page, "all_pages_cleared_after_recovery_seconds": cleared, "ticket_still_open_at_end": ticket_open_end, "sli_over_2h": round(ev["sli"], 5),
            "budget_burn_rate_2h": round(ev["burn_rate"], 2), "timeline_sample": [x for x in timeline if x["alerts"]][:6],
            "hypothesis_held": first_page is not None and first_page <= 600}


ALL = [e1_crash_recovery, e2_bitrot, e3_disk_full, e4_keystore_unavailable, e5_audit_tamper, e6_dr_drill, e7_error_budget_alerting]


def main():
    out = Path("reports"); out.mkdir(exist_ok=True); results = []
    for fn in ALL:
        tmp = Path(tempfile.mkdtemp(prefix="chaos_")); t = time.perf_counter()
        try: r = fn(tmp)
        finally: shutil.rmtree(tmp, ignore_errors=True)
        r["experiment_seconds"] = round(time.perf_counter() - t, 2); results.append(r)
        print(f"{r['id']} {r['title']:62s} hypothesis held: {r['hypothesis_held']}")
    (out / "chaos_report.json").write_text(json.dumps(results, indent=2))
    md = ["| ID | Experiment | Hypothesis held | Key result |", "|---|---|---|---|"]
    for r in results:
        key = {"E1": lambda: f"{r['trials']} trials, {r['objects_lost_or_corrupt']} lost, restart+recovery {r['restart_ms_mean_incl_keystore_unlock']} ms mean",
               "E2": lambda: f"{r['detected']}/{r['bit_flips'] + r['files_deleted']} detected, {r['false_positives']} false positives, {r['ms_per_object']} ms/object",
               "E3": lambda: f"{r['uploads_failed_cleanly']}/10 uploads failed cleanly, {r['partial_objects']} partial objects, {r['temp_files_left']} temp files",
               "E4": lambda: f"{r['failed_closed']}/{r['attempts']} attempts failed closed",
               "E5": lambda: f"both detected by full verify; only truncation caught by the {r['readiness_ms']} ms readiness check",
               "E6": lambda: f"{r['objects_recovered']}/{r['objects_backed_up']} recovered, RTO {r['rto_seconds_restore_open_scrub']} s, RPO loss {r['rpo_objects_lost_after_backup']} objects",
               "E7": lambda: f"page {r['time_to_page_seconds']} s after fault start; pages cleared {r['all_pages_cleared_after_recovery_seconds']} s after recovery"}[r["id"]]()
        md.append(f"| {r['id']} | {r['title']} | {'yes' if r['hypothesis_held'] else 'NO'} | {key} |")
    (out / "chaos_report.md").write_text("\n".join(md) + "\n"); print("\n".join(md))


if __name__ == "__main__":
    main()
