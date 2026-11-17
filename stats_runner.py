"""
stats_runner.py - repeat the key experiments many times and report mean, SD, 95 % CI, Wilson bounds and Welch tests.

Run:  python stats_runner.py                  (about 15 minutes on one CPU)
      python stats_runner.py --quick          (small run for a smoke test)
Writes reports/statistics.json and reports/statistics.md; results are saved after every section.
"""
from __future__ import annotations

import argparse, json, os, shutil, tempfile, time
from pathlib import Path

import bench, chaos, loadtest
import stats as S

OUT = Path("reports"); OUT.mkdir(exist_ok=True)
R: dict = {}


def save():
    (OUT / "statistics.json").write_text(json.dumps(R, indent=2, default=str))


def tmp():
    return Path(tempfile.mkdtemp(prefix="stat_"))


def run_chaos(fn, seeds, **kw):
    out = []
    for sd in seeds:
        t = tmp()
        try:
            out.append(fn(t, seed=sd, **kw) if "seed" in fn.__code__.co_varnames else fn(t, **kw))
        finally:
            shutil.rmtree(t, ignore_errors=True)
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--quick", action="store_true"); a = ap.parse_args()
    reps = 3 if a.quick else 10; seeds = list(range(1, reps + 1))
    sizes = [1, 10] if a.quick else [1, 10, 100, 500]
    t0 = time.time()

    # ---------------------------------------------------------------- A. migration vs naive (n repeats per size)
    print("A. file benchmarks", flush=True)
    bench.files(sizes, reps)
    R["migration_benchmark"] = {}
    for mib, res in bench.LAST_RAW.items():
        row = {k: S.summarize(v) for k, v in res.items()}
        row["speedup_mean"] = row["naive"]["mean"] / row["migrate"]["mean"]
        row["welch_naive_vs_migrate"] = S.welch(res["naive"], res["migrate"])
        R["migration_benchmark"][str(mib)] = row
    save()

    # ---------------------------------------------------------------- B. primitive operations (200 samples each)
    print("B. primitives", flush=True)
    import os as _os, time as _t
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import mlkem, padding, rsa
    n = 60 if a.quick else 200
    rk = rsa.generate_private_key(65537, 3072); rp = rk.public_key(); oaep = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    dek = _os.urandom(32); ct = rp.encrypt(dek, oaep); mk = mlkem.MLKEM768PrivateKey.generate(); mp = mk.public_key(); ss, kct = mp.encapsulate()
    def samp(fn):
        xs = []
        for _ in range(n):
            t = _t.perf_counter(); fn(); xs.append((_t.perf_counter() - t) * 1000)
        return xs
    ops = {"RSA-3072 wrap": samp(lambda: rp.encrypt(dek, oaep)), "RSA-3072 unwrap": samp(lambda: rk.decrypt(ct, oaep)),
           "ML-KEM-768 encapsulate": samp(lambda: mp.encapsulate()), "ML-KEM-768 decapsulate": samp(lambda: mk.decapsulate(kct)),
           "ML-KEM-768 keygen": samp(lambda: mlkem.MLKEM768PrivateKey.generate())}
    R["primitives_ms"] = {k: S.summarize(v) for k, v in ops.items()}
    R["primitives_ms"]["unwrap_speedup_welch"] = S.welch(ops["RSA-3072 unwrap"], ops["ML-KEM-768 decapsulate"])
    save()

    # ---------------------------------------------------------------- C. chaos experiments over many seeds
    print("C. chaos", flush=True)
    c = {}
    e1 = run_chaos(chaos.e1_crash_recovery, seeds, trials=40 if a.quick else 100)
    tr = sum(r["trials"] for r in e1); lost = sum(r["objects_lost_or_corrupt"] + r["unexpected_end_state"] for r in e1)
    c["E1"] = {"runs": len(e1), "trials": tr, "failures": lost, "wilson95": S.wilson(lost, tr),
               "restart_ms": S.summarize([r["restart_ms_mean_incl_keystore_unlock"] for r in e1]), "all_chains_intact": all(r["audit_chain_intact"] for r in e1)}
    e2 = run_chaos(chaos.e2_bitrot, seeds, objects=30 if a.quick else 60, flips=6 if a.quick else 12, deletions=2 if a.quick else 3)
    inj = sum(r["bit_flips"] + r["files_deleted"] for r in e2); det = sum(r["detected"] for r in e2); fp = sum(r["false_positives"] for r in e2); clean = sum(r["objects"] - r["bit_flips"] - r["files_deleted"] for r in e2)
    c["E2"] = {"runs": len(e2), "injected": inj, "detected": det, "detection_wilson95": S.wilson(det, inj), "false_positives": fp, "clean_objects": clean,
               "fp_wilson95": S.wilson(fp, clean), "ms_per_object": S.summarize([r["ms_per_object"] for r in e2])}
    e3 = run_chaos(chaos.e3_disk_full, seeds); c["E3"] = {"runs": len(e3), "held": sum(r["hypothesis_held"] for r in e3), "wilson95": S.wilson(sum(r["hypothesis_held"] for r in e3), len(e3))}
    e4 = run_chaos(chaos.e4_keystore_unavailable, seeds); c["E4"] = {"runs": len(e4), "failed_closed": sum(r["failed_closed"] for r in e4), "attempts": sum(r["attempts"] for r in e4),
        "wilson95": S.wilson(sum(r["failed_closed"] for r in e4), sum(r["attempts"] for r in e4))}
    e5 = run_chaos(chaos.e5_audit_tamper, seeds); c["E5"] = {"runs": len(e5), "full_verify_detected_edit": sum(r["edit_full_verify_detected"] for r in e5),
        "readiness_caught_edit": sum(r["edit_caught_by_readiness_check"] for r in e5), "readiness_caught_truncation": sum(r["truncate_caught_by_readiness_check"] for r in e5),
        "readiness_ms": S.summarize([r["readiness_ms"] for r in e5]), "full_verify_ms": S.summarize([r["full_verify_ms"] for r in e5])}
    e6 = run_chaos(chaos.e6_dr_drill, seeds, objects=60 if a.quick else 200, extra_after_backup=10 if a.quick else 20)
    objs = sum(r["objects_backed_up"] for r in e6); rec = sum(r["objects_recovered"] for r in e6)
    c["E6"] = {"runs": len(e6), "objects": objs, "recovered": rec, "wilson95": S.wilson(rec, objs), "rto_s": S.summarize([r["rto_seconds_restore_open_scrub"] for r in e6]),
               "backup_s": S.summarize([r["backup_seconds"] for r in e6]), "restore_s": S.summarize([r["restore_seconds"] for r in e6])}
    R["chaos"] = c; save()
    if not a.quick:
        e7 = run_chaos(chaos.e7_error_budget_alerting, seeds)
        c["E7"] = {"runs": len(e7), "time_to_page_s": S.summarize([r["time_to_page_seconds"] for r in e7]), "pages_cleared_s": S.summarize([r["all_pages_cleared_after_recovery_seconds"] for r in e7]),
                   "burn_rate_2h": S.summarize([r["budget_burn_rate_2h"] for r in e7]), "all_paged_within_600s": all(r["time_to_page_seconds"] is not None and r["time_to_page_seconds"] <= 600 for r in e7)}
        save()

    # ---------------------------------------------------------------- D. load test repeats + audit scaling repeats
    print("D. load", flush=True)
    nload = 3 if a.quick else 5; ops_n = 400 if a.quick else 1500; pre = 3000 if a.quick else 20000
    runs = {"v2": [], "v3": []}
    for i in range(nload):
        for name, cache in (("v2", False), ("v3", True)):
            runs[name].append(loadtest.mixed_load(cache, 8, ops_n, pre, seed=100 + i))
    d = {}
    for name, rr in runs.items():
        d[name] = {"throughput_ops_s": S.summarize([r["throughput_ops_s"] for r in rr]), "errors": sum(r["errors"] for r in rr), "chains_intact": all(r["audit_chain_intact"] for r in rr)}
        for op in ("encrypt", "decrypt", "migrate"):
            d[name][f"{op}_p50_ms"] = S.summarize([r["per_op"][op]["p50_ms"] for r in rr]); d[name][f"{op}_p99_ms"] = S.summarize([r["per_op"][op]["p99_ms"] for r in rr])
    d["throughput_welch_v2_vs_v3"] = S.welch([r["throughput_ops_s"] for r in runs["v2"]], [r["throughput_ops_s"] for r in runs["v3"]])
    d["decrypt_p99_welch_v2_vs_v3"] = S.welch([r["per_op"]["decrypt"]["p99_ms"] for r in runs["v2"]], [r["per_op"]["decrypt"]["p99_ms"] for r in runs["v3"]])
    sizes_a = (0, 1000, 5000) if a.quick else (0, 1000, 5000, 20000, 50000)
    sc = [loadtest.audit_scaling(sizes_a, 60 if a.quick else 150) for _ in range(2 if a.quick else 3)]
    d["audit_scaling"] = [{"records": sz, "v2_ms": S.summarize([rep[i]["v2_scan_ms_mean"] for rep in sc]), "v3_ms": S.summarize([rep[i]["v3_cached_ms_mean"] for rep in sc])} for i, sz in enumerate(sizes_a)]
    R["load"] = d; R["meta"] = {"repeats": reps, "load_repeats": nload, "seconds": round(time.time() - t0, 1), "cpu_count": os.cpu_count()}; save()

    # ---------------------------------------------------------------- markdown summary
    f = lambda s, dg=3, unit="": S.fmt(s, dg, unit)
    md = ["# Statistical summary", f"(n = {reps} repeats per experiment unless stated; mean \u00b1 sample SD with 95 % t-interval; proportions use Wilson 95 % intervals)", ""]
    md += ["## Migration vs naive re-encryption (seconds)", "| MiB | migrate | migrate + SHA-256 | naive | speed-up | Welch p |", "|---|---|---|---|---|---|"]
    for mib, r in R["migration_benchmark"].items():
        md.append(f"| {mib} | {f(r['migrate'])} | {f(r['migrate_deep'])} | {f(r['naive'])} | {r['speedup_mean']:.0f}x | {r['welch_naive_vs_migrate']['p']:.2g} |")
    md += ["", "## Chaos experiments"]
    for k, v in c.items(): md.append(f"* {k}: {json.dumps(v, default=str)[:400]}")
    md += ["", "## Load test (v2 scan vs v3 cached tail)", f"* throughput v2: {f(d['v2']['throughput_ops_s'])} ops/s; v3: {f(d['v3']['throughput_ops_s'])} ops/s; Welch p = {d['throughput_welch_v2_vs_v3']['p']:.2g}"]
    (OUT / "statistics.md").write_text("\n".join(md) + "\n"); print("done in", round(time.time() - t0), "s")


if __name__ == "__main__":
    main()
