"""
loadtest.py - concurrent mixed-workload load test + audit-append scaling test.

Run:  python loadtest.py                      (default: 8 workers, 1500 ops, 20 000-record audit log)
      python loadtest.py --workers 4 --ops 600 --audit-prefill 5000
Writes reports/loadtest.json and reports/loadtest.md
"""
from __future__ import annotations

import argparse, json, os, platform, random, shutil, statistics as st, sys, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import sre
from crypto_engine import Actor, Engine, GENESIS, canon, now_utc, atomic_write_bytes
from observability import Registry

PASS = "loadtest-passphrase"


def prefill_audit(e: Engine, n: int) -> None:
    """Write a valid HMAC chain of n synthetic records quickly (no fsync per record)."""
    count, prev = e._scan_tail()
    lines = []
    for i in range(n):
        count += 1
        rec = {"seq": count, "timestamp_utc": now_utc(), "event": "synthetic", "user": "loadgen", "role": "admin", "prev_hash": prev}
        rec["hash"] = e._mac(canon(rec)); prev = rec["hash"]; lines.append(canon(rec))
    with open(e.audit_path, "ab") as f:
        f.write(b"\n".join(lines) + b"\n")
    head = {"count": count, "last_hash": prev}; head["mac"] = e._mac(canon(head))
    atomic_write_bytes(e.head_path, canon(head)); e._tail = (count, prev)


def audit_scaling(sizes=(0, 1000, 5000, 20000, 50000), appends=150) -> list[dict]:
    rows = []
    for n in sizes:
        row = {"audit_records": n}
        for cache in (False, True):
            tmp = Path(tempfile.mkdtemp(prefix="auditscale_"))
            try:
                e = Engine(tmp, PASS, kdf_n=2 ** 10, cache_tail=cache); e.bootstrap_admin("admin", "adminpass1"); a = Actor("admin", "admin")
                prefill_audit(e, n); e._tail = None            # force a cold start for both modes
                ts = []
                for _ in range(appends):
                    t = time.perf_counter(); e._audit("probe", a); ts.append((time.perf_counter() - t) * 1000)
                row["v2_scan_ms_mean" if not cache else "v3_cached_ms_mean"] = round(st.mean(ts), 3)
                row["v2_scan_ms_p99" if not cache else "v3_cached_ms_p99"] = round(sorted(ts)[int(0.99 * len(ts)) - 1], 3)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        row["speedup"] = round(row["v2_scan_ms_mean"] / row["v3_cached_ms_mean"], 1)
        rows.append(row); print("  audit-scaling", row)
    return rows


def mixed_load(cache_tail: bool, workers: int, ops: int, prefill: int, seed: int = 11) -> dict:
    rnd = random.Random(seed); tmp = Path(tempfile.mkdtemp(prefix="load_"))
    try:
        reg = Registry(); e = Engine(tmp, PASS, kdf_n=2 ** 10, metrics=reg, cache_tail=cache_tail)
        e.bootstrap_admin("admin", "adminpass1"); adm = Actor("admin", "admin")
        ids = [e.encrypt_file(adm, f"seed{i}.bin", os.urandom(rnd.randint(64, 256) * 1024), "rsa")["object_id"] for i in range(40)]
        prefill_audit(e, prefill)
        reg.events.clear(); lock = threading.Lock(); pool = list(ids); migr = []; errors = [0]; plan = [rnd.random() for _ in range(ops)]
        payloads = [os.urandom(rnd.randint(64, 256) * 1024) for _ in range(20)]

        def work(i):
            r = plan[i]
            try:
                if r < 0.35:
                    m = e.encrypt_file(adm, f"w{i}.bin", payloads[i % 20], "rsa")
                    with lock: pool.append(m["object_id"])
                elif r < 0.75:
                    with lock: oid = pool[i % len(pool)]
                    e.decrypt_file(adm, oid)
                elif r < 0.90:
                    e.list_objects(adm)
                else:
                    with lock: oid = pool[(i * 7) % len(pool)]
                    e.migrate(adm, oid, "mlkem")
            except Exception:
                with lock: errors[0] += 1

        t0 = time.perf_counter()
        with ThreadPoolExecutor(workers) as ex: list(ex.map(work, range(ops)))
        wall = time.perf_counter() - t0
        per_op = {}
        for op in ("encrypt", "decrypt", "list", "migrate"):
            xs = sorted(ev.seconds * 1000 for ev in reg.events if ev.op == op and ev.status == "ok")
            if xs: per_op[op] = {"n": len(xs), "p50_ms": round(xs[len(xs) // 2], 2), "p95_ms": round(xs[int(.95 * len(xs)) - 1], 2),
                                 "p99_ms": round(xs[min(len(xs) - 1, int(.99 * len(xs)))], 2), "max_ms": round(xs[-1], 2)}
        slos = sre.slo_report(reg)
        return {"cache_tail": cache_tail, "workers": workers, "ops": ops, "audit_prefill": prefill, "wall_seconds": round(wall, 2),
                "throughput_ops_s": round(ops / wall, 1), "errors": errors[0], "per_op": per_op,
                "slo": [{k: (round(v, 5) if isinstance(v, float) else v) for k, v in s.items() if k in ("slo", "sli", "burn_rate", "meeting_slo", "good", "total")} for s in slos[:3]],
                "audit_chain_intact": e._verify_audit_raw().ok}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--workers", type=int, default=8); ap.add_argument("--ops", type=int, default=1500)
    ap.add_argument("--audit-prefill", type=int, default=20000); a = ap.parse_args()
    env = {"platform": platform.platform(), "python": sys.version.split()[0], "cpu_count": os.cpu_count()}
    print("Environment:", env); print("Audit append scaling")
    scaling = audit_scaling(); results = {}
    for name, cache in (("v2_scan", False), ("v3_cached", True)):
        print("Mixed load:", name); results[name] = mixed_load(cache, a.workers, a.ops, a.audit_prefill); print("  ", {k: results[name][k] for k in ("wall_seconds", "throughput_ops_s", "errors")})
    out = Path("reports"); out.mkdir(exist_ok=True)
    (out / "loadtest.json").write_text(json.dumps({"environment": env, "audit_scaling": scaling, "mixed_load": results}, indent=2))
    md = ["| Audit records | v2 append (ms) | v3 append (ms) | Speed-up |", "|---|---|---|---|"] + [f"| {r['audit_records']} | {r['v2_scan_ms_mean']} | {r['v3_cached_ms_mean']} | {r['speedup']}x |" for r in scaling]
    md += ["", "| Version | Op | n | p50 (ms) | p95 (ms) | p99 (ms) |", "|---|---|---|---|---|---|"]
    for name, r in results.items():
        for op, v in r["per_op"].items(): md.append(f"| {name} | {op} | {v['n']} | {v['p50_ms']} | {v['p95_ms']} | {v['p99_ms']} |")
    (out / "loadtest.md").write_text("\n".join(md) + "\n"); print("\n".join(md))


if __name__ == "__main__":
    main()
