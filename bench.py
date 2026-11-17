"""
bench.py - performance evaluation for the PQC cloud-storage prototype.

Usage:   python bench.py                 (sizes 1, 10, 100, 500 MiB)
         python bench.py --sizes 1 10 50 --repeats 3 --ops 200

Writes to reports/: benchmark_ops.csv, benchmark_files.csv, benchmark_env.json, benchmark.md
(and benchmark_migration.png if matplotlib is installed).
Compares: encrypt, decrypt, MIGRATION (DEK re-wrap only) and a NAIVE baseline that re-encrypts the payload.
"""
import argparse, csv, json, os, platform, shutil, statistics as st, sys, tempfile, time
from pathlib import Path
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from crypto_engine import Engine, Actor

OUT = Path("reports"); OUT.mkdir(exist_ok=True)
LAST_RAW = {}     # size_mib -> metric -> list of per-repeat seconds (used by stats_runner.py)


def timeit(fn, n):
    ts = []
    for _ in range(n):
        t = time.perf_counter(); fn(); ts.append((time.perf_counter() - t) * 1e3)
    return st.median(ts), st.mean(ts), min(ts)


def micro(n):
    rows = []
    rk = rsa.generate_private_key(65537, 3072); rp = rk.public_key()
    oaep = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    dek = os.urandom(32); ct = rp.encrypt(dek, oaep)
    mk = mlkem.MLKEM768PrivateKey.generate(); mp = mk.public_key()
    ss, kct = mp.encapsulate()
    ops = [("RSA-3072 key generation", lambda: rsa.generate_private_key(65537, 3072), max(3, n // 40)),
           ("RSA-OAEP-SHA256 wrap (public)", lambda: rp.encrypt(dek, oaep), n),
           ("RSA-OAEP-SHA256 unwrap (private)", lambda: rk.decrypt(ct, oaep), n),
           ("ML-KEM-768 key generation", lambda: mlkem.MLKEM768PrivateKey.generate(), n),
           ("ML-KEM-768 encapsulation", lambda: mp.encapsulate(), n),
           ("ML-KEM-768 decapsulation", lambda: mk.decapsulate(kct), n),
           ("HKDF-SHA256 (32 B)", lambda: HKDF(hashes.SHA256(), 32, None, b"x").derive(ss), n)]
    for name, fn, k in ops:
        med, mean, mn = timeit(fn, k); rows.append({"operation": name, "iterations": k, "median_ms": round(med, 4), "mean_ms": round(mean, 4), "min_ms": round(mn, 4)})
        print(f"  {name:36s} median {med:9.4f} ms")
    rows.append({"operation": "ML-KEM-768 public key / ciphertext size (bytes)", "iterations": 0, "median_ms": len(mp.public_bytes_raw()), "mean_ms": len(kct), "min_ms": 0})
    rows.append({"operation": "RSA-3072 wrapped-DEK size (bytes)", "iterations": 0, "median_ms": len(ct), "mean_ms": 0, "min_ms": 0})
    return rows


def make_file(path, mib):
    with open(path, "wb") as f:
        for _ in range(mib):
            f.write(os.urandom(1 << 20))


def files(sizes, repeats):
    rows = []
    tmp = Path(tempfile.mkdtemp(prefix="pqcbench_"))
    try:
        eng = Engine(tmp / "home", "benchmark-passphrase", kdf_n=2 ** 12)
        eng.bootstrap_admin("admin", "adminpass1"); adm = Actor("admin", "admin")
        for mib in sizes:
            src = tmp / f"in_{mib}.bin"; make_file(src, mib)
            res = {k: [] for k in ["enc_rsa", "enc_pq", "dec", "migrate", "migrate_deep", "naive"]}
            for _ in range(repeats):
                t = time.perf_counter(); m = eng.encrypt_path(adm, src, "rsa"); res["enc_rsa"].append(time.perf_counter() - t)
                t = time.perf_counter(); eng.encrypt_path(adm, src, "mlkem"); res["enc_pq"].append(time.perf_counter() - t)
                out = tmp / "out.bin"
                t = time.perf_counter(); eng.decrypt_to_path(adm, m["object_id"], out); res["dec"].append(time.perf_counter() - t); out.unlink()
                m2 = eng.encrypt_path(adm, src, "rsa")
                t = time.perf_counter(); eng.migrate(adm, m2["object_id"], "mlkem"); res["migrate"].append(time.perf_counter() - t)
                m3 = eng.encrypt_path(adm, src, "rsa")
                t = time.perf_counter(); eng.migrate(adm, m3["object_id"], "mlkem", deep_verify=True); res["migrate_deep"].append(time.perf_counter() - t)
                t = time.perf_counter()                       # naive baseline: decrypt everything, encrypt again
                eng.decrypt_to_path(adm, m["object_id"], out); eng.encrypt_path(adm, out, "mlkem"); res["naive"].append(time.perf_counter() - t); out.unlink()
            # free disk after every repeat: each object of a large size is hundreds of MiB
                for p in (tmp / "home" / "storage").glob("*.*"):
                    if p.is_file(): p.unlink()
            LAST_RAW[mib] = {k: list(v) for k, v in res.items()}
            r = {"size_mib": mib, **{k + "_s": round(st.median(v), 5) for k, v in res.items()}}
            r["encrypt_MiB_per_s"] = round(mib / r["enc_pq_s"], 1); r["decrypt_MiB_per_s"] = round(mib / r["dec_s"], 1)
            r["speedup_vs_naive"] = round(r["naive_s"] / r["migrate_s"], 1)
            rows.append(r); print("  ", r)
            src.unlink()
            for p in (tmp / "home" / "storage").glob("*.*"):
                if p.is_file(): p.unlink()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return rows


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--sizes", type=int, nargs="+", default=[1, 10, 100, 500])
    ap.add_argument("--repeats", type=int, default=3); ap.add_argument("--ops", type=int, default=200)
    a = ap.parse_args()
    env = {"platform": platform.platform(), "python": sys.version.split()[0], "cryptography": cryptography.__version__,
           "cpu_count": os.cpu_count(), "processor": platform.processor() or platform.machine(), "repeats": a.repeats}
    print("Environment:", env); (OUT / "benchmark_env.json").write_text(json.dumps(env, indent=2))
    print("Micro-benchmarks"); ops = micro(a.ops)
    print("File benchmarks"); fr = files(a.sizes, a.repeats)
    for name, rows in (("benchmark_ops.csv", ops), ("benchmark_files.csv", fr)):
        with open(OUT / name, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    md = ["| Size (MiB) | Encrypt (s) | Decrypt (s) | Migrate (s) | Migrate + SHA-256 check (s) | Naive re-encrypt (s) | Speed-up |", "|---|---|---|---|---|---|---|"]
    for r in fr:
        md.append(f"| {r['size_mib']} | {r['enc_pq_s']} | {r['dec_s']} | {r['migrate_s']} | {r['migrate_deep_s']} | {r['naive_s']} | {r['speedup_vs_naive']}x |")
    (OUT / "benchmark.md").write_text("\n".join(md) + "\n"); print("\n".join(md))
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        x = [r["size_mib"] for r in fr]
        plt.figure(figsize=(5, 3.2))
        plt.plot(x, [r["naive_s"] for r in fr], "o-", label="Naive re-encryption")
        plt.plot(x, [r["migrate_deep_s"] for r in fr], "s-", label="Migration + SHA-256 check")
        plt.plot(x, [r["migrate_s"] for r in fr], "^-", label="Migration (DEK re-wrap)")
        plt.xscale("log"); plt.yscale("log"); plt.xlabel("File size (MiB)"); plt.ylabel("Time (s)"); plt.grid(alpha=.3); plt.legend(fontsize=7)
        plt.tight_layout(); plt.savefig(OUT / "benchmark_migration.png", dpi=200)
    except ImportError:
        print("matplotlib not installed - chart skipped (pip install matplotlib)")


if __name__ == "__main__":
    main()
