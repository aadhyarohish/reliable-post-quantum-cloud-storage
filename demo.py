"""
demo.py - scripted end-to-end demonstration of every Phase 2 feature (good for screenshots).
Run:  python demo.py            (uses a throw-away folder, your real keys/ and storage/ are untouched)
"""
import json, os, shutil, tempfile
from pathlib import Path
from crypto_engine import (Actor, Engine, IntegrityError, PermissionDenied, SimulatedCrash, ALG_RSA, ALG_PQ)

tmp = Path(tempfile.mkdtemp(prefix="pqc_demo_"))
H = lambda t: print(f"\n=== {t} " + "=" * (62 - len(t)))
eng = Engine(tmp, "demo-passphrase", kdf_n=2 ** 12)
admin = eng.bootstrap_admin("admin", "adminpass1")
eng.create_user(admin, "alice", "alicepass1", "uploader"); eng.create_user(admin, "audrey", "auditpass1", "auditor")
alice, audrey = Actor("alice", "uploader"), Actor("audrey", "auditor")

H("1. Envelope encryption: RSA path, then atomic migration to ML-KEM-768")
m = eng.encrypt_file(alice, "secret.txt", b"quantum-safe demo payload", "rsa"); oid = m["object_id"]
print("stored      :", m["filename"], oid[:12] + "...", "|", m["key_protection"]["algorithm"], "| key version", m["key_protection"]["key_version"])
sha_before = m["ciphertext_sha256"]
r = eng.migrate(admin, oid, "mlkem", deep_verify=True)
m2 = eng._load_meta(oid)
print("migrated    :", m2["key_protection"]["algorithm"], "| key version", m2["key_protection"]["key_version"])
print("ciphertext SHA-256 unchanged:", m2["ciphertext_sha256"] == sha_before, "| file_ciphertext_unchanged:", r["file_ciphertext_unchanged"])
print("decrypts to :", eng.decrypt_file(alice, oid))

H("2. Crash safety: power loss during migration, then recovery")
m = eng.encrypt_file(alice, "crash_after_journal.txt", b"payload A", "rsa")
try: eng.migrate(admin, m["object_id"], "mlkem", _crash_at="after_journal")
except SimulatedCrash: print("simulated crash AFTER journal write (before commit)")
print("journal files on disk:", len(list(eng.journal.glob('*.json'))))
eng = Engine(tmp, "demo-passphrase", kdf_n=2 ** 12)         # 'restart' triggers recovery
print("after restart:", eng._load_meta(m["object_id"])["key_protection"]["algorithm"], "(rolled back) | decrypts:", eng.decrypt_file(alice, m["object_id"]))
m = eng.encrypt_file(alice, "crash_after_commit.txt", b"payload B", "rsa")
try: eng.migrate(admin, m["object_id"], "mlkem", _crash_at="after_commit")
except SimulatedCrash: print("simulated crash AFTER atomic commit")
eng = Engine(tmp, "demo-passphrase", kdf_n=2 ** 12)
print("after restart:", eng._load_meta(m["object_id"])["key_protection"]["algorithm"], "(committed) | decrypts:", eng.decrypt_file(alice, m["object_id"]))
rb = eng.rollback_migration(admin, m["object_id"]); print("admin rollback ->", rb["algorithm"], "version", rb["key_version"])

H("3. Role-based access control")
for who, what, fn in [(audrey, "auditor decrypts alice's file", lambda: eng.decrypt_file(audrey, oid)),
                      (alice, "uploader migrates keys", lambda: eng.migrate(alice, oid, "mlkem")),
                      (alice, "uploader reads audit log", lambda: eng.read_audit(alice))]:
    try: fn(); print("UNEXPECTEDLY ALLOWED:", what)
    except PermissionDenied as e: print(f"DENIED  {who.username:7s} ({who.role:8s}) {what}")
print("admin decrypts alice's file:", eng.decrypt_file(admin, oid)[:20], "...")

H("4. Large file (64 MiB) streaming AES-256-GCM + tamper detection")
big = tmp / "big.bin"
with open(big, "wb") as f:
    for _ in range(64): f.write(os.urandom(1 << 20))
mb = eng.encrypt_path(alice, big, "rsa"); print("64 MiB encrypted ->", mb["ciphertext_size"], "bytes in 1 MiB chunks")
bp = eng.storage / f"{mb['object_id']}.bin"; raw = bytearray(bp.read_bytes()); raw[32 << 20] ^= 1; bp.write_bytes(bytes(raw))
try: eng.decrypt_file(alice, mb["object_id"])
except IntegrityError as e: print("flipped 1 bit in chunk 32 ->", "REJECTED:", e)

H("5. Tamper-evident audit log")
rep = eng.verify_audit(admin); print("before tampering:", rep.message)
lines = eng.audit_path.read_text().splitlines(); rec = json.loads(lines[5]); rec["event"] = "nothing_happened"; lines[5] = json.dumps(rec)
eng.audit_path.write_text("\n".join(lines) + "\n")
rep = eng.verify_audit(admin); print("after editing record 6:", "OK" if rep.ok else "TAMPERING DETECTED ->", rep.message)
shutil.rmtree(tmp, ignore_errors=True)
