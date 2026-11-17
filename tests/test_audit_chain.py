"""Phase 2: tamper-evident (HMAC hash-chained) audit log."""
import hashlib
import json
from crypto_engine import GENESIS, canon


def _populate(engine, admin):
    for i in range(4):
        m = engine.encrypt_file(admin, f"f{i}.txt", b"x" * (i + 1), "rsa")
        engine.decrypt_file(admin, m["object_id"])
    engine.migrate(admin, m["object_id"], "mlkem")


def _lines(engine):
    return engine.audit_path.read_text().splitlines()


def test_intact_chain_verifies(engine, admin):
    _populate(engine, admin)
    rep = engine.verify_audit(admin)
    assert rep.ok and rep.records >= 10


def test_modified_record_is_detected(engine, admin):
    _populate(engine, admin)
    L = _lines(engine)
    rec = json.loads(L[3]); rec["event"] = "file_decrypted"; rec["object_id"] = "f" * 32
    L[3] = json.dumps(rec); engine.audit_path.write_text("\n".join(L) + "\n")
    rep = engine._verify_audit_raw()
    assert not rep.ok and rep.first_bad_seq == 4


def test_deleted_middle_record_is_detected(engine, admin):
    _populate(engine, admin)
    L = _lines(engine); del L[4]
    engine.audit_path.write_text("\n".join(L) + "\n")
    assert not engine._verify_audit_raw().ok


def test_truncated_tail_is_detected(engine, admin):
    _populate(engine, admin)
    L = _lines(engine)[:-2]
    engine.audit_path.write_text("\n".join(L) + "\n")
    rep = engine._verify_audit_raw()
    assert not rep.ok and "truncated" in rep.message.lower()


def test_reordered_records_are_detected(engine, admin):
    _populate(engine, admin)
    L = _lines(engine); L[2], L[3] = L[3], L[2]
    engine.audit_path.write_text("\n".join(L) + "\n")
    assert not engine._verify_audit_raw().ok


def test_attacker_without_key_cannot_rebuild_chain(engine, admin):
    """Re-computing a plain SHA-256 chain after editing must still fail (HMAC key is secret)."""
    _populate(engine, admin)
    out, prev = [], GENESIS
    for line in _lines(engine):
        r = json.loads(line); r.pop("hash")
        if r["seq"] == 3:
            r["event"] = "nothing_to_see"
        r["prev_hash"] = prev
        r["hash"] = hashlib.sha256(canon(r)).hexdigest()
        prev = r["hash"]; out.append(json.dumps(r))
    engine.audit_path.write_text("\n".join(out) + "\n")
    assert not engine._verify_audit_raw().ok


def test_missing_head_file_is_detected(engine, admin):
    _populate(engine, admin)
    engine.head_path.unlink()
    assert not engine._verify_audit_raw().ok


def test_chain_continues_after_restart(engine, admin, tmp_path):
    from crypto_engine import Engine
    from conftest import PASS
    _populate(engine, admin)
    e2 = Engine(tmp_path, PASS, kdf_n=2 ** 10)
    e2.encrypt_file(admin, "again.txt", b"1", "mlkem")
    assert e2._verify_audit_raw().ok
