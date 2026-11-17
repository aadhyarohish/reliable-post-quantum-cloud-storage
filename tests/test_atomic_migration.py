"""Phase 2: crash-safe, atomic migration with rollback."""
import pytest
from crypto_engine import (ALG_PQ, ALG_RSA, Engine, EngineError, SimulatedCrash, VerificationError)
from conftest import PASS


def _obj(engine, admin, data=b"payload" * 100):
    m = engine.encrypt_file(admin, "f.txt", data, "rsa")
    return m["object_id"], data


def test_crash_after_journal_is_rolled_back(engine, admin, tmp_path):
    oid, data = _obj(engine, admin)
    with pytest.raises(SimulatedCrash):
        engine.migrate(admin, oid, "mlkem", _crash_at="after_journal")
    e2 = Engine(tmp_path, PASS, kdf_n=2 ** 10)               # restart -> recovery runs
    assert e2._load_meta(oid)["key_protection"]["algorithm"] == ALG_RSA
    assert e2.decrypt_file(admin, oid) == data
    assert not list(e2.journal.glob("*.json"))
    assert any(r["event"] == "migration_recovered" and r["outcome"] == "rolled_back"
               for r in e2.read_audit(admin))


def test_crash_after_commit_is_completed(engine, admin, tmp_path):
    oid, data = _obj(engine, admin)
    with pytest.raises(SimulatedCrash):
        engine.migrate(admin, oid, "mlkem", _crash_at="after_commit")
    e2 = Engine(tmp_path, PASS, kdf_n=2 ** 10)
    assert e2._load_meta(oid)["key_protection"]["algorithm"] == ALG_PQ
    assert e2.decrypt_file(admin, oid) == data
    assert any(r["event"] == "migration_recovered" and r["outcome"] == "committed"
               for r in e2.read_audit(admin))


def test_failed_self_check_rolls_back(engine, admin, monkeypatch):
    oid, data = _obj(engine, admin)
    before = (engine.storage / f"{oid}.json").read_bytes()
    real = engine._unwrap
    calls = {"n": 0}
    def flaky(prot, object_id):
        calls["n"] += 1
        return b"x" * 32 if calls["n"] == 2 else real(prot, object_id)   # break verification of new wrap
    monkeypatch.setattr(engine, "_unwrap", flaky)
    with pytest.raises(VerificationError):
        engine.migrate(admin, oid, "mlkem")
    monkeypatch.undo()
    assert (engine.storage / f"{oid}.json").read_bytes() == before
    assert engine.decrypt_file(admin, oid) == data
    assert any(r["event"] == "migration_failed" for r in engine.read_audit(admin))


def test_payload_file_is_never_rewritten(engine, admin):
    oid, _ = _obj(engine, admin, b"z" * 3_000_000)
    bp = engine.storage / f"{oid}.bin"
    st1, raw1 = bp.stat(), bp.read_bytes()
    engine.migrate(admin, oid, "mlkem", deep_verify=True)
    st2 = bp.stat()
    assert (st1.st_size, st1.st_mtime_ns) == (st2.st_size, st2.st_mtime_ns)
    assert bp.read_bytes() == raw1


def test_explicit_rollback_restores_previous_version(engine, admin):
    oid, data = _obj(engine, admin)
    engine.migrate(admin, oid, "mlkem")
    r = engine.rollback_migration(admin, oid)
    assert r["algorithm"] == ALG_RSA and r["key_version"] == 1
    assert engine.decrypt_file(admin, oid) == data
    with pytest.raises(EngineError):
        engine.rollback_migration(admin, oid)                # nothing older left


def test_no_temp_files_left_behind(engine, admin):
    oid, _ = _obj(engine, admin)
    engine.migrate(admin, oid, "mlkem")
    assert not list(engine.storage.rglob("*.tmp"))


def test_failure_after_commit_is_rolled_back(engine, admin, monkeypatch):
    """Failure AFTER the atomic commit (ciphertext check) must restore the old metadata."""
    oid, data = _obj(engine, admin)
    before = (engine.storage / f"{oid}.json").read_bytes()
    seq = iter([(1, 1), (2, 2)])                                     # fingerprint differs before/after
    monkeypatch.setattr(engine, "_fingerprint", lambda bp, deep: next(seq))
    with pytest.raises(VerificationError):
        engine.migrate(admin, oid, "mlkem")
    monkeypatch.undo()
    assert (engine.storage / f"{oid}.json").read_bytes() == before
    assert engine._load_meta(oid)["key_protection"]["algorithm"] == ALG_RSA
    assert engine.decrypt_file(admin, oid) == data
    assert not list(engine.journal.glob("*.json"))
