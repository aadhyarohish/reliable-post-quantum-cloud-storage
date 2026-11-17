"""Core behaviour tests (the original five Phase 1 tests, ported to the Phase 2 engine)."""
import json
import pytest
from crypto_engine import ALG_PQ, ALG_RSA, IntegrityError, UnknownObject


def test_rsa_encrypt_decrypt_and_migrate(engine, admin):
    data = b"top secret payload " * 10
    m = engine.encrypt_file(admin, "secret.txt", data, "rsa")
    assert m["key_protection"]["algorithm"] == ALG_RSA and m["key_protection"]["key_version"] == 1
    assert engine.decrypt_file(admin, m["object_id"]) == data
    r = engine.migrate(admin, m["object_id"], "mlkem")
    assert r["status"] == "migrated" and r["file_ciphertext_unchanged"] is True
    m2 = engine._load_meta(m["object_id"])
    assert m2["key_protection"]["algorithm"] == ALG_PQ and m2["key_protection"]["key_version"] == 2
    assert m2["ciphertext_sha256"] == m["ciphertext_sha256"]
    assert engine.decrypt_file(admin, m["object_id"]) == data


def test_tampered_ciphertext_is_rejected(engine, admin):
    m = engine.encrypt_file(admin, "t.txt", b"integrity matters", "mlkem")
    bp = engine.storage / f"{m['object_id']}.bin"
    raw = bytearray(bp.read_bytes()); raw[-3] ^= 0x01; bp.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        engine.decrypt_file(admin, m["object_id"])


def test_unknown_object_is_rejected(engine, admin):
    with pytest.raises(UnknownObject):
        engine.decrypt_file(admin, "0" * 32)
    with pytest.raises(UnknownObject):
        engine.decrypt_file(admin, "../../etc/passwd")


def test_direct_mlkem_encryption_and_decryption(engine, admin):
    data = bytes(range(256)) * 50
    m = engine.encrypt_file(admin, "pq.bin", data, "mlkem")
    assert m["key_protection"]["algorithm"] == ALG_PQ and "kem_ciphertext" in m["key_protection"]
    assert engine.decrypt_file(admin, m["object_id"]) == data


def test_repeated_migration_is_idempotent(engine, admin):
    m = engine.encrypt_file(admin, "r.txt", b"abc", "rsa")
    engine.migrate(admin, m["object_id"], "mlkem")
    before = (engine.storage / f"{m['object_id']}.json").read_bytes()
    r = engine.migrate(admin, m["object_id"], "mlkem")
    assert r["status"] == "noop"
    assert (engine.storage / f"{m['object_id']}.json").read_bytes() == before
    assert engine._load_meta(m["object_id"])["key_protection"]["key_version"] == 2
