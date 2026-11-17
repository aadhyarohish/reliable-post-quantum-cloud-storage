"""Phase 2: encrypted-at-rest keystore (software KMS)."""
import pytest
from crypto_engine import AuthError, Engine
from conftest import PASS


def test_wrong_passphrase_is_rejected(engine, tmp_path):
    with pytest.raises(AuthError):
        Engine(tmp_path, "totally wrong pass", kdf_n=2 ** 10)


def test_private_keys_are_not_plaintext_on_disk(engine):
    pem = (engine.keys_dir / "rsa_private.pem").read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in pem
    seed_enc = (engine.keys_dir / "mlkem768.seed.enc").read_bytes()
    assert seed_enc[12:] != engine.ks.mlkem_private.private_bytes_raw()
    assert engine.ks.mlkem_private.private_bytes_raw() not in seed_enc


def test_data_survives_restart_with_correct_passphrase(engine, admin, tmp_path):
    m = engine.encrypt_file(admin, "p.txt", b"persist", "mlkem")
    e2 = Engine(tmp_path, PASS, kdf_n=2 ** 10)
    assert e2.decrypt_file(admin, m["object_id"]) == b"persist"


def test_short_passphrase_rejected(tmp_path):
    with pytest.raises(AuthError):
        Engine(tmp_path / "x", "short", kdf_n=2 ** 10)
