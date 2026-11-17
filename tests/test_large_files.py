"""Phase 2: large-file / chunked streaming behaviour."""
import os
import hashlib
import pytest
from crypto_engine import CHUNK, IntegrityError

SIZES = [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 17]


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("method", ["rsa", "mlkem"])
def test_chunk_boundaries_roundtrip(engine, admin, size, method):
    data = os.urandom(size)
    m = engine.encrypt_file(admin, "b.bin", data, method)
    assert m["original_size"] == size
    assert engine.decrypt_file(admin, m["object_id"]) == data


def test_64mib_streaming_roundtrip_and_migration(engine, admin, tmp_path):
    src = tmp_path / "big.bin"
    h = hashlib.sha256()
    with open(src, "wb") as f:
        for _ in range(64):
            blk = os.urandom(1 << 20); f.write(blk); h.update(blk)
    m = engine.encrypt_path(admin, src, "rsa")
    oid = m["object_id"]
    engine.migrate(admin, oid, "mlkem", deep_verify=True)
    out = tmp_path / "out.bin"
    assert engine.decrypt_to_path(admin, oid, out) == 64 << 20
    assert hashlib.sha256(out.read_bytes()).hexdigest() == h.hexdigest()


def test_truncated_ciphertext_is_rejected(engine, admin):
    m = engine.encrypt_file(admin, "t.bin", os.urandom(3 * CHUNK), "rsa")
    bp = engine.storage / f"{m['object_id']}.bin"
    raw = bp.read_bytes()
    bp.write_bytes(raw[: -(CHUNK + 16)])                             # drop the last whole chunk
    with pytest.raises(IntegrityError):
        engine.decrypt_file(admin, m["object_id"])


def test_reordered_chunks_are_rejected(engine, admin):
    m = engine.encrypt_file(admin, "r.bin", os.urandom(3 * CHUNK), "rsa")
    bp = engine.storage / f"{m['object_id']}.bin"
    raw = bp.read_bytes(); hdr, body = raw[:10], raw[10:]
    c = CHUNK + 16
    bp.write_bytes(hdr + body[c:2 * c] + body[:c] + body[2 * c:])
    with pytest.raises(IntegrityError):
        engine.decrypt_file(admin, m["object_id"])


def test_failed_decrypt_to_path_leaves_nothing(engine, admin, tmp_path):
    m = engine.encrypt_file(admin, "x.bin", os.urandom(2 * CHUNK), "mlkem")
    bp = engine.storage / f"{m['object_id']}.bin"
    raw = bytearray(bp.read_bytes()); raw[-5] ^= 1; bp.write_bytes(bytes(raw))
    dest = tmp_path / "plain.bin"
    with pytest.raises(IntegrityError):
        engine.decrypt_to_path(admin, m["object_id"], dest)
    assert not dest.exists() and not list(tmp_path.glob("plain.bin.*"))
