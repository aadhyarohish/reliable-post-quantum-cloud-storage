"""Phase 2: role-based access control and authentication."""
import json
import pytest
from crypto_engine import (AuthError, Engine, PermissionDenied, UnknownObject)
from conftest import PASS


def test_roles_and_permissions(engine, admin, alice, bob, auditor):
    m = engine.encrypt_file(alice, "a.txt", b"alice data", "rsa")
    oid = m["object_id"]
    assert engine.decrypt_file(alice, oid) == b"alice data"          # owner
    assert engine.decrypt_file(admin, oid) == b"alice data"          # admin
    with pytest.raises(PermissionDenied):
        engine.decrypt_file(bob, oid)                                # other uploader
    with pytest.raises(PermissionDenied):
        engine.decrypt_file(auditor, oid)                            # auditor: metadata only
    with pytest.raises(PermissionDenied):
        engine.migrate(alice, oid, "mlkem")                          # key ops are admin-only
    with pytest.raises(PermissionDenied):
        engine.encrypt_file(auditor, "x", b"x")
    with pytest.raises(PermissionDenied):
        engine.create_user(alice, "eve", "evepass123", "admin")
    with pytest.raises(PermissionDenied):
        engine.verify_audit(alice)
    with pytest.raises(PermissionDenied):
        engine.read_audit(bob)


def test_listing_is_scoped_to_role(engine, admin, alice, bob, auditor):
    engine.encrypt_file(alice, "a.txt", b"1"); engine.encrypt_file(bob, "b.txt", b"2")
    assert [m["filename"] for m in engine.list_objects(alice)] == ["a.txt"]
    assert [m["filename"] for m in engine.list_objects(bob)] == ["b.txt"]
    assert len(engine.list_objects(admin)) == 2 and len(engine.list_objects(auditor)) == 2


def test_denied_attempts_are_audited(engine, admin, alice):
    m = engine.encrypt_file(admin, "x.txt", b"1")
    with pytest.raises(PermissionDenied):
        engine.decrypt_file(alice, m["object_id"])
    ev = [r for r in engine.read_audit(admin) if r["event"] == "access_denied"]
    assert ev and ev[0]["user"] == "alice" and ev[0]["permission"] == "decrypt_any"


def test_authentication(engine, admin, alice):
    a = engine.authenticate("alice", "alicepass1")
    assert a.role == "uploader"
    with pytest.raises(AuthError):
        engine.authenticate("alice", "wrong-password")
    with pytest.raises(AuthError):
        engine.authenticate("nobody", "whatever123")
    assert any(r["event"] == "login_failed" for r in engine.read_audit(admin))


def test_password_and_username_policy(engine, admin):
    with pytest.raises(ValueError):
        engine.create_user(admin, "shorty", "short", "uploader")
    with pytest.raises(ValueError):
        engine.create_user(admin, "bad name!", "longenough1", "uploader")
    with pytest.raises(ValueError):
        engine.create_user(admin, "dave", "longenough1", "superuser")


def test_user_store_tampering_is_detected(engine, admin, alice, tmp_path):
    blob = json.loads(engine.users_path.read_text())
    blob["users"]["alice"]["role"] = "admin"                         # privilege escalation attempt
    engine.users_path.write_text(json.dumps(blob))
    with pytest.raises(AuthError):
        engine.authenticate("alice", "alicepass1")


def test_bootstrap_only_once(engine):
    with pytest.raises(PermissionDenied):
        engine.bootstrap_admin("intruder", "intruder123")
