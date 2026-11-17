import pytest
from crypto_engine import Engine, Actor

PASS = "correct horse battery"


@pytest.fixture
def engine(tmp_path):
    e = Engine(tmp_path, PASS, kdf_n=2 ** 10)      # tiny scrypt cost: tests only
    e.bootstrap_admin("admin", "adminpass1")
    return e


@pytest.fixture
def admin():
    return Actor("admin", "admin")


@pytest.fixture
def alice(engine, admin):
    engine.create_user(admin, "alice", "alicepass1", "uploader")
    return Actor("alice", "uploader")


@pytest.fixture
def bob(engine, admin):
    engine.create_user(admin, "bob", "bobpass123", "uploader")
    return Actor("bob", "uploader")


@pytest.fixture
def auditor(engine, admin):
    engine.create_user(admin, "audrey", "auditpass1", "auditor")
    return Actor("audrey", "auditor")
