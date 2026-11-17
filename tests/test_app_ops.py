"""UI regression: the Operations tab must never show a stale 'OK' after a scrub finds corruption."""
import os
import pytest

st_testing = pytest.importorskip("streamlit.testing.v1")


def _click(at, label):
    for b in at.button:
        if b.label == label:
            b.click(); at.run(); return True
    return False


def test_ops_tab_health_reflects_scrub_result_immediately(engine, admin, monkeypatch):
    monkeypatch.setenv("PQC_HOME", str(engine.home))
    for i in range(4): engine.encrypt_file(admin, f"f{i}.txt", b"x" * 500, "rsa")
    at = st_testing.AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=60)
    at.session_state["engine"] = engine; at.session_state["actor"] = admin; at.run()
    assert not at.exception
    victim = sorted(engine.storage.glob("*.bin"))[1]; raw = bytearray(victim.read_bytes()); raw[-3] ^= 1; victim.write_bytes(bytes(raw))
    assert _click(at, "Run integrity scrub") and not at.exception
    errors = [e.value for e in at.error]
    assert any("1 corrupt" in e for e in errors)
    assert any("Service readiness: **FAIL**" in e for e in errors)


def test_auditor_sees_ops_but_has_no_action_buttons(engine, admin, auditor, monkeypatch):
    monkeypatch.setenv("PQC_HOME", str(engine.home))
    at = st_testing.AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=60)
    at.session_state["engine"] = engine; at.session_state["actor"] = auditor; at.run()
    assert not at.exception
    labels = [b.label for b in at.button]
    assert "Run integrity scrub" not in labels and "Create backup" not in labels
