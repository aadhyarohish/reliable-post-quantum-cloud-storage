"""Reduced-size runs of the chaos experiments: the hypotheses must hold on every test run."""
import chaos


def test_e1_crash_recovery(tmp_path):
    r = chaos.e1_crash_recovery(tmp_path, trials=12, seed=3)
    assert r["hypothesis_held"] and r["objects_lost_or_corrupt"] == 0 and r["journals_left"] == 0 and r["audit_chain_intact"]


def test_e2_bitrot_detected_without_false_positives(tmp_path):
    r = chaos.e2_bitrot(tmp_path, objects=20, flips=5, deletions=2)
    assert r["hypothesis_held"] and r["missed"] == 0 and r["false_positives"] == 0 and not r["integrity_slo_met"]


def test_e3_disk_full_leaves_no_partial_state(tmp_path):
    r = chaos.e3_disk_full(tmp_path)
    assert r["hypothesis_held"] and r["partial_objects"] == 0 and r["temp_files_left"] == 0


def test_e4_keystore_fails_closed(tmp_path):
    assert chaos.e4_keystore_unavailable(tmp_path)["hypothesis_held"]


def test_e5_audit_tamper_detected_and_limits_documented(tmp_path):
    r = chaos.e5_audit_tamper(tmp_path)
    assert r["hypothesis_held"]
    assert r["edit_caught_by_readiness_check"] is False       # documented limit: cheap check does not cover mid-chain edits


def test_e6_dr_drill_recovers_everything_in_backup(tmp_path):
    r = chaos.e6_dr_drill(tmp_path, objects=30, extra_after_backup=4)
    assert r["hypothesis_held"] and r["objects_recovered"] == 30 and r["rpo_objects_lost_after_backup"] == 4 and r["audit_chain_intact_after_restore"]
