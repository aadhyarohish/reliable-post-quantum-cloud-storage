"""Validate the statistics helpers against known reference values."""
import math
import pytest
import stats


def test_summarize_known_sample():
    s = stats.summarize([2, 4, 4, 4, 5, 5, 7, 9])
    assert s["n"] == 8 and s["mean"] == pytest.approx(5.0) and s["sd"] == pytest.approx(2.13809, rel=1e-4)
    assert s["ci95"] == pytest.approx(2.365 * 2.13809 / math.sqrt(8), rel=1e-3)      # t(0.975, df=7) = 2.365


def test_t_critical_values_and_p_values_match_tables():
    assert stats.t_crit(9) == pytest.approx(2.262) and stats.t_crit(1) == pytest.approx(12.706)
    assert stats.t_two_sided_p(2.262, 9) == pytest.approx(0.05, abs=1e-3)
    assert stats.t_two_sided_p(12.706, 1) == pytest.approx(0.05, abs=1e-3)
    assert stats.t_two_sided_p(0.0, 5) == pytest.approx(1.0)
    assert stats.t_two_sided_p(4.032, 5) == pytest.approx(0.01, abs=1e-3)           # t(0.995, df=5) = 4.032


def test_wilson_interval_edges_and_midpoint():
    lo, hi = stats.wilson(0, 100)
    assert lo == 0.0 and hi == pytest.approx(0.0370, abs=1e-3)                          # 0/100 -> upper bound about 3.7 %
    lo, hi = stats.wilson(50, 100)
    assert (lo, hi) == pytest.approx((0.4038, 0.5962), abs=1e-3)
    lo, hi = stats.wilson(1000, 1000)
    assert hi == 1.0 and lo > 0.996


def test_welch_detects_a_real_difference_and_not_noise():
    a = [131, 129, 133, 130, 132]; b = [264, 262, 266, 263, 265]
    w = stats.welch(a, b)
    assert w["p"] < 1e-6 and w["cohens_d"] < -10
    same = stats.welch([1, 2, 3, 4, 5], [1.1, 2.1, 2.9, 4.2, 4.8])
    assert same["p"] > 0.5
