"""
stats.py - small, dependency-free statistics helpers used by stats_runner.py.

* summarize()   : n, mean, sample SD, 95 % CI of the mean (Student t), min, max, median
* wilson()      : Wilson score interval for a proportion (use for k successes in n trials, also when k = 0 or k = n)
* welch()       : Welch's two-sample t-test (t, df, two-sided p) and Cohen's d
"""
from __future__ import annotations

import math
import statistics as st

# two-sided 95 % critical values of Student's t for df = 1..30
T975 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131,
        2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042]


def t_crit(df: int) -> float:
    if df < 1:
        return float("nan")
    return T975[df - 1] if df <= 30 else 1.96 + 2.4 / df          # smooth approach to the normal value


def summarize(xs) -> dict:
    xs = [float(x) for x in xs]; n = len(xs)
    if n == 0:
        raise ValueError("empty sample")
    m = st.fmean(xs); sd = st.stdev(xs) if n > 1 else 0.0
    ci = t_crit(n - 1) * sd / math.sqrt(n) if n > 1 else float("nan")
    return {"n": n, "mean": m, "sd": sd, "ci95": ci, "min": min(xs), "max": max(xs), "median": st.median(xs)}


def fmt(s: dict, digits: int = 3, unit: str = "") -> str:
    ci = "n/a" if math.isnan(s["ci95"]) else f"{s['ci95']:.{digits}g}"
    return f"{s['mean']:.{digits}g} \u00b1 {s['sd']:.{digits}g}{unit} (95% CI \u00b1{ci})"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 1.0)
    p = k / n; d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


# ---- regularized incomplete beta (continued fraction, Numerical Recipes) for the t-distribution p-value
def _betacf(a: float, b: float, x: float) -> float:
    tiny = 1e-300; qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0; d = 1.0 - qab * x / qap
    d = tiny if abs(d) < tiny else d; d = 1.0 / d; h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d; d = tiny if abs(d) < tiny else d
        c = 1.0 + aa / c; c = tiny if abs(c) < tiny else c
        d = 1.0 / d; h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d; d = tiny if abs(d) < tiny else d
        c = 1.0 + aa / c; c = tiny if abs(c) < tiny else c
        d = 1.0 / d; de = d * c; h *= de
        if abs(de - 1.0) < 3e-16:
            break
    return h


def betai(a: float, b: float, x: float) -> float:
    if x <= 0.0: return 0.0
    if x >= 1.0: return 1.0
    bt = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def t_two_sided_p(t: float, df: float) -> float:
    return betai(df / 2.0, 0.5, df / (df + t * t))


def welch(a, b) -> dict:
    a = [float(x) for x in a]; b = [float(x) for x in b]
    na, nb = len(a), len(b)
    ma, mb = st.fmean(a), st.fmean(b); va, vb = st.variance(a), st.variance(b)
    se2 = va / na + vb / nb
    if se2 == 0:
        return {"t": math.inf if ma != mb else 0.0, "df": float(na + nb - 2), "p": 0.0 if ma != mb else 1.0, "cohens_d": math.inf if ma != mb else 0.0}
    t = (ma - mb) / math.sqrt(se2)
    df = se2 ** 2 / ((va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1))
    sp = math.sqrt(((na - 1) * va + (nb - 1) * vb) / (na + nb - 2))
    return {"t": t, "df": df, "p": t_two_sided_p(t, df), "cohens_d": (ma - mb) / sp if sp else math.inf}
