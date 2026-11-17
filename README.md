# Reliable and Secure Post-Quantum Cloud Storage - Cloud Security & SRE edition

Educational prototype (not a production cloud service). It protects files with AES-256-GCM and protects each key with
RSA-OAEP or ML-KEM-768, and treats the whole thing as a **service to be operated**: SLOs, error budgets, observability,
integrity scrubbing, backup/restore, staged rollouts, fault injection, runbooks and a blameless postmortem.

## What is in the box
| Layer | Files | Purpose |
|---|---|---|
| Security core | `crypto_engine.py` | streaming AES-GCM, RSA-OAEP, ML-KEM-768, atomic migration, HMAC audit chain, RBAC, keystore |
| Observability | `observability.py` | counters / gauges / histograms, Prometheus text format, event window, `/metrics` `/healthz` `/readyz` |
| SRE | `sre.py` | SLOs, burn-rate alerts, health, scrubber, backup/restore, staged (canary) migration |
| Game days | `chaos.py` | 7 fault-injection experiments with hypotheses and measured results |
| Load | `loadtest.py`, `bench.py` | concurrent workload, latency percentiles, audit scaling, migration vs re-encryption |
| Statistics | `stats.py`, `stats_runner.py` | repeats every experiment (n = 10 / 5 / 3), mean, SD, 95 % CI, Wilson bounds, Welch t-test |
| UI | `app.py` | Streamlit app; tab 6 = Operations (health, SLOs, scrub, backup, staged rollout, metrics) |
| Docs | `docs/` | `SLO.md`, `THREAT_MODEL.md`, `RUNBOOKS.md`, `POSTMORTEM_audit_append.md` |
| Evidence | `reports/`, `screenshots/` | benchmark, chaos, load-test outputs; real UI screenshots |

## Setup and run (Windows)
```
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m streamlit run app.py        # UI (set PQC_MIN_FREE=0.02 to relax the disk-space warning threshold)
python -m pytest tests/ -v            # 83 tests (run from the project root)
python chaos.py                       # game-day experiments  -> reports/chaos_report.{json,md}
python loadtest.py                    # load + audit scaling  -> reports/loadtest.{json,md}
python bench.py                       # migration vs re-encryption -> reports/benchmark_*.csv
python stats_runner.py                # statistical repeats (~10 min on 1 CPU)  -> reports/statistics.{json,md}
python stats_runner.py --quick        # 40-second smoke run
python demo.py                        # scripted security demo
```
Metrics endpoint for a Prometheus-style scraper:
```python
import observability, sre
srv, port = observability.serve(engine.metrics, lambda: sre.health(engine), port=9100)   # /metrics /healthz /readyz
```

## Test suite (83 tests)
security core 49 (crypto 5, atomic migration 7, audit chain 8, RBAC 7, keystore 4, large files 18) +
observability 5 + SRE 17 + chaos smoke 6 + UI regression 2 + statistics helpers 4
(Student-t, Wilson and Welch results are checked against reference tables and, offline, against SciPy).

## Upgrading from earlier versions
The on-disk format changed in v2 (chunked ciphertext, signed audit log, encrypted keys). Move any old `keys/`, `storage/`
and `audit.jsonl` into `archive_v1/` before the first run.

## Honest limits
Single host, software keystore, in-process metrics, no lock-out/MFA, host-level attacker can edit unauthenticated object
metadata (see `docs/THREAT_MODEL.md`). Benchmarks and chaos numbers in `reports/` were produced on a 1-vCPU Linux
development machine; re-run the scripts on your own machine to refresh them.

## Statistical method
* Benchmarks: 10 repeats per file size; load test: 5 runs per version (different seeds); audit scaling: 3 repeats; chaos: 10 seeds.
* Reported as mean ± sample SD with a 95 % Student-t interval of the mean; proportions (e.g. 0 failures in 1,000 trials) use Wilson 95 % intervals; before/after comparisons use Welch's two-sample t-test and Cohen's d.
* Runs are on one machine and are not independent of its background load; treat p-values as descriptive. Warm-up runs are not discarded.
