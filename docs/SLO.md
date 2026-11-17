# Service Level Objectives (SLOs)

Service: **PQC cloud-storage prototype** (encrypt / decrypt / list / migrate / scrub).
Metrics come from `observability.Registry`; SLIs are computed over its event window (`sre.evaluate`).

| SLO | SLI (good / valid) | Objective | Window |
|---|---|---|---|
| `data_plane_availability` | encrypt, decrypt, list requests that succeed / valid requests. **Client errors** (permission denied, unknown object, bad login) are excluded from *valid* because the service behaved correctly. Server errors and integrity failures are bad. | 99.9 % | 30 days |
| `data_plane_latency` | successful encrypt/decrypt requests that finish within 250 ms / successful requests | 99 % | 30 days |
| `migration_success` | key-protection migrations that finish without error or integrity failure / migrations attempted | 99.9 % | 30 days |
| `data_integrity` | scrubbed objects that pass SHA-256 and AEAD verification / objects scrubbed | 99.999 % | 30 days |

## Error budgets
`budget = 1 - objective`. For 99.9 % over 30 days: 0.1 % of requests, equivalent to **43.2 minutes** of full outage.
`burn rate = (observed bad fraction) / budget`. A burn rate of 1 uses the whole budget exactly at the end of the window.

## Alerting policy (multi-window, multi-burn-rate, SRE Workbook ch. 5)
| Severity | Long window | Short window | Burn rate | Meaning |
|---|---|---|---|---|
| page | 1 h | 5 min | 14.4x | 2 % of the monthly budget gone in one hour |
| page | 6 h | 30 min | 6x | 5 % of the monthly budget gone in six hours |
| ticket | 3 days | 6 h | 1x | slow leak, fix in working hours |

An alert fires only if **both** windows exceed the threshold: the long window proves the problem is significant,
the short window proves it is still happening, so alerts clear quickly after recovery.

## Rollout gate
`staged_migration(..., gate=...)` can consult the fast-burn condition before each stage: if the availability SLO is
burning faster than 14.4x the rollout halts. Error budget is therefore the control signal for risky changes.

## Known limits
* Metrics are in-process (one engine instance); a real deployment would scrape `/metrics` into a time-series database.
* `data_integrity` only measures objects that have been scrubbed; its freshness is covered by the `integrity` health check.
* Latency numbers depend on file size; the 250 ms threshold is calibrated for the 64-256 KiB objects used in the load test.
