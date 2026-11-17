| ID | Experiment | Hypothesis held | Key result |
|---|---|---|---|
| E1 | Crash during migration (random crash points) | yes | 100 trials, 0 lost, restart+recovery 149.27 ms mean |
| E2 | Silent bit flips and lost files | yes | 15/15 detected, 0 false positives, 1.4 ms/object |
| E3 | Disk full (ENOSPC) during upload and migration | yes | 10/10 uploads failed cleanly, 0 partial objects, 0 temp files |
| E4 | Keystore locked / wrong passphrase | yes | 4/4 attempts failed closed |
| E5 | Audit-log tampering (edit, truncation) | yes | both detected by full verify; only truncation caught by the 0.93 ms readiness check |
| E6 | Disaster recovery drill (total data-directory loss) | yes | 200/200 recovered, RTO 0.548 s, RPO loss 20 objects |
| E7 | Error-budget burn-rate alerting (5 % failures for 15 min) | yes | page 300 s after fault start; pages cleared 1680 s after recovery |
