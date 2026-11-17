# Blameless postmortem: audit-log append latency grows with log size

**Status:** resolved   **Severity:** SEV-3 (found in load test, no user impact)   **Detected by:** load test, not by functional tests

## Summary
The first (v2) engine computed the next audit record's sequence number and previous hash by **scanning the whole audit
file on every append**. Append cost therefore grew linearly with log size. Because audit writes happen under the engine's
lock, this slowed *every* operation, not only auditing.

## Impact (measured)
| Audit records | v2 append (ms) | v3 append (ms) | Speed-up |
|---|---|---|---|
| 0 | 0.969 | 0.989 | 1.0x |
| 1000 | 1.242 | 0.94 | 1.3x |
| 5000 | 2.517 | 1.007 | 2.5x |
| 20000 | 5.194 | 1.174 | 4.4x |
| 50000 | 10.916 | 1.123 | 9.7x |

Mixed workload (8 workers, 1,500 operations, log pre-filled to 20,000 records, 1 vCPU):
throughput **131.0 ops/s -> 264.2 ops/s**;
decrypt p50 63.77 ms -> 28.89 ms.
Latencies include queueing behind the lock with 8 workers on one CPU.

## Timeline (development session)
1. All 49 functional and security tests pass; behaviour is correct.
2. SRE work adds metrics and an event window; a concurrent load test is written.
3. The load test shows latency creeping upward during the run and throughput lower than expected.
4. An audit-scaling micro-benchmark isolates the cause: append time rises from about 1 ms (empty log) to about 11 ms (50,000 records).
5. Fix: cache the chain tail in memory after first use; keep a flag (`cache_tail=False`) so the old behaviour can be benchmarked.
6. Re-run: append time is flat (about 1.1 ms) and throughput doubles.

## Root cause
No performance or scale requirement existed for the audit path. Correctness tests used tiny logs, so an O(n) read on the write path was invisible.
The global lock turned a local inefficiency into a service-wide bottleneck.

## What went well
* The problem was found before release, with a reproducible benchmark.
* The chain still verifies after the change (regression test `test_audit_tail_cache_avoids_rescanning_log_and_keeps_chain_valid`).

## What went poorly / lessons
* Functional tests cannot find scaling faults; a load test and a latency SLO are needed from the start.
* Holding a global lock while doing disk I/O (two `fsync` calls per audit record) still limits throughput.

## Action items
| Action | Type | Status |
|---|---|---|
| Cache audit tail; keep flag for benchmarking | fix | done |
| Regression test: log is scanned at most once | prevent | done |
| Add `data_plane_latency` SLO and load test to the release checklist | detect | done (SLO), CI integration future |
| Batch / group-commit `fsync` for audit records | improve | future |
| Alert when append latency p99 exceeds 20 ms | detect | future |
