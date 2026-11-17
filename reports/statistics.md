# Statistical summary
(n = 10 repeats per experiment unless stated; mean ± sample SD with 95 % t-interval; proportions use Wilson 95 % intervals)

## Migration vs naive re-encryption (seconds)
| MiB | migrate | migrate + SHA-256 | naive | speed-up | Welch p |
|---|---|---|---|---|---|
| 1 | 0.00435 ± 0.000812 (95% CI ±0.000581) | 0.00609 ± 0.000488 (95% CI ±0.000349) | 0.00692 ± 0.000532 (95% CI ±0.000381) | 2x | 3.9e-07 |
| 10 | 0.00497 ± 0.000669 (95% CI ±0.000478) | 0.0237 ± 0.000933 (95% CI ±0.000667) | 0.0329 ± 0.00317 (95% CI ±0.00227) | 7x | 1.4e-10 |
| 100 | 0.00452 ± 0.000711 (95% CI ±0.000509) | 0.191 ± 0.00632 (95% CI ±0.00452) | 0.299 ± 0.0173 (95% CI ±0.0124) | 66x | 1.2e-12 |
| 500 | 0.00513 ± 0.00101 (95% CI ±0.000725) | 0.966 ± 0.0327 (95% CI ±0.0234) | 1.87 ± 0.311 (95% CI ±0.222) | 364x | 1.5e-08 |

## Chaos experiments
* E1: {"runs": 10, "trials": 1000, "failures": 0, "wilson95": [0.0, 0.003826898586390522], "restart_ms": {"n": 10, "mean": 141.02100000000002, "sd": 3.596255614447402, "ci95": 2.572427558257765, "min": 135.44, "max": 149.3, "median": 140.655}, "all_chains_intact": true}
* E2: {"runs": 10, "injected": 150, "detected": 150, "detection_wilson95": [0.9750288608542812, 1.0], "false_positives": 0, "clean_objects": 450, "fp_wilson95": [8.673617379884035e-19, 0.008464627306090936], "ms_per_object": {"n": 10, "mean": 1.0550000000000002, "sd": 0.10480139948174992, "ci95": 0.07496519632469456, "min": 0.95, "max": 1.27, "median": 1.03}}
* E3: {"runs": 10, "held": 10, "wilson95": [0.7224598312333834, 1.0]}
* E4: {"runs": 10, "failed_closed": 40, "attempts": 40, "wilson95": [0.9123754607496077, 1.0]}
* E5: {"runs": 10, "full_verify_detected_edit": 10, "readiness_caught_edit": 0, "readiness_caught_truncation": 10, "readiness_ms": {"n": 10, "mean": 0.6859999999999999, "sd": 0.06963396361610394, "ci95": 0.04980967600777984, "min": 0.61, "max": 0.85, "median": 0.6699999999999999}, "full_verify_ms": {"n": 10, "mean": 0.585, "sd": 0.030641293851417038, "ci95": 0.021917938315452922, "min": 0.55, "max": 0.6
* E6: {"runs": 10, "objects": 2000, "recovered": 2000, "wilson95": [0.9980828823994873, 1.0], "rto_s": {"n": 10, "mean": 0.4765, "sd": 0.030281090542522485, "ci95": 0.021660282292712624, "min": 0.428, "max": 0.525, "median": 0.475}, "backup_s": {"n": 10, "mean": 0.148, "sd": 0.004988876515698593, "ci95": 0.0035685793251656914, "min": 0.141, "max": 0.156, "median": 0.1475}, "restore_s": {"n": 10, "mean":
* E7: {"runs": 10, "time_to_page_s": {"n": 10, "mean": 240.0, "sd": 69.2820323027551, "ci95": 49.55793700306744, "min": 180.0, "max": 360.0, "median": 210.0}, "pages_cleared_s": {"n": 10, "mean": 1650.0, "sd": 50.99019513592785, "ci95": 36.47365405330264, "min": 1560.0, "max": 1740.0, "median": 1650.0}, "burn_rate_2h": {"n": 10, "mean": 6.665000000000001, "sd": 0.8712985200900498, "ci95": 0.623246110633

## Load test (v2 scan vs v3 cached tail)
* throughput v2: 141 ± 6.08 (95% CI ±7.54) ops/s; v3: 292 ± 14.2 (95% CI ±17.6) ops/s; Welch p = 1.7e-06
