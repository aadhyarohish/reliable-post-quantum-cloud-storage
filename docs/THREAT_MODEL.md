# Threat model (STRIDE) and control mapping

Assets: file contents, DEKs, private keys (RSA, ML-KEM), audit log, user store.
Trust boundary: everything runs on one host; the attacker is (a) a remote or insider *application* user, or
(b) someone with read/write access to the data folder but **without** the keystore passphrase.
Out of scope: attacker with the passphrase and live process memory, side channels, supply-chain compromise.

| STRIDE | Threat | Control | Evidence (test / experiment) |
|---|---|---|---|
| **S**poofing | Guess or reuse credentials; forge a role | scrypt-hashed passwords, constant-time compare, MAC-protected user store, `login_failed` audit | `test_rbac` (authentication, user-store tampering) |
| **T**ampering | Modify ciphertext, drop/reorder chunks | AES-256-GCM per chunk with index + last-flag in AAD | `test_large_files`, E2 (15/15 detected) |
| **T**ampering | Edit or delete audit records | HMAC hash chain + signed head, full verifier, O(1) readiness check | `test_audit_chain`, E5 |
| **T**ampering | Move a wrapped key to another object | object ID bound as OAEP label / AEAD data | `test_crypto_engine` |
| **R**epudiation | Deny an action | every operation (incl. denials, logins, rollouts, backups) logged with user and role | `test_rbac`, `test_sre` |
| **I**nformation disclosure | Read plaintext or keys at rest | envelope encryption; keys encrypted under passphrase-derived key (scrypt + AES-GCM) | `test_keystore` |
| **I**nformation disclosure | Harvest-now-decrypt-later of wrapped DEKs | ML-KEM-768 protection path + safe migration | migration tests, benchmarks |
| **D**enial of service | Disk full, I/O errors, crashes mid-operation | atomic writes, journaled migration, recovery on start, fail-closed behaviour | E1, E3, E4 |
| **D**enial of service | Brute-force login / request flooding | **not mitigated** (no lock-out or rate limiting) | residual risk |
| **E**levation of privilege | Uploader reads others' files or migrates keys | role checks in the engine (not only the UI) | `test_rbac` |

## NIST SP 800-53 Rev. 5 families (informal mapping)
| Family | Where addressed |
|---|---|
| AC - Access control | roles, least privilege, ownership checks |
| AU - Audit and accountability | HMAC-chained audit log, verification, CSV export |
| CP - Contingency planning | backup / restore, DR drill (E6), RPO/RTO measurement |
| IA - Identification and authentication | scrypt passwords, login auditing |
| IR - Incident response | runbooks, alerts, postmortem |
| SC - System and communications protection | AES-256-GCM, RSA-OAEP, ML-KEM-768, key management (SC-12/SC-13) |
| SI - System and information integrity | AEAD, scrubber, health checks |

## Residual risks
1. Object metadata JSON (e.g. `owner`, `original_size`) is not MAC-protected; a host-level attacker could edit `owner`.
   Key material and ciphertext are still protected, because tampering with wrapped keys or file names fails authentication.
2. Restoring an older consistent copy of both audit log and head file is not detected.
3. No lock-out, rate limiting or MFA.
4. Software keystore only; passphrase and DEKs live in process memory.
