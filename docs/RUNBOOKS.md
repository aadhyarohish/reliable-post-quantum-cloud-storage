# Runbooks

Every page-severity alert links to one of these. Principles: **mitigate first, diagnose second; fail closed; never loosen security to restore service.**

## RB-1  Audit chain broken (`audit_head` fail, or "Audit chain" verification fails)
Severity: page (possible tampering).
1. Do not restart or write to the data folder. Copy `audit.jsonl` and `keys/audit.head.json` somewhere safe.
2. Run *Verify full audit chain* (or `engine.verify_audit(admin)`); note `first_bad_seq` and the message (modified / missing / truncated).
3. Compare with the latest backup's `audit.jsonl`; the records before `first_bad_seq` are trustworthy.
4. Treat as a security incident: review OS access logs, rotate the keystore passphrase after investigation.
5. Restore the log from backup only after evidence is preserved (a restore loses newer records, which is the RPO).

## RB-2  Corrupt objects (`integrity` fail, `data_integrity` SLO burning)
Severity: page.
1. Read the scrub report: object IDs and reason (`sha256_mismatch`, `authentication_failed`, `missing_files`).
2. Check disk health and recent changes (rollouts, restores).
3. Restore only the affected `<id>.bin` and `<id>.json` from the newest backup into `storage/` (verify with the backup manifest).
4. Re-run the scrub; the `integrity` check must return to `ok`.
5. Objects created after the backup cannot be recovered (RPO): notify owners.

## RB-3  Pending migration journals (`pending_journals` warn)
1. Restart the service, or press *Run crash recovery now*; recovery commits or rolls back every journal automatically.
2. Confirm `migration_recovered` events in the audit log and that `pending_journals` returns to 0.
3. Run a scrub on the affected object.

## RB-4  Availability SLO fast burn (page)
1. Open the Operations tab or `/metrics`: which `op` and `status` is rising (`error`, `integrity_error`)?
2. `error` -> check `storage_writable`, `disk_free`, I/O errors in logs. `integrity_error` -> go to RB-2.
3. **Stop any rollout** (the staged-rollout gate does this automatically) and roll back the last change.
4. When burn rate < 1 on both windows, close the page; open a ticket if the monthly budget is below 50 %.

## RB-5  Rollout halted (`rollout_halted`)
1. Read the stage report: failed objects and reason. Failed stage was rolled back automatically.
2. Verify with a scrub that no object is damaged and that earlier stages still decrypt.
3. Fix the cause, then re-run the staged rollout; already-migrated objects are skipped.

## RB-6  Keystore locked / wrong passphrase at start
The service must **fail closed**. Obtain the passphrase from the secret store; do not create a new keystore over an existing data folder.

## RB-7  Disk low (`disk_free` warn/fail)
Prune old backup archives, move backups off-host, expand the volume. At < 2 % free the service reports `fail` and uploads will fail cleanly (E3).

## RB-8  Backup stale (`backup_age` warn)
Press *Create backup* (or run `sre.backup`). Copy the archive off-host. Record the new RPO.

## RB-9  Disaster recovery (data folder lost)
```
python -c "import sre; print(sre.restore(r'backups/pqc_backup_<stamp>.tar', r'restored_home'))"
# start the app with PQC_HOME=restored_home and the original keystore passphrase
# then: Run integrity scrub -> Verify full audit chain
```
Measured in drill E6: 200 objects (48.9 MB) restored, opened and scrubbed in about 0.5 s on the development machine.
