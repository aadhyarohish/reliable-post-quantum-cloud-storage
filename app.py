"""app.py - Streamlit interface for the Post-Quantum Secure Cloud Storage prototype (v2, full project)."""
import io
import os
from pathlib import Path

import pandas as pd
import streamlit as st

import sre
from crypto_engine import (ALG_PQ, ALG_RSA, PERMISSIONS, AuthError, Engine, EngineError, IntegrityError,
                           PermissionDenied)

HOME = Path(os.environ.get("PQC_HOME", Path(__file__).parent))
MAX_PREPARE_BYTES = 200 * 1024 * 1024

st.set_page_config(page_title="Post-Quantum Secure Cloud Storage", page_icon="🔐", layout="wide")
st.title("🔐 Post-Quantum Secure Cloud Storage")
st.caption("Crypto-agility | ML-KEM-768 | Atomic migration | Tamper-evident audit | RBAC | SLOs | Observability | Chaos-tested")
st.info("Student prototype: files are encrypted locally before storage. This is a local simulation, "
        "not a production cloud service.")


# ------------------------------------------------------------------ session: unlock keystore, then log in
def short(alg: str) -> str:
    return "ML-KEM-768 hybrid wrapping" if alg == ALG_PQ else ("RSA-OAEP-SHA256 (legacy)" if alg == ALG_RSA else alg)


with st.sidebar:
    st.header("Access")
    if "engine" not in st.session_state:
        first = not (HOME / "keys" / "keystore.json").exists()
        st.write("Create a keystore passphrase." if first else "Unlock the keystore.")
        with st.form("unlock"):
            pw = st.text_input("Keystore passphrase", type="password", help="At least 8 characters. Never stored.")
            go = st.form_submit_button("Create keystore" if first else "Unlock keystore")
        env_pw = os.environ.get("PQC_PASSPHRASE")
        if go or env_pw:
            try:
                st.session_state.engine = Engine(HOME, pw if go else env_pw)
                st.rerun()
            except AuthError as e:
                st.error(str(e))
        st.stop()

    eng: Engine = st.session_state.engine
    if not eng.has_users():
        st.write("First run: create the administrator account.")
        with st.form("bootstrap"):
            u = st.text_input("Admin username", value="admin")
            p = st.text_input("Admin password", type="password")
            go = st.form_submit_button("Create administrator")
        if go:
            try:
                st.session_state.actor = eng.bootstrap_admin(u, p)
                st.rerun()
            except (ValueError, EngineError) as e:
                st.error(str(e))
        st.stop()

    actor = st.session_state.get("actor")
    if actor is None:
        with st.form("login"):
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            go = st.form_submit_button("Sign in")
        if go:
            try:
                st.session_state.actor = eng.authenticate(u, p)
                st.rerun()
            except AuthError as e:
                st.error(str(e))
        st.stop()

    st.success(f"Signed in as **{actor.username}** ({actor.role})")
    st.caption("Permissions: " + ", ".join(sorted(PERMISSIONS[actor.role])))
    if st.button("Sign out"):
        st.session_state.pop("actor", None)
        st.session_state.pop("prepared", None)
        st.rerun()

perms = PERMISSIONS[actor.role]
tabs = st.tabs(["1. Upload & encrypt", "2. Stored files", "3. Audit trail", "4. Administration", "5. Benchmarks", "6. Operations (SRE)"])

# ------------------------------------------------------------------ 1. upload
with tabs[0]:
    st.header("1. Upload and encrypt a file")
    if "upload" not in perms:
        st.warning(f"Your role ({actor.role}) is not allowed to upload files.")
    else:
        up = st.file_uploader("Choose a file")
        method = st.radio("Initial key-protection method", ["RSA-OAEP (legacy)", "ML-KEM-768 (post-quantum)"])
        if st.button("Encrypt and store file", type="primary"):
            if up is None:
                st.error("Choose a file first.")
            else:
                try:
                    m = eng.encrypt_stream_obj(actor, up.name, up, "rsa" if method.startswith("RSA") else "mlkem")
                    st.success(f"Stored **{m['filename']}** ({m['original_size']} B) as object `{m['object_id']}` "
                               f"using {short(m['key_protection']['algorithm'])}.")
                except EngineError as e:
                    st.error(str(e))

# ------------------------------------------------------------------ 2. stored files
with tabs[1]:
    st.header("2. Stored files and crypto-agility")
    try:
        objs = eng.list_objects(actor)
    except PermissionDenied as e:
        objs, _ = [], st.warning(str(e))
    st.write(f"Stored encrypted objects: **{len(objs)}**")
    for m in reversed(objs):
        oid, kp = m["object_id"], m["key_protection"]
        with st.container(border=True):
            left, right = st.columns([1, 1])
            with left:
                st.subheader(m["filename"])
                st.caption(f"Object ID: {oid} | owner: {m['owner']}")
                st.write(f"Original size: {m['original_size']} B")
            with right:
                st.markdown(f"**Key-protection algorithm:** {short(kp['algorithm'])}")
                st.markdown(f"**Key version:** {kp['key_version']}")
                st.markdown(f"**File encryption:** {m['file_encryption']} (1 MiB chunks)")
            c1, c2, c3 = st.columns([1, 1, 1])
            can_dec = "decrypt_any" in perms or ("decrypt_own" in perms and m["owner"] == actor.username)
            with c1:
                if can_dec:
                    if st.button("Decrypt", key=f"dec_{oid}"):
                        if m["original_size"] > MAX_PREPARE_BYTES:
                            st.error("File too large to prepare in the browser; use decrypt_to_path().")
                        else:
                            try:
                                st.session_state["prepared"] = (oid, m["filename"], eng.decrypt_file(actor, oid))
                            except IntegrityError as e:
                                st.session_state.pop("prepared", None)
                                st.error(f"Integrity check failed: {e}")
                    prep = st.session_state.get("prepared")
                    if prep and prep[0] == oid:
                        st.download_button("Download decrypted file", prep[2], file_name=prep[1], key=f"dl_{oid}")
                else:
                    st.caption("No decrypt permission")
            with c2:
                if "migrate" in perms and kp["algorithm"] == ALG_RSA:
                    if st.button("Migrate to ML-KEM-768", key=f"mig_{oid}"):
                        with st.spinner("Migrating (atomic)..."):
                            r = eng.migrate(actor, oid, "mlkem")
                        st.success(f"Migrated to key version {r['key_version']}; file ciphertext unchanged: "
                                   f"{r['file_ciphertext_unchanged']}")
                        st.rerun()
            with c3:
                if "rollback" in perms and kp["key_version"] > 1:
                    if st.button("Roll back last migration", key=f"rb_{oid}"):
                        try:
                            r = eng.rollback_migration(actor, oid)
                            st.warning(f"Rolled back to {short(r['algorithm'])} (version {r['key_version']}).")
                            st.rerun()
                        except EngineError as e:
                            st.error(str(e))
            if kp["algorithm"] == ALG_PQ:
                st.success("Post-quantum key protection active")
            else:
                st.warning("Legacy RSA key protection - migrate to ML-KEM-768")

# ------------------------------------------------------------------ 3. audit
with tabs[2]:
    st.header("3. Audit trail")
    if "view_audit" not in perms:
        st.warning(f"Your role ({actor.role}) cannot view the audit trail.")
    else:
        if "verify_audit" in perms and st.button("Verify audit chain"):
            rep = eng.verify_audit(actor)
            (st.success if rep.ok else st.error)(rep.message)
        rows = eng.read_audit(actor)
        df = pd.DataFrame(rows)
        if not df.empty:
            first = [c for c in ["seq", "timestamp_utc", "event", "user", "role", "object_id", "from_algorithm",
                                 "to_algorithm", "key_version", "file_ciphertext_unchanged", "ciphertext_check",
                                 "key_algorithm", "file_size_bytes"] if c in df.columns]
            df = df[first + [c for c in df.columns if c not in first]]
            st.download_button("Download as CSV", df.to_csv(index=False), file_name="audit_export.csv", mime="text/csv")
            st.dataframe(df, width="stretch")

# ------------------------------------------------------------------ 4. admin
with tabs[3]:
    st.header("4. Administration")
    if "manage_users" not in perms:
        st.warning("Administrator role required.")
    else:
        with st.form("newuser", clear_on_submit=True):
            c = st.columns(3)
            nu = c[0].text_input("New username")
            npw = c[1].text_input("Password (min 8 chars)", type="password")
            nr = c[2].selectbox("Role", sorted(PERMISSIONS))
            if st.form_submit_button("Create user"):
                try:
                    eng.create_user(actor, nu, npw, nr)
                    st.success(f"Created {nu} ({nr}).")
                except (ValueError, EngineError) as e:
                    st.error(str(e))
        st.dataframe(pd.DataFrame(eng.list_users(actor)), width="stretch")
        st.subheader("Role permissions")
        st.dataframe(pd.DataFrame({r: {p: ("yes" if p in v else "") for p in sorted(set().union(*PERMISSIONS.values()))}
                                   for r, v in PERMISSIONS.items()}), width="stretch")
        if st.button("Run crash recovery now"):
            res = eng.recover_pending()
            st.info(f"{len(res)} pending migration(s) resolved." if res else "No pending migrations.")

# ------------------------------------------------------------------ 5. benchmarks
with tabs[4]:
    st.header("5. Benchmarks")
    bf = HOME / "reports" / "benchmark_files.csv"
    bo = HOME / "reports" / "benchmark_ops.csv"
    if bf.exists():
        d = pd.read_csv(bf)
        st.subheader("Migration vs naive re-encryption")
        st.dataframe(d, width="stretch")
        st.line_chart(d.set_index("size_mib")[["migrate_s", "migrate_deep_s", "naive_s"]])
        if bo.exists():
            st.subheader("Primitive operations (ms)")
            st.dataframe(pd.read_csv(bo), width="stretch")
    else:
        st.info("Run `python bench.py` to generate benchmark results.")

# ------------------------------------------------------------------ 6. operations (SRE)
with tabs[5]:
    st.header("6. Operations (SRE)")
    can_ops = "scrub" in perms
    if not ({"scrub", "view_audit"} & perms):
        st.warning(f"Your role ({actor.role}) cannot view operations data.")
    else:
        _m = st.session_state.pop("ops_msg", None)
        if _m:
            {"ok": st.success, "bad": st.error, "info": st.info}[_m["kind"]](_m["text"])
            if _m.get("table") is not None:
                st.dataframe(pd.DataFrame(_m["table"]), width="stretch", hide_index=True)
        h = sre.health(eng, min_free_fraction=float(os.environ.get("PQC_MIN_FREE", "0.10")))
        {"ok": st.success, "degraded": st.warning, "fail": st.error}[h["status"]](f"Service readiness: **{h['status'].upper()}**")
        st.dataframe(pd.DataFrame(h["checks"]), width="stretch", hide_index=True)

        st.subheader("Service level objectives (this session)")
        rows = []
        for r, slo in zip(sre.slo_report(eng.metrics), sre.DEFAULT_SLOS):
            rows.append({"SLO": r["slo"], "objective": f"{slo.objective:.3%}", "SLI": f"{r['sli']:.3%}", "good / valid": f"{r['good']} / {r['total']}",
                         "burn rate": f"{r['burn_rate']:.2f}x", "budget remaining": f"{r['budget_remaining']:.0%}", "alerts": ", ".join(r["alerts"]) or "none"})
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        q = {op: eng.metrics.quantile(op, 0.99) * 1000 for op in ("encrypt", "decrypt", "migrate")}
        c = st.columns(3)
        for col, (op, v) in zip(c, q.items()):
            col.metric(f"{op} p99 latency", f"{v:.1f} ms")

        if can_ops:
            st.subheader("Operational actions")
            a, b, d = st.columns(3)
            if a.button("Run integrity scrub"):
                rep = sre.scrub(eng, actor)
                st.session_state["ops_msg"] = {"kind": "bad" if rep["corrupt"] else "ok",
                    "text": f"Scrubbed {rep['checked']} objects in {rep['seconds']*1000:.0f} ms: {len(rep['corrupt'])} corrupt."
                            + (" Objects: " + ", ".join(c["object_id"][:12] + "..." for c in rep["corrupt"]) if rep["corrupt"] else "")}
                st.rerun()
            if b.button("Create backup"):
                bk = sre.backup(eng, actor, HOME / "backups")
                st.session_state["ops_msg"] = {"kind": "ok", "text": f"Backup of {bk['objects']} objects ({bk['bytes']/1e3:.0f} kB) in {bk['seconds']*1000:.0f} ms: {Path(bk['archive']).name}"}
                st.rerun()
            if d.button("Verify full audit chain"):
                rep = eng.verify_audit(actor)
                st.session_state["ops_msg"] = {"kind": "ok" if rep.ok else "bad", "text": rep.message}
                st.rerun()
            st.markdown("**Staged (canary) migration to ML-KEM-768**")
            gate_on = st.checkbox("Halt if the availability SLO is burning faster than 14.4x (fast-burn gate)", value=True)
            if st.button("Start staged rollout (canary, 10%, 50%, 100%)"):
                gate = (lambda: ((sre.evaluate(eng.metrics, sre.DEFAULT_SLOS[0], 300)["burn_rate"] < 14.4), "availability SLO fast burn")) if gate_on else None
                rep = sre.staged_migration(eng, actor, "mlkem", gate=gate)
                st.session_state["ops_msg"] = {"kind": "ok" if rep["status"] == "completed" else "bad",
                    "text": f"Rollout {rep['status']}: {rep['candidates']} candidate object(s) across {len(rep['stages'])} stage(s).",
                    "table": rep["stages"]}
                st.rerun()
        with st.expander("Prometheus metrics (/metrics format)"):
            st.code(eng.metrics.render(), language="text")
