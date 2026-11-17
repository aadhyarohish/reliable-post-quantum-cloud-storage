"""
crypto_engine.py - Post-Quantum Secure Cloud Storage (local prototype, v2)

Envelope encryption with crypto-agility:
  * file payload : chunked streaming AES-256-GCM (large-file safe, truncation/reorder detecting)
  * DEK protection: RSA-OAEP-SHA256 (legacy)  or  ML-KEM-768 + HKDF-SHA256 + AES-256-GCM (post-quantum)
  * migration    : atomic, journaled, crash-recoverable, rollback-able; payload is NOT re-encrypted
  * audit log    : JSON Lines, HMAC-SHA256 hash chain + signed head (tamper-evident)
  * access control: role-based (admin / uploader / auditor), scrypt password hashes, MAC-protected user store
  * keystore     : private keys encrypted at rest under a passphrase-derived key (software KMS, not an HSM)

Educational proof of concept. Not a production cloud service.
"""
from __future__ import annotations

import base64
import copy
import functools
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

from observability import Registry
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ----------------------------------------------------------------------------- constants
ALG_RSA = "RSA-OAEP-SHA256"
ALG_PQ = "ML-KEM-768-HKDF-SHA256-AES-256-GCM"
FILE_ENC = "AES-256-GCM"
CHUNK = 1 << 20                      # 1 MiB plaintext per AES-GCM chunk
MAGIC = b"PQCS1\n"
GENESIS = "0" * 64
OID_RE = re.compile(r"^[0-9a-f]{32}$")

PERMISSIONS = {
    "admin": {"upload", "decrypt_any", "list_all", "migrate", "rollback",
              "view_audit", "verify_audit", "manage_users", "scrub", "backup"},
    "uploader": {"upload", "decrypt_own", "list_own"},
    "auditor": {"list_all", "view_audit", "verify_audit"},
}


# ----------------------------------------------------------------------------- errors
class EngineError(Exception): ...
class UnknownObject(EngineError): ...
class IntegrityError(EngineError): ...
class PermissionDenied(EngineError): ...
class AuthError(EngineError): ...
class VerificationError(EngineError): ...
class SimulatedCrash(Exception):
    """Raised only by tests / fault injection to emulate a hard crash (no cleanup)."""


@dataclass(frozen=True)
class Actor:
    username: str
    role: str


@dataclass
class AuditReport:
    ok: bool
    records: int
    message: str
    first_bad_seq: Optional[int] = None


# ----------------------------------------------------------------------------- helpers
def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fsync_dir(path: Path) -> None:
    try:  # not supported on Windows; best effort elsewhere
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write to a temp file in the same directory, fsync, then atomically replace."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _scrypt(password: bytes, salt: bytes, n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(password)


def _subkey(master: bytes, label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pqc-cloud-storage/subkey/" + label).derive(master)


# ----------------------------------------------------------------------------- keystore
class KeyStore:
    """Software keystore: private keys are encrypted at rest under a passphrase-derived key."""

    def __init__(self, keydir: Path, passphrase: str, kdf_n: int = 2 ** 15):
        if not passphrase or len(passphrase) < 8:
            raise AuthError("Keystore passphrase must be at least 8 characters.")
        self.dir = Path(keydir)
        self.dir.mkdir(parents=True, exist_ok=True)
        pw = passphrase.encode("utf-8")
        meta_path = self.dir / "keystore.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            kek = _scrypt(pw, b64d(meta["salt"]), meta["n"])
            try:
                AESGCM(kek).decrypt(b64d(meta["nonce"]), b64d(meta["check"]), b"keystore-check")
            except InvalidTag:
                raise AuthError("Wrong keystore passphrase.") from None
        else:
            salt = os.urandom(16)
            kek = _scrypt(pw, salt, kdf_n)
            nonce = os.urandom(12)
            check = AESGCM(kek).encrypt(nonce, b"pqc-keystore-ok", b"keystore-check")
            atomic_write_bytes(meta_path, canon({"kdf": "scrypt", "n": kdf_n, "salt": b64e(salt),
                                                 "nonce": b64e(nonce), "check": b64e(check)}))
        self._kek = kek
        self._pw = pw
        self.audit_key = _subkey(kek, b"audit-mac")
        self.users_key = _subkey(kek, b"users-mac")
        self._mlkem_wrap_key = _subkey(kek, b"mlkem-seed")
        self._load_or_create()

    def _load_or_create(self) -> None:
        rsa_priv = self.dir / "rsa_private.pem"
        rsa_pub = self.dir / "rsa_public.pem"
        if not rsa_priv.exists():
            k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            atomic_write_bytes(rsa_priv, k.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(self._pw)))
            atomic_write_bytes(rsa_pub, k.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.rsa_private = serialization.load_pem_private_key(rsa_priv.read_bytes(), self._pw)
        self.rsa_public = serialization.load_pem_public_key(rsa_pub.read_bytes())

        seed_path = self.dir / "mlkem768.seed.enc"
        pub_path = self.dir / "mlkem768_public.bin"
        if not seed_path.exists():
            k = mlkem.MLKEM768PrivateKey.generate()
            nonce = os.urandom(12)
            enc = AESGCM(self._mlkem_wrap_key).encrypt(nonce, k.private_bytes_raw(), b"mlkem768-seed")
            atomic_write_bytes(seed_path, nonce + enc)
            atomic_write_bytes(pub_path, k.public_key().public_bytes_raw())
        blob = seed_path.read_bytes()
        seed = AESGCM(self._mlkem_wrap_key).decrypt(blob[:12], blob[12:], b"mlkem768-seed")
        self.mlkem_private = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
        self.mlkem_public = mlkem.MLKEM768PublicKey.from_public_bytes(pub_path.read_bytes())


# ----------------------------------------------------------------------------- streaming AEAD
def _nonce(prefix: bytes, i: int) -> bytes:
    return prefix + i.to_bytes(8, "big")


def _aad(object_id: str, filename: str, i: int, last: bool) -> bytes:
    return b"|".join([object_id.encode(), filename.encode("utf-8"), str(i).encode(), b"1" if last else b"0"])


def encrypt_stream(dek: bytes, src: BinaryIO, dst: Path, object_id: str, filename: str,
                   chunk: int = CHUNK) -> tuple[int, int, str]:
    """Encrypt src -> dst (atomic). Returns (plaintext_size, ciphertext_size, sha256_of_ciphertext)."""
    aes = AESGCM(dek)
    prefix = os.urandom(4)
    h = hashlib.sha256()
    total = ct_total = 0
    fd, tmp = tempfile.mkstemp(dir=str(dst.parent), prefix=dst.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            header = MAGIC + prefix
            out.write(header); h.update(header); ct_total += len(header)
            cur = src.read(chunk)
            i = 0
            while True:
                nxt = src.read(chunk) if cur else b""
                last = not nxt
                ct = aes.encrypt(_nonce(prefix, i), cur, _aad(object_id, filename, i, last))
                out.write(ct); h.update(ct)
                total += len(cur); ct_total += len(ct)
                if last:
                    break
                cur = nxt
                i += 1
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return total, ct_total, h.hexdigest()


def iter_decrypt(dek: bytes, src_path: Path, object_id: str, filename: str,
                 chunk: int = CHUNK) -> Iterator[bytes]:
    aes = AESGCM(dek)
    with open(src_path, "rb") as f:
        hdr = f.read(len(MAGIC) + 4)
        if len(hdr) != len(MAGIC) + 4 or not hdr.startswith(MAGIC):
            raise IntegrityError("Bad ciphertext header.")
        prefix = hdr[len(MAGIC):]
        cur = f.read(chunk + 16)
        i = 0
        while True:
            nxt = f.read(chunk + 16) if cur else b""
            last = not nxt
            try:
                yield aes.decrypt(_nonce(prefix, i), cur, _aad(object_id, filename, i, last))
            except (InvalidTag, ValueError):
                raise IntegrityError("Authentication failed: ciphertext was modified, truncated or reordered.") from None
            if last:
                return
            cur = nxt
            i += 1


# ----------------------------------------------------------------------------- engine
class Engine:
    def __init__(self, home: str | os.PathLike, passphrase: str, kdf_n: int = 2 ** 15,
                 metrics: Optional[Registry] = None, cache_tail: bool = True):
        self.home = Path(home)
        self.metrics = metrics or Registry()
        self._cache_tail = cache_tail     # False re-creates the v2 behaviour (O(n) audit append) for regression benchmarks
        self._tail: Optional[tuple[int, str]] = None
        self.keys_dir = self.home / "keys"
        self.storage = self.home / "storage"
        self.backups = self.storage / "backups"
        self.journal = self.storage / "journal"
        for d in (self.keys_dir, self.storage, self.backups, self.journal):
            d.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.home / "audit.jsonl"
        self.head_path = self.keys_dir / "audit.head.json"
        self.users_path = self.keys_dir / "users.json"
        self.kdf_n = kdf_n
        self.ks = KeyStore(self.keys_dir, passphrase, kdf_n=kdf_n)
        self._lock = threading.RLock()
        self.recover_pending()
        for name, op in [("encrypt_stream_obj", "encrypt"), ("decrypt_file", "decrypt"), ("decrypt_to_path", "decrypt"),
                         ("list_objects", "list"), ("migrate", "migrate"), ("rollback_migration", "rollback"),
                         ("authenticate", "login"), ("verify_audit", "verify_audit"), ("verify_object", "scrub")]:
            setattr(self, name, self._instrument(op, getattr(self, name)))

    def _instrument(self, op: str, fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            t0 = time.perf_counter(); status = "ok"; nbytes = 0
            try:
                r = fn(*a, **k)
                if isinstance(r, (bytes, bytearray)): nbytes = len(r)
                elif isinstance(r, dict): nbytes = r.get("original_size", 0) or 0
                elif isinstance(r, int) and not isinstance(r, bool) and op == "decrypt": nbytes = r
                return r
            except (PermissionDenied, UnknownObject, AuthError, ValueError):
                status = "client_error"; raise
            except (IntegrityError, VerificationError):
                status = "integrity_error"; raise
            except BaseException:
                status = "error"; raise
            finally:
                self.metrics.record(op, status, time.perf_counter() - t0, nbytes)
        return wrapper

    # ------------------------------------------------------------------ audit
    def _head(self) -> tuple[int, str]:
        if not self.head_path.exists():
            return 0, GENESIS
        h = json.loads(self.head_path.read_text())
        return h["count"], h["last_hash"]

    def _mac(self, data: bytes) -> str:
        return hmac.new(self.ks.audit_key, data, hashlib.sha256).hexdigest()

    def _audit(self, event: str, actor: Optional[Actor] = None, **fields) -> dict:
        with self._lock:
            # seq/prev come from the log itself so that a lagging head file cannot fork the chain
            count, last = self._tail_state()
            rec = {"seq": count + 1, "timestamp_utc": now_utc(), "event": event,
                   "user": actor.username if actor else None, "role": actor.role if actor else None}
            rec.update(fields)
            rec["prev_hash"] = last
            rec["hash"] = self._mac(canon(rec))
            with open(self.audit_path, "ab") as f:
                f.write(canon(rec) + b"\n")
                f.flush()
                os.fsync(f.fileno())
            head = {"count": rec["seq"], "last_hash": rec["hash"]}
            head["mac"] = self._mac(canon(head))
            atomic_write_bytes(self.head_path, canon(head))
            if self._cache_tail:
                self._tail = (rec["seq"], rec["hash"])
            self.metrics.set_gauge("pqc_audit_records", rec["seq"])
            return rec

    def _tail_state(self) -> tuple[int, str]:
        if not self._cache_tail:
            return self._scan_tail()
        if self._tail is None:
            self._tail = self._scan_tail()
        return self._tail

    def _scan_tail(self) -> tuple[int, str]:
        if not self.audit_path.exists():
            return 0, GENESIS
        last_line = None
        with open(self.audit_path, "rb") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if last_line is None:
            return 0, GENESIS
        r = json.loads(last_line)
        return r["seq"], r["hash"]

    def verify_audit(self, actor: Actor) -> AuditReport:
        self._require(actor, "verify_audit")
        rep = self._verify_audit_raw()
        self._audit("audit_verified", actor, result="ok" if rep.ok else "FAILED", detail=rep.message)
        return rep

    def _verify_audit_raw(self) -> AuditReport:
        prev = GENESIS
        n = 0
        if self.audit_path.exists():
            with open(self.audit_path, "rb") as f:
                for raw in f:
                    if not raw.strip():
                        continue
                    try:
                        rec = json.loads(raw)
                    except ValueError:
                        return AuditReport(False, n, f"Unparseable record after entry {n}.", n + 1)
                    n += 1
                    claimed = rec.pop("hash", None)
                    if rec.get("seq") != n:
                        return AuditReport(False, n, f"Sequence gap or reorder at entry {n}.", n)
                    if rec.get("prev_hash") != prev:
                        return AuditReport(False, n, f"Chain link broken at entry {n} (deleted or reordered record).", n)
                    if claimed is None or not hmac.compare_digest(claimed, self._mac(canon(rec))):
                        return AuditReport(False, n, f"Record {n} was modified (MAC mismatch).", n)
                    prev = claimed
        # head check detects truncation of the tail
        if self.head_path.exists():
            head = json.loads(self.head_path.read_text())
            mac = head.pop("mac", "")
            if not hmac.compare_digest(mac, self._mac(canon(head))):
                return AuditReport(False, n, "Audit head file was modified.", None)
            if head["count"] > n:
                return AuditReport(False, n, f"Log truncated: head records {head['count']} entries, log has {n}.", n + 1)
            if head["count"] < n - 1:  # one extra record is tolerated: crash between log append and head write
                return AuditReport(False, n, "Log has extra records beyond the signed head.", head["count"] + 1)
        elif n > 0:
            return AuditReport(False, n, "Audit head file is missing.", None)
        return AuditReport(True, n, f"Audit chain intact: {n} records verified.")

    def read_audit(self, actor: Actor) -> list[dict]:
        self._require(actor, "view_audit")
        out = []
        if self.audit_path.exists():
            with open(self.audit_path, "rb") as f:
                for raw in f:
                    if raw.strip():
                        out.append(json.loads(raw))
        return out[::-1]  # newest first

    # ------------------------------------------------------------------ users / RBAC
    def _load_users(self) -> dict:
        if not self.users_path.exists():
            return {}
        blob = json.loads(self.users_path.read_text())
        mac = blob.pop("mac", "")
        calc = hmac.new(self.ks.users_key, canon(blob), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, calc):
            raise AuthError("User store failed integrity check (it was modified outside the application).")
        return blob["users"]

    def _save_users(self, users: dict) -> None:
        blob = {"users": users}
        blob["mac"] = hmac.new(self.ks.users_key, canon(blob), hashlib.sha256).hexdigest()
        atomic_write_bytes(self.users_path, canon(blob))

    def has_users(self) -> bool:
        return bool(self._load_users())

    def _add_user(self, username: str, password: str, role: str) -> None:
        if role not in PERMISSIONS:
            raise ValueError(f"Unknown role: {role}")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            raise ValueError("Username must be 3-32 characters: letters, digits, _ . -")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters.")
        users = self._load_users()
        if username in users:
            raise ValueError("User already exists.")
        salt = os.urandom(16)
        users[username] = {"role": role, "salt": b64e(salt),
                           "hash": b64e(_scrypt(password.encode(), salt, min(self.kdf_n, 2 ** 14))),
                           "n": min(self.kdf_n, 2 ** 14), "created_utc": now_utc()}
        self._save_users(users)

    def bootstrap_admin(self, username: str, password: str) -> Actor:
        with self._lock:
            if self.has_users():
                raise PermissionDenied("Users already exist; only an admin can create accounts.")
            self._add_user(username, password, "admin")
            a = Actor(username, "admin")
            self._audit("user_created", a, target_user=username, target_role="admin", bootstrap=True)
            return a

    def create_user(self, actor: Actor, username: str, password: str, role: str) -> None:
        self._require(actor, "manage_users")
        with self._lock:
            self._add_user(username, password, role)
            self._audit("user_created", actor, target_user=username, target_role=role)

    def list_users(self, actor: Actor) -> list[dict]:
        self._require(actor, "manage_users")
        return [{"username": u, "role": v["role"], "created_utc": v["created_utc"]}
                for u, v in sorted(self._load_users().items())]

    def authenticate(self, username: str, password: str) -> Actor:
        users = self._load_users()
        u = users.get(username)
        salt = b64d(u["salt"]) if u else b"\x00" * 16
        calc = _scrypt(password.encode(), salt, u["n"] if u else min(self.kdf_n, 2 ** 14))
        if not u or not hmac.compare_digest(calc, b64d(u["hash"])):
            self._audit("login_failed", None, attempted_user=username)
            raise AuthError("Invalid username or password.")
        a = Actor(username, u["role"])
        self._audit("login", a)
        return a

    def _require(self, actor: Optional[Actor], perm: str, object_id: str | None = None) -> None:
        if actor is None or perm not in PERMISSIONS.get(actor.role, set()):
            self._audit("access_denied", actor, permission=perm, object_id=object_id)
            raise PermissionDenied(f"Role '{actor.role if actor else None}' lacks permission '{perm}'.")

    # ------------------------------------------------------------------ key protection
    @staticmethod
    def _norm(method: str) -> str:
        m = method.strip().lower()
        if m in ("rsa", "rsa-oaep", ALG_RSA.lower()):
            return ALG_RSA
        if m in ("mlkem", "ml-kem", "ml-kem-768", "pq", ALG_PQ.lower()):
            return ALG_PQ
        raise ValueError(f"Unknown key-protection method: {method}")

    def _wrap(self, dek: bytes, object_id: str, alg: str) -> dict:
        oid = object_id.encode()
        if alg == ALG_RSA:
            w = self.ks.rsa_public.encrypt(dek, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=oid))
            return {"algorithm": ALG_RSA, "wrapped_dek": b64e(w)}
        ss, ct = self.ks.mlkem_public.encapsulate()
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"pqc-cloud-storage/dek-wrap/v1/" + oid).derive(ss)
        nonce = os.urandom(12)
        w = AESGCM(kek).encrypt(nonce, dek, oid)
        return {"algorithm": ALG_PQ, "wrapped_dek": b64e(w), "kem_ciphertext": b64e(ct), "wrap_nonce": b64e(nonce)}

    def _unwrap(self, prot: dict, object_id: str) -> bytes:
        oid = object_id.encode()
        try:
            if prot["algorithm"] == ALG_RSA:
                return self.ks.rsa_private.decrypt(b64d(prot["wrapped_dek"]), padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=oid))
            ss = self.ks.mlkem_private.decapsulate(b64d(prot["kem_ciphertext"]))
            kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"pqc-cloud-storage/dek-wrap/v1/" + oid).derive(ss)
            return AESGCM(kek).decrypt(b64d(prot["wrap_nonce"]), b64d(prot["wrapped_dek"]), oid)
        except (InvalidTag, ValueError) as e:
            raise IntegrityError("Could not recover the data-encryption key.") from e

    # ------------------------------------------------------------------ storage helpers
    def _paths(self, object_id: str) -> tuple[Path, Path]:
        if not OID_RE.match(object_id or ""):
            raise UnknownObject("Unknown object.")
        return self.storage / f"{object_id}.json", self.storage / f"{object_id}.bin"

    def _load_meta(self, object_id: str) -> dict:
        mp, bp = self._paths(object_id)
        if not mp.exists() or not bp.exists():
            raise UnknownObject("Unknown object.")
        return json.loads(mp.read_text())

    def _write_meta(self, meta: dict) -> None:
        mp, _ = self._paths(meta["object_id"])
        atomic_write_bytes(mp, canon(meta))

    # ------------------------------------------------------------------ upload / download
    def encrypt_stream_obj(self, actor: Actor, filename: str, src: BinaryIO, method: str = "rsa") -> dict:
        self._require(actor, "upload")
        alg = self._norm(method)
        filename = os.path.basename(filename) or "unnamed"
        oid = uuid.uuid4().hex
        mp, bp = self._paths(oid)
        dek = AESGCM.generate_key(bit_length=256)
        size, ct_size, sha = encrypt_stream(dek, src, bp, oid, filename)
        meta = {"schema": 2, "object_id": oid, "filename": filename, "original_size": size,
                "created_utc": now_utc(), "owner": actor.username, "file_encryption": FILE_ENC,
                "chunk_size": CHUNK, "ciphertext_size": ct_size, "ciphertext_sha256": sha,
                "key_protection": {**self._wrap(dek, oid, alg), "key_version": 1}, "history": []}
        self._write_meta(meta)
        self._audit("file_encrypted", actor, object_id=oid, key_algorithm=alg,
                    file_size_bytes=size, key_version=1)
        return meta

    def encrypt_file(self, actor: Actor, filename: str, data: bytes, method: str = "rsa") -> dict:
        return self.encrypt_stream_obj(actor, filename, io.BytesIO(data), method)

    def encrypt_path(self, actor: Actor, path: str | os.PathLike, method: str = "rsa") -> dict:
        with open(path, "rb") as f:
            return self.encrypt_stream_obj(actor, os.path.basename(str(path)), f, method)

    def _authorize_decrypt(self, actor: Actor, object_id: str) -> dict:
        try:
            meta = self._load_meta(object_id)
        except UnknownObject:
            self._audit("decrypt_failed", actor, object_id=str(object_id)[:64], reason="unknown_object")
            raise
        perms = PERMISSIONS.get(actor.role, set()) if actor else set()
        if "decrypt_any" in perms or ("decrypt_own" in perms and meta["owner"] == actor.username):
            return meta
        self._require(actor, "decrypt_any", object_id)  # logs access_denied and raises
        raise PermissionDenied("Not permitted.")

    def decrypt_file(self, actor: Actor, object_id: str) -> bytes:
        meta = self._authorize_decrypt(actor, object_id)
        _, bp = self._paths(object_id)
        try:
            dek = self._unwrap(meta["key_protection"], object_id)
            data = b"".join(iter_decrypt(dek, bp, object_id, meta["filename"]))
        except IntegrityError as e:
            self._audit("decrypt_failed", actor, object_id=object_id, reason="integrity_failure")
            raise
        self._audit("file_decrypted", actor, object_id=object_id, file_size_bytes=len(data))
        return data

    def decrypt_to_path(self, actor: Actor, object_id: str, dest: str | os.PathLike) -> int:
        """Stream-decrypt to dest. Nothing is left at dest if authentication fails."""
        meta = self._authorize_decrypt(actor, object_id)
        _, bp = self._paths(object_id)
        dest = Path(dest)
        fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=dest.name + ".", suffix=".tmp")
        n = 0
        try:
            dek = self._unwrap(meta["key_protection"], object_id)
            with os.fdopen(fd, "wb") as out:
                for pt in iter_decrypt(dek, bp, object_id, meta["filename"]):
                    out.write(pt); n += len(pt)
            os.replace(tmp, dest)
        except BaseException as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            if isinstance(e, IntegrityError):
                self._audit("decrypt_failed", actor, object_id=object_id, reason="integrity_failure")
            raise
        self._audit("file_decrypted", actor, object_id=object_id, file_size_bytes=n)
        return n

    def verify_object(self, actor: Actor, object_id: str, authenticate: bool = True) -> dict:
        """Integrity check without releasing plaintext: SHA-256 vs metadata, then (optionally) AEAD authentication."""
        self._require(actor, "scrub", object_id)
        mp, bp = self._paths(object_id)
        if not mp.exists() or not bp.exists():
            self._audit("object_corrupt", actor, object_id=object_id, reason="missing_files")
            raise IntegrityError("Object files are missing.")
        meta = json.loads(mp.read_text())
        h = hashlib.sha256(); size = 0
        with open(bp, "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""):
                h.update(blk); size += len(blk)
        if size != meta["ciphertext_size"] or h.hexdigest() != meta["ciphertext_sha256"]:
            self._audit("object_corrupt", actor, object_id=object_id, reason="sha256_mismatch")
            raise IntegrityError("Ciphertext does not match the recorded SHA-256.")
        if authenticate:
            dek = self._unwrap(meta["key_protection"], object_id)
            try:
                for _ in iter_decrypt(dek, bp, object_id, meta["filename"]):
                    pass
            except IntegrityError:
                self._audit("object_corrupt", actor, object_id=object_id, reason="authentication_failed")
                raise
        return {"object_id": object_id, "status": "ok", "bytes": size}

    def list_objects(self, actor: Actor) -> list[dict]:
        perms = PERMISSIONS.get(actor.role, set()) if actor else set()
        if "list_all" not in perms and "list_own" not in perms:
            self._require(actor, "list_all")
        out = []
        for mp in self.storage.glob("*.json"):
            if not OID_RE.match(mp.stem):
                continue
            m = json.loads(mp.read_text())
            if "list_all" in perms or m["owner"] == actor.username:
                out.append(m)
        return sorted(out, key=lambda m: m["created_utc"])

    # ------------------------------------------------------------------ migration
    @staticmethod
    def _fingerprint(bp: Path, deep: bool) -> tuple:
        st = bp.stat()
        fp = (st.st_size, st.st_mtime_ns)
        if deep:
            h = hashlib.sha256()
            with open(bp, "rb") as f:
                for blk in iter(lambda: f.read(1 << 20), b""):
                    h.update(blk)
            fp += (h.hexdigest(),)
        return fp

    def migrate(self, actor: Actor, object_id: str, target: str = "mlkem",
                deep_verify: bool = False, _crash_at: str | None = None) -> dict:
        """Atomically migrate DEK protection. The AES-GCM payload file is never rewritten."""
        self._require(actor, "migrate", object_id)
        target = self._norm(target)
        with self._lock:
            meta = self._load_meta(object_id)
            old_prot = meta["key_protection"]
            if old_prot["algorithm"] == target:
                self._audit("migration_skipped", actor, object_id=object_id, to_algorithm=target,
                            key_version=old_prot["key_version"])
                return {"status": "noop", "object_id": object_id, "key_version": old_prot["key_version"]}
            _, bp = self._paths(object_id)
            mp, _ = self._paths(object_id)
            old_meta = copy.deepcopy(meta)
            try:
                dek = self._unwrap(old_prot, object_id)
                new_prot = {**self._wrap(dek, object_id, target), "key_version": old_prot["key_version"] + 1}
                if self._unwrap(new_prot, object_id) != dek:
                    raise VerificationError("New key protection failed its self-check.")
                before = self._fingerprint(bp, deep_verify)
                new_meta = copy.deepcopy(meta)
                new_meta["key_protection"] = new_prot
                new_meta["history"] = meta.get("history", []) + [{
                    "timestamp_utc": now_utc(), "from_algorithm": old_prot["algorithm"],
                    "to_algorithm": target, "key_version": new_prot["key_version"], "by": actor.username}]
                atomic_write_bytes(self.backups / f"{object_id}.v{old_prot['key_version']}.json", canon(old_meta))
                atomic_write_bytes(self.journal / f"{object_id}.json",
                                   canon({"object_id": object_id, "old": old_meta, "new": new_meta,
                                          "started_utc": now_utc()}))
                if _crash_at == "after_journal":
                    raise SimulatedCrash("after_journal")
                atomic_write_bytes(mp, canon(new_meta))              # <-- the single atomic commit point
                if _crash_at == "after_commit":
                    raise SimulatedCrash("after_commit")
                after = self._fingerprint(bp, deep_verify)
                if after != before:
                    raise VerificationError("File ciphertext changed during migration.")
                if self._unwrap(self._load_meta(object_id)["key_protection"], object_id) != dek:
                    raise VerificationError("Committed metadata failed verification.")
            except SimulatedCrash:
                raise                                               # emulate power loss: no cleanup
            except Exception as e:
                atomic_write_bytes(mp, canon(old_meta))             # rollback
                try:
                    os.unlink(self.journal / f"{object_id}.json")
                except OSError:
                    pass
                self._audit("migration_failed", actor, object_id=object_id, reason=type(e).__name__)
                raise
            os.unlink(self.journal / f"{object_id}.json")
            self._audit("key_migrated", actor, object_id=object_id, from_algorithm=old_prot["algorithm"],
                        to_algorithm=target, key_version=new_prot["key_version"],
                        file_ciphertext_unchanged=True,
                        ciphertext_check="sha256" if deep_verify else "size+mtime")
            return {"status": "migrated", "object_id": object_id, "key_version": new_prot["key_version"],
                    "file_ciphertext_unchanged": True, "from": old_prot["algorithm"], "to": target}

    def recover_pending(self) -> list[dict]:
        """Crash recovery: resolve every migration journal left behind (commit or roll back)."""
        results = []
        with self._lock:
            for jp in sorted(self.journal.glob("*.json")):
                try:
                    j = json.loads(jp.read_text())
                    oid = j["object_id"]
                    mp, _ = self._paths(oid)
                    cur = json.loads(mp.read_text()) if mp.exists() else None
                    if cur is not None and canon(cur) == canon(j["new"]):
                        outcome = "committed"
                    else:
                        atomic_write_bytes(mp, canon(j["old"]))
                        outcome = "rolled_back"
                    jp.unlink()
                    self._audit("migration_recovered", None, object_id=oid, outcome=outcome)
                    results.append({"object_id": oid, "outcome": outcome})
                except (ValueError, KeyError, UnknownObject):
                    jp.unlink(missing_ok=True)
            for t in self.storage.rglob("*.tmp"):
                t.unlink(missing_ok=True)
        return results

    def rollback_migration(self, actor: Actor, object_id: str) -> dict:
        """Admin: restore the metadata that existed before the latest migration."""
        self._require(actor, "rollback", object_id)
        with self._lock:
            meta = self._load_meta(object_id)
            cur_v = meta["key_protection"]["key_version"]
            cands = sorted(self.backups.glob(f"{object_id}.v*.json"),
                           key=lambda p: int(p.stem.rsplit(".v", 1)[1]))
            cands = [p for p in cands if int(p.stem.rsplit(".v", 1)[1]) < cur_v]
            if not cands:
                raise EngineError("No earlier version to roll back to.")
            old = json.loads(cands[-1].read_text())
            self._unwrap(old["key_protection"], object_id)     # make sure it is still usable
            self._write_meta(old)
            self._audit("migration_rolled_back", actor, object_id=object_id,
                        from_algorithm=meta["key_protection"]["algorithm"],
                        to_algorithm=old["key_protection"]["algorithm"],
                        key_version=old["key_protection"]["key_version"])
            return {"object_id": object_id, "algorithm": old["key_protection"]["algorithm"],
                    "key_version": old["key_protection"]["key_version"]}
