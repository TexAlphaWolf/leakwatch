"""Archivio cifrato su SQLite.

- Chiave derivata dalla passphrase con scrypt; vive solo in RAM mentre il vault è sbloccato.
- Ogni record è cifrato con Fernet (AES-128-CBC + HMAC-SHA256).
- PRAGMA secure_delete: i record cancellati vengono sovrascritti con zeri.
- I risultati e le ricerche scadono dopo LW_RETENTION_HOURS (default 24h).
- Delle scoperte resta solo un'impronta HMAC (irreversibile) per riconoscere le novità.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_SCRYPT = dict(n=2**15, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=64)
_VERIFIER = b"leakwatch-ok"


class VaultLocked(Exception):
    pass


class Vault:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._fernet: Fernet | None = None
        self._hmac_key: bytes | None = None
        self._mem_profile: dict | None = None
        self._db = self._connect()

    # ------------------------------------------------------------------ #
    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        db.execute("PRAGMA secure_delete = ON")
        db.execute("PRAGMA journal_mode = DELETE")
        db.execute("PRAGMA temp_store = MEMORY")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS profile (id INTEGER PRIMARY KEY CHECK (id = 1), blob BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, created_at REAL NOT NULL, blob BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, created_at REAL NOT NULL, blob BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS fingerprints (fp TEXT PRIMARY KEY, created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS tg_messages (
                chat_id TEXT NOT NULL, message_id INTEGER NOT NULL, sent_at REAL NOT NULL,
                PRIMARY KEY (chat_id, message_id));
            CREATE INDEX IF NOT EXISTS ix_findings_time ON findings(created_at);
            CREATE INDEX IF NOT EXISTS ix_scans_time ON scans(created_at);
        """)
        with contextlib.suppress(OSError):
            os.chmod(self.path, 0o600)
        return db

    # ------------------------------------------------------------------ #
    # Chiavi
    # ------------------------------------------------------------------ #
    @property
    def initialized(self) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM meta WHERE k='salt'").fetchone() is not None

    @property
    def unlocked(self) -> bool:
        return self._fernet is not None

    def _derive(self, passphrase: str, salt: bytes) -> None:
        raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, **_SCRYPT)
        self._fernet = Fernet(base64.urlsafe_b64encode(raw[:32]))
        self._hmac_key = raw[32:]

    def init(self, passphrase: str) -> None:
        if self.initialized:
            raise ValueError("Vault già inizializzato")
        if len(passphrase) < 12:
            raise ValueError("La passphrase deve avere almeno 12 caratteri")
        salt = secrets.token_bytes(16)
        self._derive(passphrase, salt)
        with self._lock:
            self._db.execute("INSERT INTO meta VALUES ('salt', ?)", (salt,))
            self._db.execute("INSERT INTO meta VALUES ('verifier', ?)", (self._fernet.encrypt(_VERIFIER),))

    def unlock(self, passphrase: str) -> bool:
        with self._lock:
            salt = self._db.execute("SELECT v FROM meta WHERE k='salt'").fetchone()
            ver = self._db.execute("SELECT v FROM meta WHERE k='verifier'").fetchone()
        if not salt or not ver:
            return False
        self._derive(passphrase, salt[0])
        try:
            ok = self._fernet.decrypt(ver[0]) == _VERIFIER
        except InvalidToken:
            ok = False
        if not ok:
            self.lock()
        return ok

    def verify(self, passphrase: str) -> bool:
        """Controlla la passphrase senza toccare la chiave già in memoria."""
        with self._lock:
            salt = self._db.execute("SELECT v FROM meta WHERE k='salt'").fetchone()
            ver = self._db.execute("SELECT v FROM meta WHERE k='verifier'").fetchone()
        if not salt or not ver:
            return False
        raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt[0], **_SCRYPT)
        try:
            return Fernet(base64.urlsafe_b64encode(raw[:32])).decrypt(ver[0]) == _VERIFIER
        except InvalidToken:
            return False

    # Metadati non sensibili (es. orario della prossima scansione)
    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT v FROM meta WHERE k=?", (f"plain:{key}",)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (f"plain:{key}", value))

    # Messaggi Telegram da cancellare (solo ID numerici, nessun contenuto)
    def add_tg_message(self, chat_id: str, message_id: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO tg_messages VALUES (?, ?, ?)", (chat_id, message_id, time.time())
            )

    def due_tg_messages(self, retention_hours: int) -> list[tuple[str, int]]:
        cutoff = time.time() - retention_hours * 3600
        with self._lock:
            return self._db.execute(
                "SELECT chat_id, message_id FROM tg_messages WHERE sent_at < ?", (cutoff,)
            ).fetchall()

    def all_tg_messages(self) -> list[tuple[str, int]]:
        with self._lock:
            return self._db.execute("SELECT chat_id, message_id FROM tg_messages").fetchall()

    def remove_tg_message(self, chat_id: str, message_id: int) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM tg_messages WHERE chat_id=? AND message_id=?", (chat_id, message_id)
            )

    def lock(self) -> None:
        # Python non garantisce l'azzeramento della memoria: rilasciamo i riferimenti.
        self._fernet = None
        self._hmac_key = None
        self._mem_profile = None

    def _require(self) -> Fernet:
        if self._fernet is None:
            raise VaultLocked()
        return self._fernet

    def _enc(self, obj) -> bytes:
        return self._require().encrypt(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _dec(self, blob: bytes):
        return json.loads(self._require().decrypt(blob).decode("utf-8"))

    def fingerprint(self, *parts: str) -> str:
        if self._hmac_key is None:
            raise VaultLocked()
        return hmac.new(self._hmac_key, "|".join(parts).encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------ #
    # Profilo
    # ------------------------------------------------------------------ #
    def save_profile(self, data: dict, persist: bool) -> None:
        self._require()
        self._mem_profile = data
        with self._lock:
            if persist:
                self._db.execute("INSERT OR REPLACE INTO profile VALUES (1, ?)", (self._enc(data),))
            else:
                self._db.execute("DELETE FROM profile")

    def load_profile(self) -> dict:
        self._require()
        if self._mem_profile is not None:
            return self._mem_profile
        with self._lock:
            row = self._db.execute("SELECT blob FROM profile WHERE id=1").fetchone()
        self._mem_profile = self._dec(row[0]) if row else {}
        return self._mem_profile

    # ------------------------------------------------------------------ #
    # Ricerche e risultati
    # ------------------------------------------------------------------ #
    def add_scan(self, scan_id: str, summary: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO scans VALUES (?, ?, ?)", (scan_id, time.time(), self._enc(summary))
            )

    def add_finding(self, scan_id: str, finding: dict, fp: str) -> bool:
        """Salva un risultato; restituisce True se è una novità."""
        now = time.time()
        with self._lock:
            is_new = self._db.execute("SELECT 1 FROM fingerprints WHERE fp=?", (fp,)).fetchone() is None
            finding = {**finding, "new": is_new}
            self._db.execute(
                "INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?)",
                (secrets.token_hex(8), scan_id, now, self._enc(finding)),
            )
            self._db.execute("INSERT OR REPLACE INTO fingerprints VALUES (?, ?)", (fp, now))
        return is_new

    def list_findings(self, retention_hours: int) -> list[dict]:
        out = []
        with self._lock:
            rows = self._db.execute(
                "SELECT created_at, blob FROM findings ORDER BY created_at DESC"
            ).fetchall()
        for created, blob in rows:
            try:
                f = self._dec(blob)
            except InvalidToken:
                continue
            f["created_at"] = created
            f["expires_in"] = max(0, int(created + retention_hours * 3600 - time.time()))
            out.append(f)
        return out

    def list_scans(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT created_at, blob FROM scans ORDER BY created_at DESC").fetchall()
        out = []
        for created, blob in rows:
            try:
                s = self._dec(blob)
            except InvalidToken:
                continue
            s["created_at"] = created
            out.append(s)
        return out

    # ------------------------------------------------------------------ #
    # Pulizia
    # ------------------------------------------------------------------ #
    def purge(self, retention_hours: int, fingerprint_days: int) -> int:
        """Cancella risultati e ricerche scaduti. Funziona anche a vault bloccato."""
        cutoff = time.time() - retention_hours * 3600
        fp_cutoff = time.time() - fingerprint_days * 86400
        with self._lock:
            n = self._db.execute("DELETE FROM findings WHERE created_at < ?", (cutoff,)).rowcount
            n += self._db.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,)).rowcount
            if fingerprint_days <= 0:
                self._db.execute("DELETE FROM fingerprints")
            else:
                self._db.execute("DELETE FROM fingerprints WHERE created_at < ?", (fp_cutoff,))
            if n:
                self._db.execute("VACUUM")
        return n

    def purge_results_now(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM findings")
            self._db.execute("DELETE FROM scans")
            self._db.execute("VACUUM")

    def wipe(self) -> None:
        """Distrugge tutto: chiavi, profilo, risultati, impronte e file del database."""
        self.lock()
        with self._lock:
            self._db.close()
            for p in [self.path, Path(str(self.path) + "-journal")]:
                if p.exists():
                    size = p.stat().st_size
                    with open(p, "r+b") as fh:  # sovrascrittura (best effort su SSD)
                        fh.write(secrets.token_bytes(size))
                        fh.flush()
                        os.fsync(fh.fileno())
                    p.unlink()
            self._db = self._connect()
