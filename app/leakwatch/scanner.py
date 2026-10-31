"""Orchestrazione di una scansione."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from dataclasses import asdict

from . import net
from .config import settings
from .matcher import Matcher, worst
from .profile import Profile
from .sources import leakcheck, pwned_passwords, web
from .vault import Vault

log = logging.getLogger("leakwatch.scanner")


class Scanner:
    def __init__(self, vault: Vault, on_done=None):
        self.vault = vault
        self.on_done = on_done  # async (summary, nuovi_risultati, automatica) -> None
        self._new: list[dict] = []
        self._lock = asyncio.Lock()
        self.status: dict = {"running": False, "step": "", "progress": 0, "last_error": ""}

    @property
    def running(self) -> bool:
        return self._lock.locked()

    def _set(self, step: str, progress: int) -> None:
        self.status.update(step=step, progress=progress)

    async def run(
        self, profile: Profile, passwords: list[str] | None = None, automatic: bool = False
    ) -> str | None:
        if self._lock.locked():
            return None
        async with self._lock:
            scan_id = secrets.token_hex(6)
            summary = {
                "id": scan_id,
                "started": time.time(),
                "new": 0,
                "total": 0,
                "errors": [],
                "automatic": automatic,
            }
            self._new = []
            self.status.update(running=True, last_error="", progress=0, step="Verifica di Tor")
            try:
                async with net.external_client() as ext, net.local_client() as loc:
                    await net.ensure_tor(ext)
                    await self._passwords(ext, passwords or [], scan_id, summary)
                    await self._breaches(ext, profile, scan_id, summary)
                    await self._web(ext, loc, profile, scan_id, summary)
                self._set("Completata", 100)
            except net.TorUnavailable as e:
                summary["tor_down"] = True
                summary["errors"].append(str(e))
                self.status["last_error"] = str(e)
                self._set("Interrotta", 100)
            except Exception as e:  # non registriamo dettagli che potrebbero contenere dati
                summary["errors"].append(f"Errore imprevisto: {type(e).__name__}")
                self.status["last_error"] = type(e).__name__
                self._set("Interrotta", 100)
            finally:
                passwords = None
                summary["ended"] = time.time()
                if summary["errors"]:
                    net.forget_tor_check()  # al prossimo giro si verifica di nuovo Tor
                self.status["running"] = False
                try:
                    self.vault.add_scan(scan_id, summary)
                except Exception:
                    return None  # vault bloccato durante la scansione
            if self.on_done:
                try:
                    await self.on_done(summary, list(self._new), automatic)
                except Exception as e:  # una notifica fallita non deve far fallire la scansione
                    log.warning("Notifica non inviata: %s", type(e).__name__)
            return scan_id

    # ------------------------------------------------------------------ #
    def _store(self, scan_id: str, summary: dict, finding: dict, *fp_parts: str) -> None:
        if self.vault.add_finding(scan_id, finding, self.vault.fingerprint(*fp_parts)):
            summary["new"] += 1
            self._new.append(finding)
        summary["total"] += 1

    async def _passwords(self, ext, passwords, scan_id, summary):
        for i, pw in enumerate(p for p in passwords if p):
            self._set(f"Controllo password {i + 1}", 5)
            try:
                count = await pwned_passwords.times_pwned(ext, pw)
            except Exception as e:
                summary["errors"].append(f"Pwned Passwords: {type(e).__name__}")
                continue
            if count:
                sha = hashlib.sha1(pw.encode()).hexdigest()
                self._store(
                    scan_id,
                    summary,
                    {
                        "kind": "password",
                        "source": "Pwned Passwords",
                        "severity": "alta",
                        "title": f"Password n.{i + 1} trovata in {count:,} violazioni".replace(",", "."),
                        "url": "",
                        "items": [
                            {
                                "label": "Password (non salvata)",
                                "severity": "alta",
                                "context": "Cambiala ovunque la usi.",
                            }
                        ],
                    },
                    "pw",
                    sha,
                )
            await net.jitter(0.5, 1.5)

    async def _breaches(self, ext, p: Profile, scan_id, summary):
        targets = [("email", e) for e in p.emails] + [("username", u) for u in p.usernames]
        for i, (kind, value) in enumerate(targets):
            self._set(f"Database di breach ({i + 1}/{len(targets)})", 15)
            query = leakcheck.email_hash(value) if kind == "email" and settings.leakcheck_hashed else value
            try:
                res = await leakcheck.lookup(ext, query)
            except Exception as e:
                reason = e if isinstance(e, RuntimeError) else type(e).__name__
                summary["errors"].append(f"LeakCheck: {reason}")
                await net.jitter()
                continue
            if res["found"]:
                fields = res["fields"]
                sev = "alta" if any(f in fields for f in ("password", "phone", "address", "dob")) else "media"
                masked = value[:3] + "***" + (value[value.find("@") :] if "@" in value else "")
                for src in res["sources"] or [{"name": "sconosciuta", "date": ""}]:
                    self._store(
                        scan_id,
                        summary,
                        {
                            "kind": "breach",
                            "source": "LeakCheck",
                            "severity": sev,
                            "breach_name": src["name"],
                            "title": f"{masked} presente nel breach «{src['name']}»"
                            + (f" ({src['date']})" if src["date"] else ""),
                            "url": "",
                            "items": [
                                {
                                    "label": "Dati esposti",
                                    "severity": sev,
                                    "context": ", ".join(fields) or "non specificati",
                                }
                            ],
                        },
                        "breach",
                        value,
                        src["name"],
                    )
            await net.jitter()

    async def _web(self, ext, loc, p: Profile, scan_id, summary):
        queries = web.build_queries(p)
        if not queries:
            return
        matcher = Matcher(p)
        candidates: dict[str, dict] = {}
        for i, q in enumerate(queries):
            self._set(f"Ricerca web ({i + 1}/{len(queries)})", 25 + int(25 * i / len(queries)))
            try:
                for r in await web.searx(loc, q):
                    candidates.setdefault(r["url"], r)
            except Exception as e:
                summary["errors"].append(f"SearXNG: {type(e).__name__}")
                break
            await net.jitter(0.5, 2.0)

        urls = list(candidates)[: settings.max_pages]
        sem = asyncio.Semaphore(3)
        done = 0

        async def analyse(url: str):
            nonlocal done
            async with sem:
                await net.jitter(0.5, 2.5)
                try:
                    text = await web.fetch_text(ext, url)
                except Exception:
                    text = ""
                meta = candidates[url]
                hits = await asyncio.to_thread(matcher.scan, f"{meta['title']} {meta['snippet']} {text}")
                done += 1
                self._set(f"Analisi pagine ({done}/{len(urls)})", 50 + int(50 * done / max(1, len(urls))))
                if not hits:
                    return
                sev = worst(hits)
                self._store(
                    scan_id,
                    summary,
                    {
                        "kind": "web",
                        "source": "Web",
                        "severity": sev,
                        "title": meta["title"] or url,
                        "url": url,
                        "items": [asdict(h) for h in hits],
                    },
                    "web",
                    url,
                    ",".join(sorted(h.field for h in hits)),
                )

        await asyncio.gather(*(analyse(u) for u in urls))
