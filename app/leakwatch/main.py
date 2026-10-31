"""API locale + dashboard + scheduler + bot Telegram. Ascolta solo su 127.0.0.1."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import random
import secrets
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .config import settings
from .profile import Profile
from .scanner import Scanner
from .telegram import Telegram, format_report
from .vault import Vault, VaultLocked

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("leakwatch")  # mai loggare dati personali

STATIC = Path(__file__).parent / "static"
ALLOWED_HOSTS = {h.strip() for h in os.environ.get("LW_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")}
PUBLIC_API = {"/api/state", "/api/init", "/api/unlock"}
COOKIE = "lw_session"
SCHEDULER = settings.auto_scan_hours > 0

vault = Vault(settings.data_dir / "vault.db")
tg = Telegram(vault)
_sessions: dict[str, float] = {}  # token -> scadenza (solo in RAM)
_bg_tasks: set[asyncio.Task] = set()
_unlock_lock = asyncio.Lock()  # un tentativo di sblocco alla volta
_failed_unlocks = 0


def _spawn(coro) -> asyncio.Task:
    """create_task con riferimento forte: evita che il GC fermi il task a metà."""
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return task


# --------------------------------------------------------------------------- #
# Notifica a fine scansione
# --------------------------------------------------------------------------- #
async def _after_scan(summary: dict, new: list[dict], automatic: bool) -> None:
    if not tg.enabled:
        return
    if automatic and summary.get("tor_down"):
        return  # verrà ritentata: il report arriva alla scansione riuscita
    text = format_report(summary, new, len(vault.list_findings(settings.retention_hours)), automatic)
    if text:
        await tg.send(text)


scanner = Scanner(vault, on_done=_after_scan)


# --------------------------------------------------------------------------- #
# Sessioni della dashboard (separate dalla chiave del vault)
# --------------------------------------------------------------------------- #
def _session_ttl() -> int:
    return max(1, settings.auto_lock_minutes) * 60


def _new_session() -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + _session_ttl()
    return token


def _valid_session(request: Request, renew: bool = True) -> bool:
    token = request.cookies.get(COOKIE)
    exp = _sessions.get(token or "")
    if not exp or exp < time.time():
        _sessions.pop(token or "", None)
        return False
    if renew:  # solo le azioni reali rinnovano: il polling dello stato non tiene viva la sessione
        _sessions[token] = time.time() + _session_ttl()
    return True


def _session_response(payload: dict) -> JSONResponse:
    resp = JSONResponse(payload)
    resp.set_cookie(
        COOKIE, _new_session(), httponly=True, samesite="strict", path="/", max_age=_session_ttl()
    )
    return resp


# --------------------------------------------------------------------------- #
# Scheduler
# --------------------------------------------------------------------------- #
def _schedule_next(from_ts: float | None = None) -> float:
    jitter = random.uniform(-1, 1) * settings.auto_scan_jitter_minutes * 60
    nxt = (from_ts or time.time()) + settings.auto_scan_hours * 3600 + jitter
    vault.set_meta("next_scan_at", str(nxt))
    return nxt


def _next_scan_at() -> float | None:
    v = vault.get_meta("next_scan_at") if SCHEDULER else None
    return float(v) if v else None


async def _scheduler_tick() -> None:
    nxt = _next_scan_at()
    if nxt is None:
        vault.set_meta("next_scan_at", str(time.time() + 300))  # prima scansione tra 5 minuti
        return
    if time.time() < nxt or scanner.running:
        return
    _schedule_next()
    if not vault.unlocked:
        with contextlib.suppress(Exception):
            await tg.send(
                "⏸ LeakWatch: scansione automatica saltata, il vault è bloccato "
                "(riavvio del server o /panico). Sbloccalo dalla dashboard."
            )
        return
    profile = Profile.from_dict(vault.load_profile())
    _spawn(_auto_scan(profile))


TOR_RETRIES = 6  # tentativi se Tor non risponde
TOR_RETRY_MINUTES = 15


async def _auto_scan(profile: Profile) -> None:
    await scanner.run(profile, automatic=True)
    if not scanner.status.get("last_error", "").startswith("Tor"):
        vault.set_meta("tor_retries", "0")
        return
    n = int(vault.get_meta("tor_retries") or 0)
    if n < TOR_RETRIES:
        vault.set_meta("tor_retries", str(n + 1))
        vault.set_meta("next_scan_at", str(time.time() + TOR_RETRY_MINUTES * 60))
    else:
        vault.set_meta("tor_retries", "0")  # si riprova al prossimo giro di 24h
        log.warning("Tor non raggiungibile dopo %d tentativi", TOR_RETRIES)


async def _startup_notice() -> None:
    """Avvisa su Telegram che il servizio è ripartito (es. dopo un riavvio del server)."""
    if not tg.enabled:
        return
    text = "🟢 LeakWatch avviato. " + (
        "Vault sbloccato, scansioni automatiche attive."
        if vault.unlocked
        else "Vault BLOCCATO: sbloccalo dalla dashboard per riprendere le scansioni."
    )
    for _ in range(10):  # Tor può impiegare qualche minuto al primo avvio
        await asyncio.sleep(60)
        try:
            await tg.send(text)
            return
        except Exception as e:
            log.info("Notifica di avvio rimandata: %s", type(e).__name__)


async def _housekeeping():
    last_purge = 0.0
    while True:
        now = time.time()
        for tok, exp in list(_sessions.items()):
            if exp < now:
                _sessions.pop(tok, None)
        if not SCHEDULER and not _sessions and vault.unlocked and not scanner.running:
            vault.lock()
        if now - last_purge > 600:
            with contextlib.suppress(Exception):
                vault.purge(settings.retention_hours, settings.fingerprint_days)
            with contextlib.suppress(Exception):
                await tg.delete_expired()
            last_purge = now
        if SCHEDULER:
            with contextlib.suppress(Exception):
                await _scheduler_tick()
        await asyncio.sleep(30)


# --------------------------------------------------------------------------- #
# Comandi Telegram
# --------------------------------------------------------------------------- #
def _fmt_time(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%d/%m %H:%M") if ts else "—"


async def panic() -> None:
    """Lockdown: chiave fuori dalla RAM, sessioni chiuse, scheduler fermo, chat ripulita.
    I dati su disco restano cifrati; per ripartire serve la passphrase dalla dashboard."""
    _sessions.clear()
    vault.lock()
    with contextlib.suppress(Exception):
        await tg.delete_all()


async def _tg_command(cmd: str) -> str:
    if cmd in ("/start", "/aiuto", "/help"):
        return (
            "Comandi LeakWatch:\n/stato — stato e risultati attivi\n/scansiona — avvia una scansione\n"
            "/pulisci — cancella subito i risultati\n"
            "/panico — blocca tutto (chiave fuori dalla RAM, chat ripulita)\n"
            "La passphrase non si invia mai qui."
        )
    if cmd == "/panico":
        await panic()
        return (
            "🔒 Lockdown eseguito: vault bloccato, sessioni chiuse, scansioni ferme, "
            "messaggi cancellati.\nPer ripartire sblocca il vault dalla dashboard."
        )
    if cmd == "/stato":
        lines = [
            f"Vault: {'sbloccato' if vault.unlocked else 'BLOCCATO'}",
            f"Scansione in corso: {'sì' if scanner.running else 'no'}",
        ]
        if SCHEDULER:
            lines.append(f"Prossima scansione automatica: {_fmt_time(_next_scan_at())}")
        if vault.unlocked:
            fs = vault.list_findings(settings.retention_hours)
            counts = {s: sum(1 for f in fs if f["severity"] == s) for s in ("alta", "media", "bassa")}
            lines.append(
                f"Risultati attivi: 🔴 {counts['alta']} · 🟠 {counts['media']} · 🔵 {counts['bassa']}"
            )
            scans = vault.list_scans()
            if scans:
                lines.append(f"Ultima scansione: {_fmt_time(scans[0].get('ended'))}")
        return "\n".join(lines)
    if cmd == "/scansiona":
        if not vault.unlocked:
            return "Vault bloccato: sbloccalo dalla dashboard."
        if scanner.running:
            return "C'è già una scansione in corso."
        _spawn(scanner.run(Profile.from_dict(vault.load_profile())))
        return "Scansione avviata. Ti scrivo appena finisce."
    if cmd == "/pulisci":
        vault.purge_results_now()
        return "Risultati e storico delle ricerche cancellati."
    return "Comando sconosciuto. Scrivi /aiuto."


# --------------------------------------------------------------------------- #
@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    vault.purge(settings.retention_hours, settings.fingerprint_days)
    if settings.unlock_keyfile and Path(settings.unlock_keyfile).is_file() and vault.initialized:
        passphrase = Path(settings.unlock_keyfile).read_text(encoding="utf-8").strip()
        if not vault.unlock(passphrase):
            log.warning("File-chiave non valido: vault rimasto bloccato")
        del passphrase
    tasks = [asyncio.create_task(_housekeeping()), asyncio.create_task(_startup_notice())]
    if tg.enabled:
        tasks.append(asyncio.create_task(tg.poll_commands(_tg_command)))
    yield
    for t in tasks:
        t.cancel()
    vault.lock()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


# --------------------------------------------------------------------------- #
# Sicurezza: anti DNS-rebinding, anti CSRF, sessione, header restrittivi
# --------------------------------------------------------------------------- #
@app.middleware("http")
async def guard(request: Request, call_next):
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
    if host not in ALLOWED_HOSTS:
        return JSONResponse({"detail": "Host non consentito"}, status_code=403)
    if request.method not in ("GET", "HEAD"):
        if request.headers.get("x-leakwatch") != "1":
            return JSONResponse({"detail": "Richiesta non consentita"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1].rsplit(":", 1)[0].strip("[]") not in ALLOWED_HOSTS:
            return JSONResponse({"detail": "Origine non consentita"}, status_code=403)
    path = request.url.path
    if (
        path.startswith("/api/")
        and path not in PUBLIC_API
        and not (_valid_session(request) and vault.unlocked)
    ):
        return JSONResponse({"detail": "Vault bloccato"}, status_code=423)
    response = await call_next(request)
    response.headers.update(
        {
            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        }
    )
    return response


@app.exception_handler(VaultLocked)
async def _locked(_req, _exc):
    return JSONResponse({"detail": "Vault bloccato"}, status_code=423)


# --------------------------------------------------------------------------- #
# Pagine statiche
# --------------------------------------------------------------------------- #
@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/healthz")
async def healthz():
    return {"ok": True}  # nessuna informazione: serve solo all'healthcheck di Docker


@app.get("/static/{name}")
async def static(name: str):
    path = (STATIC / name).resolve()
    if path.parent != STATIC.resolve() or not path.is_file():
        raise HTTPException(404)
    return FileResponse(path)


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
class Passphrase(BaseModel):
    passphrase: str = Field(min_length=1, max_length=512)


class ScanRequest(BaseModel):
    passwords: list[Annotated[str, Field(max_length=256)]] = Field(default_factory=list, max_length=20)


class LockRequest(BaseModel):
    full: bool = False  # true = blocca anche lo scheduler


class WipeRequest(BaseModel):
    confirm: str


@app.get("/api/state")
async def state(request: Request):
    return {
        "initialized": vault.initialized,
        "unlocked": vault.unlocked and _valid_session(request, renew=False),
        "vault_unlocked": vault.unlocked,
        "require_tor": settings.require_tor,
        "retention_hours": settings.retention_hours,
        "store_profile": settings.store_profile,
        "scheduler": SCHEDULER,
        "auto_scan_hours": settings.auto_scan_hours,
        "next_scan_at": _next_scan_at(),
        "telegram": tg.enabled,
        "scan": scanner.status,
    }


@app.post("/api/init")
async def init(body: Passphrase):
    try:
        await asyncio.to_thread(vault.init, body.passphrase)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _session_response({"ok": True})


@app.post("/api/unlock")
async def unlock(body: Passphrase):
    global _failed_unlocks
    async with _unlock_lock:  # tentativi in serie: niente attacchi in parallelo
        if vault.unlocked:  # scheduler attivo: verifica senza toccare la chiave in uso
            ok = await asyncio.to_thread(vault.verify, body.passphrase)
        else:
            ok = await asyncio.to_thread(vault.unlock, body.passphrase)
        if not ok:
            _failed_unlocks += 1
            await asyncio.sleep(min(30.0, 1.5 * _failed_unlocks))  # ritardo crescente, max 30 s
            if _failed_unlocks in (5, 20) and tg.enabled:
                _spawn(_notify_failed_unlocks(_failed_unlocks))
            raise HTTPException(401, "Passphrase errata")
        _failed_unlocks = 0
    return _session_response({"ok": True})


async def _notify_failed_unlocks(n: int) -> None:
    with contextlib.suppress(Exception):
        await tg.send(f"⚠️ LeakWatch: {n} tentativi di sblocco falliti di fila sulla dashboard.")


@app.post("/api/lock")
async def lock(request: Request, body: LockRequest | None = None):
    _sessions.pop(request.cookies.get(COOKIE, ""), None)
    if not SCHEDULER or (body and body.full):
        _sessions.clear()
        vault.lock()
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.get("/api/profile")
async def get_profile():
    return vault.load_profile()


@app.put("/api/profile")
async def put_profile(body: dict):
    prof = Profile.from_dict(body)
    vault.save_profile(prof.to_dict(), persist=settings.store_profile)
    return {"ok": True, "warnings": prof.validate()}


@app.post("/api/scan")
async def scan(body: ScanRequest):
    prof = Profile.from_dict(vault.load_profile())
    if scanner.running:
        raise HTTPException(409, "Scansione già in corso")
    _spawn(scanner.run(prof, body.passwords))
    return {"ok": True}


@app.get("/api/results")
async def results():
    return {"findings": vault.list_findings(settings.retention_hours), "scans": vault.list_scans()}


@app.post("/api/telegram/test")
async def telegram_test():
    if not tg.enabled:
        raise HTTPException(400, "Telegram non configurato")
    try:
        await tg.send("👋 LeakWatch collegato. Scrivi /aiuto per i comandi.")
    except Exception as e:
        reason = e if isinstance(e, RuntimeError) else type(e).__name__
        raise HTTPException(502, f"Invio non riuscito: {reason}")
    return {"ok": True}


@app.post("/api/purge")
async def purge():
    vault.purge_results_now()
    with contextlib.suppress(Exception):
        await tg.delete_all()
    return {"ok": True}


@app.post("/api/wipe")
async def wipe(body: WipeRequest):
    if body.confirm != "CANCELLA TUTTO":
        raise HTTPException(400, "Conferma non valida")
    if scanner.running:
        raise HTTPException(409, "Attendi la fine della scansione")
    with contextlib.suppress(Exception):
        await tg.delete_all()
    _sessions.clear()
    vault.wipe()
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


def run():
    import uvicorn

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        access_log=False,
        log_level="warning",
        server_header=False,
        date_header=False,
    )


if __name__ == "__main__":
    run()
