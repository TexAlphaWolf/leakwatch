"""Rete: tutto il traffico esterno passa da Tor, con kill switch e blocco degli indirizzi interni."""

from __future__ import annotations

import asyncio
import ipaddress
import random
import time

import httpx

from .config import settings

# User-Agent comune (Tor Browser / Firefox ESR): non identifica il programma.
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept": "text/html,application/xhtml+xml,application/json,application/pdf;q=0.9,*/*;q=0.8",
}

TOR_CHECK_TTL = 600  # una verifica riuscita vale 10 minuti: niente richieste inutili a ogni chiamata
_tor_ok_until = 0.0


class TorUnavailable(Exception):
    pass


class BlockedDestination(Exception):
    """Destinazione nella rete locale: una pagina trovata online non deve poter puntare lì (SSRF)."""


_INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".home", ".localhost", ".arpa")


def is_internal_host(host: str) -> bool:
    host = (host or "").strip("[]").lower().rstrip(".")
    if not host or host == "localhost" or host.endswith(_INTERNAL_SUFFIXES) or "." not in host:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # nome pubblico: lo risolve il nodo di uscita Tor (socks5h)
    return not ip.is_global


async def _guard_destination(request: httpx.Request) -> None:
    # Vale anche per ogni redirect, perché httpx richiama l'hook a ogni richiesta.
    if not settings.allow_private_urls and is_internal_host(request.url.host):
        raise BlockedDestination("Destinazione interna bloccata")


def external_client() -> httpx.AsyncClient:
    """Client per Internet. Se LW_REQUIRE_TOR è attivo, usa SEMPRE il proxy Tor."""
    proxy = settings.tor_proxy or None  # LW_TOR_PROXY="" solo per test senza Tor
    return httpx.AsyncClient(
        proxy=proxy,
        headers=_HEADERS,
        timeout=httpx.Timeout(30.0, connect=20.0),
        follow_redirects=True,
        max_redirects=5,
        trust_env=False,  # ignora HTTP_PROXY ecc. del sistema: niente fughe laterali
        event_hooks={"request": [_guard_destination]},
    )


def local_client() -> httpx.AsyncClient:
    """Client per SearXNG locale (che a sua volta esce via Tor)."""
    return httpx.AsyncClient(timeout=httpx.Timeout(60.0), trust_env=False)


async def check_tor(client: httpx.AsyncClient) -> bool:
    """True se le richieste escono davvero dalla rete Tor."""
    try:
        r = await client.get("https://check.torproject.org/api/ip")
        return bool(r.json().get("IsTor"))
    except Exception:
        return False


async def ensure_tor(client: httpx.AsyncClient) -> None:
    global _tor_ok_until
    if not settings.require_tor or time.monotonic() < _tor_ok_until:
        return
    if not await check_tor(client):
        raise TorUnavailable("Tor non raggiungibile: nessuna richiesta inviata (kill switch).")
    _tor_ok_until = time.monotonic() + TOR_CHECK_TTL


def forget_tor_check() -> None:
    """Forza una nuova verifica (es. dopo un errore di rete)."""
    global _tor_ok_until
    _tor_ok_until = 0.0


async def jitter(low: float = 1.0, high: float = 4.0) -> None:
    """Pausa casuale tra le richieste: niente raffiche riconoscibili, rispetto dei servizi."""
    await asyncio.sleep(random.uniform(low, high))
