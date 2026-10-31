"""Have I Been Pwned - Pwned Passwords (gratuito, senza chiave).

k-anonymity: si inviano solo i primi 5 caratteri dell'hash SHA-1.
La password e l'hash completo non lasciano mai il programma.
"""

from __future__ import annotations

import hashlib

import httpx


async def times_pwned(client: httpx.AsyncClient, password: str) -> int:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    r = await client.get(
        f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true"}
    )  # risposta di lunghezza costante
    r.raise_for_status()
    for line in r.text.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            return int(count.strip() or 0)  # le righe di padding hanno conteggio 0
    return 0
