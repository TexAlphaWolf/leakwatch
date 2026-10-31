"""LeakCheck - API pubblica (gratuita, senza chiave, limitata).

Di default non invia l'email in chiaro ma l'hash SHA-256 dell'email in minuscolo,
troncato a 24 caratteri (formato "hash" supportato da LeakCheck).
"""

from __future__ import annotations

import hashlib

import httpx

URL = "https://leakcheck.io/api/public"


def email_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:24]


async def lookup(client: httpx.AsyncClient, query: str) -> dict:
    """Restituisce {'found': int, 'fields': [...], 'sources': [{'name','date'}]}."""
    r = await client.get(URL, params={"check": query})
    if r.status_code == 429:
        raise RuntimeError("LeakCheck: limite di richieste raggiunto, riprova più tardi")
    data = r.json()
    if not data.get("success"):
        msg = str(data.get("error") or data.get("message") or "")
        if "not found" in msg.lower():
            return {"found": 0, "fields": [], "sources": []}
        raise RuntimeError(f"LeakCheck: {msg or 'risposta non valida'}")
    sources = []
    for s in data.get("sources") or []:
        if isinstance(s, dict):
            sources.append({"name": str(s.get("name", "?")), "date": str(s.get("date", ""))})
        else:
            sources.append({"name": str(s), "date": ""})
    return {
        "found": int(data.get("found") or len(sources)),
        "fields": [str(f) for f in data.get("fields") or []],
        "sources": sources,
    }
