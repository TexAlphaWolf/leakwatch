"""Ricerca web via SearXNG locale + download delle pagine via Tor + estrazione testo.

Le query contengono solo dati poco sensibili (nome e cognome, opzionalmente email/telefono).
CF, numero di documento e data di nascita si cercano SOLO in locale nel testo scaricato.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
from html.parser import HTMLParser
from urllib.parse import urlsplit

import httpx
from pypdf import PdfReader

from .. import normalize as n
from ..config import settings
from ..profile import Profile


def build_queries(p: Profile) -> list[str]:
    qs: list[str] = []
    if p.first_name and p.last_name:
        fn, ln = p.first_name, p.last_name
        qs += [f'"{fn} {ln}"', f'"{ln} {fn}"', f'"{fn} {ln}" filetype:pdf', f'"{ln} {fn}" filetype:pdf']
    if settings.web_search_email:
        qs += [f'"{e}"' for e in p.emails]
    if settings.web_search_phone:
        for ph in p.phones:
            nat = n.normalize_phone(ph)
            if len(nat) >= 9:
                qs.append(f'"{nat[:3]} {nat[3:]}"')
    for u in p.usernames:
        qs.append(f'"{u}"')
    return qs


async def searx(client: httpx.AsyncClient, query: str) -> list[dict]:
    r = await client.get(
        f"{settings.searxng_url.rstrip('/')}/search", params={"q": query, "format": "json", "safesearch": 0}
    )
    r.raise_for_status()
    out = []
    for item in r.json().get("results", []):
        url = item.get("url") or ""
        if urlsplit(url).scheme in ("http", "https"):
            out.append({"url": url, "title": item.get("title") or "", "snippet": item.get("content") or ""})
    return out


class _TextExtractor(HTMLParser):
    _SKIP = frozenset({"script", "style", "noscript", "svg", "template"})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip += 1
        elif tag in {"br", "p", "div", "li", "tr", "td", "th", "h1", "h2", "h3"}:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _TextExtractor()
    with contextlib.suppress(Exception):  # HTML malformato: teniamo quanto estratto
        p.feed(html)
    return " ".join(p.parts)


def pdf_to_text(data: bytes, max_pages: int = 60) -> str:
    try:
        reader = PdfReader(io.BytesIO(data))
        return " ".join((pg.extract_text() or "") for pg in reader.pages[:max_pages])
    except Exception:
        return ""


async def fetch_text(client: httpx.AsyncClient, url: str) -> str:
    """Scarica una pagina in memoria (mai su disco) con limite di dimensione."""
    buf = bytearray()
    async with client.stream("GET", url) as r:
        if r.status_code >= 400:
            return ""
        ctype = r.headers.get("content-type", "").lower()
        async for chunk in r.aiter_bytes():
            buf += chunk
            if len(buf) > settings.max_page_bytes:
                break
    data = bytes(buf)
    # Parsing in un thread: un PDF grande non deve bloccare dashboard e bot
    if "pdf" in ctype or data[:5] == b"%PDF-":
        return await asyncio.to_thread(pdf_to_text, data)
    if "html" in ctype or "text" in ctype or "xml" in ctype or not ctype:
        html = data.decode(r.encoding or "utf-8", errors="replace")
        return await asyncio.to_thread(html_to_text, html)
    return ""
