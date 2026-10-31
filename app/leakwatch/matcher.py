"""Confronto locale tra il testo di una pagina e il profilo.

Il dato sensibile (CF, documento, data di nascita) NON viene mai inviato a terzi:
le pagine vengono scaricate e confrontate qui, in memoria.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from . import normalize as n
from .profile import Profile

SEVERITY_ORDER = {"alta": 3, "media": 2, "bassa": 1}

_PHONE_CANDIDATE = re.compile(r"(?:\+|00)?\d[\d\s.\-/()]{6,18}\d")
_WORD = re.compile(r"[A-Z]+")
_SEP = r"[\s\-./]?"


@dataclass
class Hit:
    field: str  # cf, document, email, phone, name, name+birth
    label: str  # descrizione leggibile
    severity: str  # alta / media / bassa
    context: str  # estratto mascherato


def _fold_keep_len(text: str) -> str:
    """Come normalize.fold ma con lunghezza identica, così le posizioni coincidono."""
    out = []
    for ch in text:
        base = unicodedata.normalize("NFKD", ch)
        base = "".join(c for c in base if not unicodedata.combining(c)) or ch
        up = base.upper()
        out.append(up[0] if len(up) >= 1 else ch)
    return "".join(out)


def _flex_pattern(value: str) -> re.Pattern:
    """'ABC123' -> A[sep]?B[sep]?C... per trovarlo anche con spazi o trattini."""
    return re.compile(_SEP.join(re.escape(c) for c in value))


class Matcher:
    def __init__(self, profile: Profile):
        self.p = profile
        self.first = n.name_tokens(profile.first_name)
        self.last = n.name_tokens(profile.last_name)
        self.dates = [d.upper() for d in n.date_variants(profile.birth_date)]
        self.phones = {n.normalize_phone(x) for x in profile.phones if len(n.normalize_phone(x)) >= 8}
        self.cf_pat = _flex_pattern(profile.cf) if profile.cf else None
        self.cf_canon = n.cf_canonical(profile.cf) if profile.cf else None
        self.doc_pats = [(d, _flex_pattern(d)) for d in profile.documents if len(d) >= 5]
        self.emails = [e.upper() for e in profile.emails if e]
        # Valori da oscurare negli estratti
        self._secrets = [v for v in [profile.cf, *profile.documents, *profile.emails] if v]

    # ------------------------------------------------------------------ #
    def scan(self, text: str) -> list[Hit]:
        if not text:
            return []
        t = _fold_keep_len(text)
        hits: list[Hit] = []
        hits += self._cf(text, t)
        hits += self._documents(text, t)
        hits += self._emails(text, t)
        hits += self._phones(text, t)
        hits += self._names(text, t)
        return hits

    # ------------------------------------------------------------------ #
    def _cf(self, raw: str, t: str) -> list[Hit]:
        if not self.cf_pat:
            return []
        m = self.cf_pat.search(t)
        if m:
            return [Hit("cf", "Codice fiscale", "alta", self._ctx(raw, m.start(), m.end()))]
        # Variante omocodica: stesso CF con lettere al posto delle cifre
        compact = re.sub(r"[\s\-./]", "", t)
        for cand in n.CF_REGEX.findall(compact):
            if n.cf_canonical(cand) == self.cf_canon:
                return [
                    Hit("cf", "Codice fiscale (variante omocodica)", "alta", "[estratto non disponibile]")
                ]
        return []

    def _documents(self, raw: str, t: str) -> list[Hit]:
        out = []
        for _, pat in self.doc_pats:
            m = pat.search(t)
            if m:
                out.append(Hit("document", "Numero di documento", "alta", self._ctx(raw, m.start(), m.end())))
        return out

    def _emails(self, raw: str, t: str) -> list[Hit]:
        out = []
        for e in self.emails:
            i = t.find(e)
            if i >= 0:
                out.append(Hit("email", "Indirizzo email", "media", self._ctx(raw, i, i + len(e))))
        return out

    def _phones(self, raw: str, t: str) -> list[Hit]:
        if not self.phones:
            return []
        for m in _PHONE_CANDIDATE.finditer(t):
            if n.normalize_phone(m.group()) in self.phones:
                return [Hit("phone", "Numero di telefono", "media", self._ctx(raw, m.start(), m.end()))]
        return []

    def _names(self, raw: str, t: str) -> list[Hit]:
        if not self.first or not self.last:
            return []
        words = [(m.group(), m.start(), m.end()) for m in _WORD.finditer(t)]
        best: Hit | None = None
        seen_starts = set()
        for i in range(len(words)):
            end_idx = self._seq_at(words, i, self.first, self.last) or self._seq_at(
                words, i, self.last, self.first
            )
            if not end_idx:
                continue
            start, end = words[i][1], words[end_idx - 1][2]
            if any(abs(start - s) < 200 for s in seen_starts):
                continue
            seen_starts.add(start)
            if self._date_near(t, start, end):
                return [
                    Hit("name+birth", "Nome e data di nascita insieme", "alta", self._ctx(raw, start, end))
                ]
            if best is None:
                best = Hit("name", "Nome e cognome", "bassa", self._ctx(raw, start, end))
        return [best] if best else []

    @staticmethod
    def _seq_at(words, i: int, a: list[str], b: list[str]) -> int:
        """Nome e cognome consecutivi (in un ordine) a partire da i, con al massimo
        una parola in mezzo (secondo nome). Restituisce l'indice di fine o 0."""

        def run(j, toks):
            for k, tok in enumerate(toks):
                if j + k >= len(words) or not n.fuzzy_equal(words[j + k][0], tok):
                    return 0
            return j + len(toks)

        j = run(i, a)
        if not j:
            return 0
        return run(j, b) or run(j + 1, b)

    def _date_near(self, t: str, start: int, end: int, radius: int = 300) -> bool:
        if not self.dates:
            return False
        area = t[max(0, start - radius) : end + radius]
        return any(d in area for d in self.dates)

    # ------------------------------------------------------------------ #
    def _ctx(self, raw: str, s: int, e: int, pad: int = 70) -> str:
        snippet = re.sub(r"\s+", " ", raw[max(0, s - pad) : e + pad]).strip()
        for secret in self._secrets:
            snippet = _flex_pattern_ci(secret).sub(n.mask(secret), snippet)
        for d in self.dates:
            snippet = re.sub(re.escape(d), "**/**/****", snippet, flags=re.IGNORECASE)
        snippet = _PHONE_CANDIDATE.sub(
            lambda m: n.mask(m.group(), 3, 2) if n.normalize_phone(m.group()) in self.phones else m.group(),
            snippet,
        )
        return snippet[:300]


def _flex_pattern_ci(value: str) -> re.Pattern:
    return re.compile(_SEP.join(re.escape(c) for c in value), re.IGNORECASE)


def worst(hits: list[Hit]) -> str:
    return max((h.severity for h in hits), key=lambda s: SEVERITY_ORDER[s], default="bassa")
