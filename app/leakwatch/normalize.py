"""Normalizzazione e validazione dei dati personali. Algoritmi deterministici, niente IA."""

from __future__ import annotations

import re
import unicodedata
from datetime import date

# --------------------------------------------------------------------------- #
# Codice fiscale
# --------------------------------------------------------------------------- #
_CF_ODD = {
    **dict(zip("0123456789", [1, 0, 5, 7, 9, 13, 15, 17, 19, 21], strict=True)),
    **dict(
        zip(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23],
            strict=True,
        )
    ),
}
_CF_EVEN = {**{str(i): i for i in range(10)}, **{c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}}
# Lettere ammesse al posto delle cifre in caso di omocodia
_OMO = "LMNPQRSTUV"
_D = f"[0-9{_OMO}]"
CF_REGEX = re.compile(rf"[A-Z]{{6}}{_D}{{2}}[ABCDEHLMPRST]{_D}{{2}}[A-Z]{_D}{{3}}[A-Z]")


def cf_check_char(first15: str) -> str:
    total = 0
    for i, ch in enumerate(first15):
        total += _CF_ODD[ch] if i % 2 == 0 else _CF_EVEN[ch]
    return chr(ord("A") + total % 26)


def normalize_cf(cf: str) -> str:
    return re.sub(r"\s+", "", cf or "").upper()


def is_valid_cf(cf: str) -> bool:
    cf = normalize_cf(cf)
    if len(cf) != 16 or not CF_REGEX.fullmatch(cf):
        return False
    return cf_check_char(cf[:15]) == cf[15]


def cf_canonical(cf: str) -> str:
    """Riporta le posizioni numeriche omocodiche a cifre (per confronto)."""
    cf = normalize_cf(cf)
    out = list(cf)
    for pos in (6, 7, 9, 10, 12, 13, 14):
        if pos < len(out) and out[pos] in _OMO:
            out[pos] = str(_OMO.index(out[pos]))
    return "".join(out[:15])  # il carattere di controllo cambia con l'omocodia


# --------------------------------------------------------------------------- #
# Email, telefono, documento
# --------------------------------------------------------------------------- #
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(e: str) -> str:
    return (e or "").strip().lower()


def is_valid_email(e: str) -> bool:
    return bool(EMAIL_REGEX.match(normalize_email(e)))


def normalize_phone(p: str) -> str:
    """Restituisce il numero nazionale (solo cifre) senza prefisso internazionale."""
    digits = re.sub(r"\D", "", p or "")
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("39") and len(digits) >= 11:
        digits = digits[2:]
    return digits


def normalize_document(doc: str) -> str:
    return re.sub(r"[\s\-./]", "", doc or "").upper()


# --------------------------------------------------------------------------- #
# Nomi e date
# --------------------------------------------------------------------------- #
def fold(text: str) -> str:
    """Maiuscolo, senza accenti: 'Niccolò' -> 'NICCOLO'."""
    nfkd = unicodedata.normalize("NFKD", text or "")
    return "".join(c for c in nfkd if not unicodedata.combining(c)).upper()


def name_tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[^A-Z]+", fold(name)) if t]


_MESI_IT = [
    "gennaio",
    "febbraio",
    "marzo",
    "aprile",
    "maggio",
    "giugno",
    "luglio",
    "agosto",
    "settembre",
    "ottobre",
    "novembre",
    "dicembre",
]
_MONTHS_EN = [
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
]


def date_variants(iso: str) -> list[str]:
    """'1985-12-10' -> tutte le forme comuni con cui la data compare nei testi."""
    try:
        d = date.fromisoformat(iso)
    except (TypeError, ValueError):
        return []
    dd, mm, yy, yyyy = f"{d.day:02d}", f"{d.month:02d}", f"{d.year % 100:02d}", str(d.year)
    out = set()
    for day in {dd, str(d.day)}:
        for mon in {mm, str(d.month)}:
            for sep in ("/", "-", "."):
                out.add(f"{day}{sep}{mon}{sep}{yyyy}")
                out.add(f"{day}{sep}{mon}{sep}{yy}")
        out.add(f"{day} {_MESI_IT[d.month - 1]} {yyyy}")
        out.add(f"{_MONTHS_EN[d.month - 1]} {day}, {yyyy}")
    out.add(f"{yyyy}-{mm}-{dd}")
    out.add(f"{yyyy}/{mm}/{dd}")
    # Le varianti con anno a 2 cifre generano troppi falsi positivi se da sole:
    # le teniamo, ma il matcher le usa solo vicino al nome.
    return sorted(out, key=len, reverse=True)


# --------------------------------------------------------------------------- #
# Distanza di Levenshtein con uscita anticipata
# --------------------------------------------------------------------------- #
def levenshtein(a: str, b: str, max_dist: int = 2) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        row_min = cur[0]
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            row_min = min(row_min, cur[j])
        if row_min > max_dist:
            return max_dist + 1
        prev = cur
    return prev[-1]


def fuzzy_equal(a: str, b: str) -> bool:
    """Tolleranza 0 per parole corte, 1 per parole da 5+ lettere."""
    tol = 1 if min(len(a), len(b)) >= 5 else 0
    return levenshtein(a, b, tol) <= tol


# --------------------------------------------------------------------------- #
# Mascheramento per la visualizzazione
# --------------------------------------------------------------------------- #
def mask(value: str, keep_start: int = 3, keep_end: int = 2) -> str:
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return value[:keep_start] + "*" * (len(value) - keep_start - keep_end) + value[-keep_end:]
