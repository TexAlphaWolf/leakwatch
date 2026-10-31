"""Profilo dell'utente: i dati da cercare."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from . import normalize as n

MAX_ITEMS = 10  # voci per lista: limita il numero di richieste per scansione
MAX_LEN = 200


@dataclass
class Profile:
    first_name: str = ""
    last_name: str = ""
    birth_date: str = ""  # ISO: AAAA-MM-GG
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    cf: str = ""
    documents: list[str] = field(default_factory=list)  # carta d'identità, patente, passaporto
    usernames: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> Profile:
        def txt(key) -> str:
            v = d.get(key)
            return str(v).strip()[:MAX_LEN] if isinstance(v, (str, int)) else ""

        def lst(key) -> list[str]:
            v = d.get(key) or []
            if isinstance(v, str):
                v = v.replace(",", "\n").splitlines()
            if not isinstance(v, list):
                return []
            out = [str(x).strip()[:MAX_LEN] for x in v if isinstance(x, (str, int)) and str(x).strip()]
            return list(dict.fromkeys(out))[:MAX_ITEMS]  # niente duplicati, al massimo 10 voci

        return cls(
            first_name=txt("first_name"),
            last_name=txt("last_name"),
            birth_date=txt("birth_date"),
            emails=[n.normalize_email(e) for e in lst("emails")],
            phones=[p for p in lst("phones")],
            cf=n.normalize_cf(txt("cf")),
            documents=[n.normalize_document(x) for x in lst("documents")],
            usernames=lst("usernames"),
        )

    def to_dict(self) -> dict:
        return asdict(self)

    def validate(self) -> list[str]:
        """Restituisce avvisi (non blocca il salvataggio)."""
        warnings = []
        if self.cf and not n.is_valid_cf(self.cf):
            warnings.append("Il codice fiscale non supera il controllo del carattere finale.")
        for e in self.emails:
            if not n.is_valid_email(e):
                warnings.append(f"Email non valida: {n.mask(e)}")
        for p in self.phones:
            if len(n.normalize_phone(p)) < 8:
                warnings.append("Un numero di telefono sembra troppo corto.")
        if self.birth_date and not n.date_variants(self.birth_date):
            warnings.append("Data di nascita non nel formato AAAA-MM-GG.")
        if bool(self.first_name) != bool(self.last_name):
            warnings.append("Per la ricerca web servono sia nome sia cognome.")
        return warnings

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()
