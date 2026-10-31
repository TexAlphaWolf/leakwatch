"""Configurazione tramite variabili d'ambiente. Nessun valore sensibile qui."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on", "si"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # Rete
    tor_proxy: str = os.environ.get("LW_TOR_PROXY", "socks5h://127.0.0.1:9050")
    require_tor: bool = _bool("LW_REQUIRE_TOR", True)  # kill switch
    searxng_url: str = os.environ.get("LW_SEARXNG_URL", "http://127.0.0.1:8888")
    allow_private_urls: bool = _bool("LW_ALLOW_PRIVATE_URLS", False)  # solo per test locali

    # Dati
    data_dir: Path = Path(os.environ.get("LW_DATA_DIR", "./data"))
    retention_hours: int = _int("LW_RETENTION_HOURS", 24)  # risultati e ricerche
    fingerprint_days: int = _int("LW_FINGERPRINT_DAYS", 30)  # 0 = disattivato
    store_profile: bool = _bool("LW_STORE_PROFILE", True)  # profilo cifrato su disco

    # Ricerca
    max_pages: int = _int("LW_MAX_PAGES", 25)
    max_page_bytes: int = _int("LW_MAX_PAGE_BYTES", 8 * 1024 * 1024)
    web_search_email: bool = _bool("LW_WEB_SEARCH_EMAIL", True)
    web_search_phone: bool = _bool("LW_WEB_SEARCH_PHONE", False)
    leakcheck_hashed: bool = _bool("LW_LEAKCHECK_HASHED", True)

    # Sessione
    auto_lock_minutes: int = _int("LW_AUTO_LOCK_MINUTES", 30)
    auto_scan_hours: int = _int("LW_AUTO_SCAN_HOURS", 0)  # 0 = solo manuale

    auto_scan_jitter_minutes: int = _int("LW_AUTO_SCAN_JITTER_MINUTES", 90)  # orario non prevedibile
    unlock_keyfile: str = os.environ.get("LW_UNLOCK_KEYFILE", "")  # sblocco automatico (opzionale)

    # Telegram
    telegram_token: str = os.environ.get("LW_TELEGRAM_TOKEN", "")
    telegram_chat_id: str = os.environ.get("LW_TELEGRAM_CHAT_ID", "")
    telegram_api: str = os.environ.get("LW_TELEGRAM_API", "https://api.telegram.org")
    telegram_quiet: bool = _bool("LW_TELEGRAM_QUIET", False)  # true = scrivi solo se ci sono novità
    telegram_commands: bool = _bool("LW_TELEGRAM_COMMANDS", True)

    # Server
    host: str = os.environ.get("LW_HOST", "127.0.0.1")
    port: int = _int("LW_PORT", 8765)


settings = Settings()
