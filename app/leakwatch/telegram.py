"""Bot Telegram: report giornaliero e comandi, sempre via Tor.

Regole:
- I messaggi dei bot NON sono cifrati end-to-end: non inviamo mai CF, documenti,
  date, email, telefoni né estratti di testo. Solo conteggi, gravità, domini e tipi di dato.
- Il bot risponde solo al chat ID configurato; tutto il resto viene ignorato.
- I messaggi (del bot e i tuoi comandi) vengono cancellati dopo LW_RETENTION_HOURS.
- protect_content: i messaggi non si possono inoltrare né salvare.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime
from urllib.parse import urlsplit

from . import net
from .config import settings
from .vault import Vault

log = logging.getLogger("leakwatch.telegram")

ICON = {"alta": "🔴", "media": "🟠", "bassa": "🔵"}


class Telegram:
    def __init__(self, vault: Vault):
        self.vault = vault
        self.chat_id = str(settings.telegram_chat_id).strip()
        self._base = f"{settings.telegram_api.rstrip('/')}/bot{settings.telegram_token}"

    @property
    def enabled(self) -> bool:
        return bool(settings.telegram_token and self.chat_id)

    async def _call(self, method: str, payload: dict, timeout: float = 30) -> dict:
        async with net.external_client() as client:
            await net.ensure_tor(client)
            r = await client.post(f"{self._base}/{method}", json=payload, timeout=timeout)
        data = r.json()
        if not data.get("ok"):
            # la descrizione di Telegram non contiene dati nostri
            raise RuntimeError(f"Telegram {method}: {data.get('description', r.status_code)}")
        return data

    # ------------------------------------------------------------------ #
    async def send(self, text: str) -> None:
        if not self.enabled:
            return
        data = await self._call(
            "sendMessage",
            {
                "chat_id": self.chat_id,
                "text": text[:4000],
                "disable_web_page_preview": True,
                "protect_content": True,
            },
        )
        self.vault.add_tg_message(self.chat_id, int(data["result"]["message_id"]))

    async def _delete(self, chat_id: str, message_id: int) -> None:
        # già cancellato, o oltre le 48h consentite da Telegram
        with contextlib.suppress(RuntimeError):
            await self._call("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
        self.vault.remove_tg_message(chat_id, message_id)

    async def delete_expired(self) -> None:
        if not self.enabled:
            return
        for chat_id, mid in self.vault.due_tg_messages(settings.retention_hours):
            await self._delete(chat_id, mid)

    async def delete_all(self) -> None:
        if not self.enabled:
            return
        for chat_id, mid in self.vault.all_tg_messages():
            await self._delete(chat_id, mid)

    # ------------------------------------------------------------------ #
    async def poll_commands(self, handler: Callable[[str], Awaitable[str]]) -> None:
        """Long polling (niente webhook: nessuna porta esposta)."""
        if not (self.enabled and settings.telegram_commands):
            return
        offset = int(self.vault.get_meta("tg_offset") or 0)
        backoff = 5
        while True:
            try:
                data = await self._call(
                    "getUpdates",
                    {"offset": offset, "timeout": 50, "allowed_updates": ["message"]},
                    timeout=70,
                )
                for upd in data.get("result", []):
                    offset = max(offset, int(upd["update_id"]) + 1)
                    self.vault.set_meta("tg_offset", str(offset))
                    msg = upd.get("message") or {}
                    chat = str((msg.get("chat") or {}).get("id", ""))
                    if chat != self.chat_id:
                        continue  # sconosciuti: ignorati in silenzio
                    self.vault.add_tg_message(chat, int(msg["message_id"]))  # cancella anche i tuoi
                    text = (msg.get("text") or "").strip()
                    if text.startswith("/"):
                        reply = await handler(text.split()[0].split("@")[0].lower())
                        if reply:
                            await self.send(reply)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("Polling Telegram: %s", type(e).__name__)
                net.forget_tor_check()
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 120)  # 5, 10, 20, 40, 80, 120 s
                continue
            backoff = 5


# --------------------------------------------------------------------------- #
# Testo dei report (solo informazioni non sensibili)
# --------------------------------------------------------------------------- #
def _line(f: dict) -> str:
    icon = ICON.get(f["severity"], "•")
    labels = ", ".join(dict.fromkeys(i["label"] for i in f.get("items", [])))
    if f["kind"] == "web":
        host = urlsplit(f.get("url", "")).hostname or "sito sconosciuto"
        return f"{icon} Web · {host} — {labels}"
    if f["kind"] == "breach":
        name = f.get("breach_name", "sconosciuto")
        exposed = f["items"][0]["context"] if f.get("items") else ""
        return f"{icon} Breach «{name}» — dati esposti: {exposed}"
    if f["kind"] == "password":
        return f"{icon} {f['title']}"
    return f"{icon} {f.get('source', '')}"


def format_report(summary: dict, new: list[dict], active_total: int, automatic: bool) -> str | None:
    errors = summary.get("errors", [])
    if settings.telegram_quiet and not new and not errors:
        return None
    when = datetime.fromtimestamp(summary.get("ended") or summary["started"]).strftime("%d/%m %H:%M")
    head = f"🔎 LeakWatch · scansione {'automatica' if automatic else 'manuale'} del {when}"
    lines = [head]
    if new:
        counts = {s: sum(1 for f in new if f["severity"] == s) for s in ("alta", "media", "bassa")}
        detail = ", ".join(f"{ICON[s]} {c} {s}" for s, c in counts.items() if c)
        lines += [f"Nuovi risultati: {len(new)} ({detail})", ""]
        order = {"alta": 0, "media": 1, "bassa": 2}
        shown = sorted(new, key=lambda f: order.get(f["severity"], 3))[:15]
        lines += [_line(f) for f in shown]
        if len(new) > len(shown):
            lines.append(f"…e altri {len(new) - len(shown)}")
    else:
        lines.append("✅ Nessun nuovo leak trovato.")
    lines += ["", f"Risultati attivi: {active_total}. Dettagli nella dashboard."]
    if errors:
        lines += ["", "⚠️ Problemi: " + " · ".join(errors[:4])]
    lines.append(f"Questo messaggio si cancella tra {settings.retention_hours}h.")
    return "\n".join(lines)
