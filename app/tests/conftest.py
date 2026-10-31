"""Ambiente di test: nessuna rete, nessun Tor, dati in una cartella temporanea.

Le variabili vanno impostate PRIMA di importare leakwatch.config.
"""

import os
import tempfile

os.environ.update(
    {
        "LW_DATA_DIR": tempfile.mkdtemp(prefix="leakwatch-test-"),
        "LW_REQUIRE_TOR": "false",
        "LW_TOR_PROXY": "",
        "LW_AUTO_SCAN_HOURS": "0",
        "LW_TELEGRAM_TOKEN": "",
        "LW_TELEGRAM_CHAT_ID": "",
    }
)
