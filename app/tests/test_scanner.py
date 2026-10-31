"""Scansione end-to-end con sorgenti simulate (nessuna rete) e report Telegram."""

import asyncio

import pytest

from leakwatch import net, scanner
from leakwatch.profile import Profile
from leakwatch.sources import leakcheck, pwned_passwords, web
from leakwatch.telegram import format_report
from leakwatch.vault import Vault

SECRETS = ["RSSMRA85T10A562S", "CA12345AB", "MARIO.ROSSI@EXAMPLE.COM", "10/12/1985", "MARIO ROSSI"]
PAGE = (
    "<html><head><title>Graduatoria</title><script>var x = 1;</script></head><body>"
    "<td>ROSSI MARIO</td><td>10/12/1985</td><td>RSSMRA85T10A562S</td></body></html>"
)


@pytest.fixture
def profile():
    return Profile.from_dict(
        {
            "first_name": "Mario",
            "last_name": "Rossi",
            "birth_date": "1985-12-10",
            "emails": ["mario.rossi@example.com"],
            "cf": "RSSMRA85T10A562S",
            "documents": ["CA12345AB"],
        }
    )


@pytest.fixture
def offline(monkeypatch):
    sent_queries = []

    async def noop(*_a, **_k):
        return None

    async def fake_pwned(_client, password):
        return 42 if password == "password123" else 0

    async def fake_leakcheck(_client, query):
        sent_queries.append(query)
        return {
            "found": 1,
            "fields": ["email", "password"],
            "sources": [{"name": "ExampleShop", "date": "2023-05"}],
        }

    async def fake_searx(_client, query):
        sent_queries.append(query)
        return [{"url": "https://comune.example.it/graduatoria.pdf", "title": "Graduatoria", "snippet": ""}]

    async def fake_fetch(_client, _url):
        return web.html_to_text(PAGE)

    monkeypatch.setattr(net, "ensure_tor", noop)
    monkeypatch.setattr(net, "jitter", noop)
    monkeypatch.setattr(pwned_passwords, "times_pwned", fake_pwned)
    monkeypatch.setattr(leakcheck, "lookup", fake_leakcheck)
    monkeypatch.setattr(web, "searx", fake_searx)
    monkeypatch.setattr(web, "fetch_text", fake_fetch)
    return sent_queries


def test_html_to_text_skips_scripts():
    text = web.html_to_text(PAGE)
    assert "var x" not in text and "ROSSI MARIO" in text


def test_scan_finds_and_tracks_novelty(tmp_path, profile, offline):
    vault = Vault(tmp_path / "v.db")
    vault.init("una passphrase lunga")
    reports = []

    async def on_done(summary, new, automatic):
        reports.append((summary, new))

    sc = scanner.Scanner(vault, on_done=on_done)

    asyncio.run(sc.run(profile, ["password123", "unica-e-sicura"]))
    _summary, new = reports[-1]
    kinds = {f["kind"] for f in new}
    assert kinds == {"password", "breach", "web"}
    web_hit = next(f for f in new if f["kind"] == "web")
    assert web_hit["severity"] == "alta"
    assert {i["field"] for i in web_hit["items"]} >= {"cf", "name+birth"}

    # Privacy delle richieste: a LeakCheck va l'hash dell'email; CF, documento e data mai inviati
    sent = " ".join(offline).upper()
    assert leakcheck.email_hash("mario.rossi@example.com") in offline
    assert "mario.rossi@example.com" not in offline
    assert "RSSMRA85T10A562S" not in sent and "CA12345AB" not in sent and "1985" not in sent

    # Seconda scansione: stessi risultati, nessuna novità
    asyncio.run(sc.run(profile, ["password123"]))
    assert reports[-1][0]["new"] == 0 and reports[-1][1] == []


def test_telegram_report_contains_no_personal_data(tmp_path, profile, offline):
    vault = Vault(tmp_path / "v.db")
    vault.init("una passphrase lunga")
    out = {}

    async def on_done(summary, new, automatic):
        out["text"] = format_report(summary, new, len(new), automatic)

    asyncio.run(scanner.Scanner(vault, on_done=on_done).run(profile, ["password123"]))
    text = out["text"].upper()
    for secret in SECRETS:
        assert secret not in text, secret
    assert "COMUNE.EXAMPLE.IT" in text and "EXAMPLESHOP" in text
