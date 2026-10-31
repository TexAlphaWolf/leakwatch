"""Robustezza e sicurezza: PDF, SSRF, kill switch Tor, input malformati, sorgenti esterne, sessioni."""

import asyncio
import dataclasses
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from leakwatch import main, net
from leakwatch.profile import MAX_ITEMS, Profile
from leakwatch.sources import leakcheck, pwned_passwords, web
from leakwatch.telegram import format_report
from leakwatch.vault import Vault

H = {"X-LeakWatch": "1"}
PASS = "una passphrase di test lunga"


# --------------------------------------------------------------------------- #
# PDF (graduatorie, albi, atti: il caso più comune di esposizione del CF)
# --------------------------------------------------------------------------- #
def make_pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def test_pdf_text_extraction():
    text = web.pdf_to_text(make_pdf("ROSSI MARIO RSSMRA85T10A562S"))
    assert "RSSMRA85T10A562S" in text and "ROSSI MARIO" in text


def test_pdf_garbage_does_not_crash():
    assert web.pdf_to_text(b"%PDF-1.4 rotto") == ""


def test_fetch_text_handles_pdf_and_size_limit():
    pdf = make_pdf("RSSMRA85T10A562S")

    def handler(request):
        if request.url.path == "/doc":
            return httpx.Response(200, content=pdf, headers={"content-type": "application/pdf"})
        return httpx.Response(200, content=b"A" * (9 * 1024 * 1024), headers={"content-type": "text/html"})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await web.fetch_text(c, "https://example.org/doc"), await web.fetch_text(
                c, "https://example.org/big"
            )

    doc, big = asyncio.run(run())
    assert "RSSMRA85T10A562S" in doc
    assert isinstance(big, str)  # risposta oltre il limite: nessun crash


# --------------------------------------------------------------------------- #
# SSRF: una pagina trovata online non può far raggiungere la rete di casa
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "localhost",
        "192.168.1.10",
        "10.0.0.5",
        "[::1]",
        "router.lan",
        "nas.local",
        "searxng",
        "169.254.1.1",
    ],
)
def test_internal_hosts_are_detected(host):
    assert net.is_internal_host(host)


@pytest.mark.parametrize("host", ["example.org", "comune.example.it", "8.8.8.8", "api.telegram.org"])
def test_public_hosts_are_allowed(host):
    assert not net.is_internal_host(host)


def test_external_client_blocks_internal_destinations():
    async def run():
        async with net.external_client() as c:
            await c.get("http://192.168.1.1/admin")

    with pytest.raises(net.BlockedDestination):
        asyncio.run(run())


# --------------------------------------------------------------------------- #
# Kill switch Tor
# --------------------------------------------------------------------------- #
def test_kill_switch_and_check_cache(monkeypatch):
    monkeypatch.setattr(net, "settings", dataclasses.replace(net.settings, require_tor=True))
    calls = []

    async def tor_down(_c):
        calls.append(1)
        return False

    async def tor_up(_c):
        calls.append(1)
        return True

    net.forget_tor_check()
    monkeypatch.setattr(net, "check_tor", tor_down)
    with pytest.raises(net.TorUnavailable):
        asyncio.run(net.ensure_tor(None))

    monkeypatch.setattr(net, "check_tor", tor_up)
    asyncio.run(net.ensure_tor(None))
    asyncio.run(net.ensure_tor(None))  # entro 10 minuti: nessuna nuova verifica
    assert len(calls) == 2
    net.forget_tor_check()


# --------------------------------------------------------------------------- #
# Input malformati
# --------------------------------------------------------------------------- #
def test_profile_from_dict_is_robust():
    p = Profile.from_dict(
        {
            "first_name": 123,
            "last_name": {"x": 1},
            "cf": None,
            "emails": [f"a{i}@example.com" for i in range(50)] + ["a0@example.com", {"bad": 1}],
            "phones": "333 1, 333 2",
            "documents": 42,
        }
    )
    assert p.first_name == "123" and p.last_name == "" and p.cf == ""
    assert len(p.emails) == MAX_ITEMS and len(set(p.emails)) == MAX_ITEMS
    assert p.phones == ["333 1", "333 2"] and p.documents == []


def test_scan_rejects_oversized_passwords():
    if main.vault.initialized:
        main.vault.wipe()
    c = TestClient(main.app, base_url="http://127.0.0.1")
    c.post("/api/init", json={"passphrase": PASS}, headers=H)
    r = c.post("/api/scan", json={"passwords": ["x" * 1000]}, headers=H)
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# Sorgenti esterne (risposte simulate)
# --------------------------------------------------------------------------- #
def test_pwned_passwords_sends_only_prefix():
    seen = []
    # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\n"

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, text=body)

    async def run(pw):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await pwned_passwords.times_pwned(c, pw)

    assert asyncio.run(run("password")) == 3861493
    assert asyncio.run(run("una-password-mai-vista-2026")) == 0
    assert seen[0].endswith("/range/5BAA6")  # solo 5 caratteri dell'hash
    assert not any("1E4C9B93F3F0682250B6CF8331B7EE68FD8" in u for u in seen)  # mai il resto


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (
            200,
            {"success": True, "found": 1, "fields": ["password"], "sources": [{"name": "X", "date": "2020"}]},
            1,
        ),
        (200, {"success": False, "error": "Not found"}, 0),
    ],
)
def test_leakcheck_parsing(status, payload, expected):
    def handler(request):
        return httpx.Response(status, json=payload)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await leakcheck.lookup(c, "abc")

    assert asyncio.run(run())["found"] == expected


def test_leakcheck_rate_limit_is_reported():
    async def run():
        transport = httpx.MockTransport(lambda r: httpx.Response(429, json={}))
        async with httpx.AsyncClient(transport=transport) as c:
            return await leakcheck.lookup(c, "abc")

    with pytest.raises(RuntimeError, match="limite"):
        asyncio.run(run())


# --------------------------------------------------------------------------- #
# Telegram, sessioni, brute force
# --------------------------------------------------------------------------- #
def test_telegram_message_retention(tmp_path):
    v = Vault(tmp_path / "v.db")
    v.add_tg_message("555", 1)
    v.add_tg_message("555", 2)
    v._db.execute("UPDATE tg_messages SET sent_at = ? WHERE message_id = 1", (time.time() - 25 * 3600,))
    assert v.due_tg_messages(24) == [("555", 1)]
    v.remove_tg_message("555", 1)
    assert v.all_tg_messages() == [("555", 2)]


def test_quiet_report_is_skipped_when_nothing_new(monkeypatch):
    import leakwatch.telegram as tgmod

    monkeypatch.setattr(tgmod, "settings", dataclasses.replace(tgmod.settings, telegram_quiet=True))
    assert format_report({"started": time.time(), "errors": []}, [], 0, True) is None
    assert format_report({"started": time.time(), "errors": ["x"]}, [], 0, True) is not None


def test_state_polling_does_not_extend_session():
    if main.vault.initialized:
        main.vault.wipe()
    main._sessions.clear()
    c = TestClient(main.app, base_url="http://127.0.0.1")
    c.post("/api/init", json={"passphrase": PASS}, headers=H)
    token = next(iter(main._sessions))
    main._sessions[token] = time.time() + 5
    before = main._sessions[token]
    assert c.get("/api/state").json()["unlocked"] is True
    assert main._sessions[token] == before  # lo stato non rinnova
    c.get("/api/profile")
    assert main._sessions[token] > before  # un'azione reale sì


def test_failed_unlocks_slow_down_and_reset(monkeypatch):
    if main.vault.initialized:
        main.vault.wipe()
    main._sessions.clear()
    main._failed_unlocks = 0
    delays = []
    real_sleep = asyncio.sleep

    async def fake_sleep(s):
        delays.append(s)
        await real_sleep(0)

    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    c = TestClient(main.app, base_url="http://127.0.0.1")
    c.post("/api/init", json={"passphrase": PASS}, headers=H)
    c.post("/api/lock", json={}, headers=H)
    for _ in range(3):
        assert c.post("/api/unlock", json={"passphrase": "sbagliata!!!!"}, headers=H).status_code == 401
    assert delays == [1.5, 3.0, 4.5]  # ritardo crescente
    assert c.post("/api/unlock", json={"passphrase": PASS}, headers=H).status_code == 200
    assert main._failed_unlocks == 0
