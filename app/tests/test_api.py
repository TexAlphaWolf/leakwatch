"""Sicurezza dell'API locale: host, CSRF, sessioni, path traversal, wipe."""

import pytest
from fastapi.testclient import TestClient

from leakwatch import main

PASS = "una passphrase di test lunga"
H = {"X-LeakWatch": "1"}


@pytest.fixture
def client():
    if main.vault.initialized:
        main.vault.wipe()
    main._sessions.clear()
    # Senza "with": niente lifespan, quindi nessun task di fondo durante i test
    return TestClient(main.app, base_url="http://127.0.0.1")


def test_rejects_foreign_host(client):
    r = client.get("/api/state", headers={"Host": "evil.example"})
    assert r.status_code == 403


def test_rejects_post_without_csrf_header(client):
    assert client.post("/api/init", json={"passphrase": PASS}).status_code == 403


def test_rejects_cross_origin(client):
    r = client.post("/api/init", json={"passphrase": PASS}, headers={**H, "Origin": "https://evil.example"})
    assert r.status_code == 403


def test_security_headers(client):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"


def test_static_path_traversal(client):
    assert client.get("/static/..%2Fmain.py").status_code == 404


def test_full_session_flow(client):
    assert client.post("/api/init", json={"passphrase": "corta"}, headers=H).status_code == 400
    r = client.post("/api/init", json={"passphrase": PASS}, headers=H)
    assert r.status_code == 200
    assert "httponly" in r.headers["set-cookie"].lower()
    assert "samesite=strict" in r.headers["set-cookie"].lower()

    profile = {"first_name": "Mario", "last_name": "Rossi", "cf": "RSSMRA85T10A562X"}
    r = client.put("/api/profile", json=profile, headers=H)
    assert r.status_code == 200
    assert any("codice fiscale" in w.lower() for w in r.json()["warnings"])  # carattere di controllo errato
    assert client.get("/api/profile").json()["first_name"] == "Mario"

    # Un altro browser, senza cookie, non vede nulla
    stranger = TestClient(main.app, base_url="http://127.0.0.1")
    assert stranger.get("/api/results").status_code == 423
    assert stranger.get("/api/profile").status_code == 423

    # Blocco: senza scheduler la chiave esce dalla RAM
    assert client.post("/api/lock", json={}, headers=H).status_code == 200
    assert not main.vault.unlocked
    assert client.get("/api/profile").status_code == 423

    assert client.post("/api/unlock", json={"passphrase": "sbagliata!!!!"}, headers=H).status_code == 401
    assert client.post("/api/unlock", json={"passphrase": PASS}, headers=H).status_code == 200
    assert client.get("/api/profile").json()["last_name"] == "Rossi"


def test_wipe_requires_exact_confirmation(client):
    client.post("/api/init", json={"passphrase": PASS}, headers=H)
    assert client.post("/api/wipe", json={"confirm": "si"}, headers=H).status_code == 400
    assert client.post("/api/wipe", json={"confirm": "CANCELLA TUTTO"}, headers=H).status_code == 200
    assert not main.vault.initialized
    assert client.get("/api/state").json()["initialized"] is False
