import time

import pytest

from leakwatch import normalize as n
from leakwatch.matcher import Matcher
from leakwatch.profile import Profile
from leakwatch.vault import Vault, VaultLocked

CF = "RSSMRA85T10A562S"  # codice fiscale di esempio (Mario Rossi)


def test_cf_validation():
    assert n.is_valid_cf(CF)
    assert n.is_valid_cf("rssmra 85t10 a562s")
    assert not n.is_valid_cf("RSSMRA85T10A562X")
    assert n.cf_check_char(CF[:15]) == "S"


def test_phone_and_dates():
    assert n.normalize_phone("+39 333 123 4567") == "3331234567"
    assert n.normalize_phone("0039-333.1234567") == "3331234567"
    v = n.date_variants("1985-12-10")
    assert "10/12/1985" in v and "10 dicembre 1985" in v and "1985-12-10" in v


def test_levenshtein():
    assert n.levenshtein("ROSSI", "ROSI") == 1
    assert n.fuzzy_equal("BIANCHINI", "BIANCINI")
    assert not n.fuzzy_equal("LUCA", "LUKA")  # parole corte: nessuna tolleranza


@pytest.fixture
def profile():
    return Profile.from_dict(
        {
            "first_name": "Mario",
            "last_name": "Rossi",
            "birth_date": "1985-12-10",
            "emails": ["mario.rossi@example.com"],
            "phones": ["+39 333 1234567"],
            "cf": CF,
            "documents": ["CA12345AB"],
        }
    )


def test_matcher_detects_everything(profile):
    text = (
        "Graduatoria 2024 - ROSSÌ Mario nato il 10/12/1985, C.F. RSS MRA 85T10 A562S, "
        "documento CA 12345 AB, tel. 333 123 4567, mail Mario.Rossi@example.com"
    )
    fields = {h.field for h in Matcher(profile).scan(text)}
    assert {"cf", "document", "phone", "email", "name+birth"} <= fields


def test_matcher_masks_context(profile):
    hits = Matcher(profile).scan("Elenco: Mario Rossi, CF RSSMRA85T10A562S, nato il 10/12/1985")
    joined = " ".join(h.context for h in hits)
    assert CF not in joined and "10/12/1985" not in joined


def test_matcher_no_false_positive(profile):
    assert Matcher(profile).scan("Mario Bianchi e Luca Rossi, codice VRDGPP80A01H501U") == []


def test_matcher_omocodia(profile):
    omo = "RSSMRA85T1LA562"  # 0 -> L in posizione 10
    omo += n.cf_check_char(omo)
    assert any(h.field == "cf" for h in Matcher(profile).scan(f"codice {omo}"))


def test_vault_roundtrip_and_purge(tmp_path):
    v = Vault(tmp_path / "v.db")
    v.init("una passphrase lunga")
    v.save_profile({"first_name": "Mario"}, persist=True)
    v.add_scan("s1", {"id": "s1"})
    assert v.add_finding("s1", {"title": "x"}, v.fingerprint("a")) is True
    assert v.add_finding("s1", {"title": "x"}, v.fingerprint("a")) is False  # non è più nuovo
    raw = (tmp_path / "v.db").read_bytes()
    assert b"Mario" not in raw  # cifrato su disco
    v.lock()
    with pytest.raises(VaultLocked):
        v.load_profile()
    assert not v.unlock("sbagliata!!!!")
    assert v.unlock("una passphrase lunga")
    assert v.load_profile()["first_name"] == "Mario"
    # Simula il passaggio di 25 ore
    v._db.execute("UPDATE findings SET created_at = ?", (time.time() - 25 * 3600,))
    v._db.execute("UPDATE scans SET created_at = ?", (time.time() - 25 * 3600,))
    assert v.purge(24, 30) == 3
    assert v.list_findings(24) == [] and v.list_scans() == []
    v.wipe()
    assert not v.initialized
