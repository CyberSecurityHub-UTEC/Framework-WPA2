"""Tests del modelo Network, channel_to_freq y safe_name."""

from __future__ import annotations

import pytest

from csh_tui import backend as be

# ─── Network.hidden ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("essid,expected", [
    ("", True),
    ("<hidden>", True),
    ("VisibleNet", False),
])
def test_hidden(net_factory, essid, expected):
    assert net_factory(essid=essid).hidden is expected


# ─── Network.encryption ───────────────────────────────────────────────────────

@pytest.mark.parametrize("privacy,auth,expected", [
    ("WPA2", "PSK", "WPA2"),
    ("WPA2 WPA", "PSK", "WPA2"),
    ("WPA", "PSK", "WPA"),
    ("WPA3", "SAE", "WPA3"),
    ("WPA2", "SAE", "WPA3"),       # SAE gana aunque privacy diga WPA2
    ("WEP", "", "WEP"),
    ("OPN", "", "OPN"),
    ("", "", "?"),
])
def test_encryption(net_factory, privacy, auth, expected):
    assert net_factory(privacy=privacy, auth=auth).encryption == expected


# ─── Network.is_enterprise ────────────────────────────────────────────────────

@pytest.mark.parametrize("auth,expected", [
    ("MGT", True),
    ("mgt", True),
    ("EAP", True),
    ("PSK", False),
    ("", False),
])
def test_is_enterprise(net_factory, auth, expected):
    assert net_factory(auth=auth).is_enterprise is expected


# ─── Network.crackable ────────────────────────────────────────────────────────

def test_crackable_wpa2_psk(net_factory):
    assert net_factory(privacy="WPA2", auth="PSK").crackable is True


def test_crackable_wpa_psk(net_factory):
    assert net_factory(privacy="WPA", auth="PSK").crackable is True


def test_not_crackable_enterprise(net_factory):
    assert net_factory(privacy="WPA2", auth="MGT").crackable is False


def test_not_crackable_wpa3(net_factory):
    assert net_factory(privacy="WPA3", auth="SAE").crackable is False


def test_not_crackable_open(net_factory):
    assert net_factory(privacy="OPN", auth="").crackable is False


# ─── channel_to_freq ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("ch,expected", [
    ("1", "2412 MHz"),
    ("6", "2437 MHz"),
    ("13", "2472 MHz"),
    ("14", "2484 MHz"),
    ("36", "5180 MHz"),
    ("149", "5745 MHz"),
])
def test_channel_to_freq_valid(ch, expected):
    assert be.channel_to_freq(ch) == expected


@pytest.mark.parametrize("ch", ["", "abc", None, "0", "20"])
def test_channel_to_freq_invalid(ch):
    assert be.channel_to_freq(ch) == "N/A"


# ─── safe_name ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("<hidden>", "hidden"),
    ("My Net!", "My_Net"),
    ("Clean-Name_1.0", "Clean-Name_1.0"),
    ("", "unknown"),
    ("!!!", "unknown"),
    (None, "unknown"),
    ("  spaces  ", "spaces"),
])
def test_safe_name(raw, expected):
    assert be.safe_name(raw) == expected
