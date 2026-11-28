"""Tests de is_root, have y capabilities."""

from __future__ import annotations

from csh_tui import backend as be


def test_is_root_true(monkeypatch):
    monkeypatch.setattr(be.os, "geteuid", lambda: 0)
    assert be.is_root() is True


def test_is_root_false(monkeypatch):
    monkeypatch.setattr(be.os, "geteuid", lambda: 1000)
    assert be.is_root() is False


def test_have_present(monkeypatch):
    monkeypatch.setattr(be.shutil, "which", lambda c: "/usr/bin/" + c)
    assert be.have("airodump-ng") is True


def test_have_absent(monkeypatch):
    monkeypatch.setattr(be.shutil, "which", lambda c: None)
    assert be.have("airodump-ng") is False


def test_capabilities_all_present(monkeypatch):
    monkeypatch.setattr(be, "have", lambda c: True)
    caps = be.capabilities()
    assert caps["airodump-ng"] is True
    assert caps["hashcat"] is True
    # Todas las herramientas esperadas están presentes como claves.
    assert {"airodump-ng", "aireplay-ng", "aircrack-ng", "tshark",
            "hcxpcapngtool", "hashcat", "crunch"} <= set(caps)


def test_capabilities_partial(monkeypatch):
    present = {"airodump-ng", "aircrack-ng"}
    monkeypatch.setattr(be, "have", lambda c: c in present)
    caps = be.capabilities()
    assert caps["airodump-ng"] is True
    assert caps["aircrack-ng"] is True
    assert caps["hashcat"] is False
    assert caps["tshark"] is False
