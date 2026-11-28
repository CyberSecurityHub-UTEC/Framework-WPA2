"""Tests de list_interfaces, iface_bus y select_monitor_interface."""

from __future__ import annotations

from csh_tui import backend as be
from tests.conftest import FakeProc

# `iw dev` con la antena USB externa (phy#1) ANTES de un bloque
# Unnamed/non-netdev (P2P-device) de phy#0. Reproduce el bug real: el bloque
# P2P no debe pisar/borrar la interfaz externa.
IW_DEV = """phy#1
\tInterface wlp0s20f0u2
\t\tifindex 5
\t\twdev 0x100000001
\t\taddr 11:22:33:44:55:66
\t\ttype managed
\t\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
\t\ttxpower 20.00 dBm
phy#0
\tUnnamed/non-netdev interface
\t\twdev 0x4
\t\taddr aa:bb:cc:dd:ee:ff
\t\ttype P2P-device
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\taddr aa:bb:cc:dd:ee:00
\t\ttype managed
\t\tchannel 11 (2462 MHz), width: 20 MHz
"""

# Clasificación de bus por interfaz (sustituye la lectura de /sys).
_BUS = {"wlp0s20f0u2": "usb", "wlan0": "pci"}


def _patch_iw(monkeypatch, stdout=IW_DEV):
    monkeypatch.setattr(be.subprocess, "run",
                        lambda *a, **k: FakeProc(stdout=stdout))
    monkeypatch.setattr(be, "iface_bus", lambda iface: _BUS.get(iface, "other"))


def test_external_iface_before_p2p_is_preserved(monkeypatch):
    """Regresión: la externa (phy#1) NO se pierde por el bloque P2P de phy#0."""
    _patch_iw(monkeypatch)
    ifs = be.list_interfaces()
    names = {i["iface"] for i in ifs}
    assert "wlp0s20f0u2" in names
    ext = next(i for i in ifs if i["iface"] == "wlp0s20f0u2")
    assert ext["bus"] == "usb"
    assert ext["external"] is True
    assert ext["type"] == "managed"
    assert ext["phy"] == "phy#1"
    assert ext["mac"] == "11:22:33:44:55:66"


def test_p2p_device_excluded(monkeypatch):
    _patch_iw(monkeypatch)
    ifs = be.list_interfaces()
    assert all(i["type"] != "P2P-device" for i in ifs)
    # El P2P no tiene nombre de interfaz, así que no debe aparecer su addr.
    assert all(i["mac"] != "aa:bb:cc:dd:ee:ff" for i in ifs)


def test_multiple_phys_parsed(monkeypatch):
    _patch_iw(monkeypatch)
    ifs = be.list_interfaces()
    names = {i["iface"] for i in ifs}
    assert names == {"wlp0s20f0u2", "wlan0"}
    phys = {i["iface"]: i["phy"] for i in ifs}
    assert phys["wlan0"] == "phy#0"
    assert phys["wlp0s20f0u2"] == "phy#1"


def test_external_only_filters_to_usb(monkeypatch):
    _patch_iw(monkeypatch)
    ifs = be.list_interfaces(external_only=True)
    names = {i["iface"] for i in ifs}
    assert names == {"wlp0s20f0u2"}


def test_list_interfaces_subprocess_failure_returns_empty(monkeypatch):
    def _boom(*a, **k):
        raise OSError("no iw")

    monkeypatch.setattr(be.subprocess, "run", _boom)
    assert be.list_interfaces() == []


def test_iface_bus_usb(monkeypatch):
    monkeypatch.setattr(be.os.path, "realpath", lambda p: "/sys/bus/usb")
    assert be.iface_bus("wlan0") == "usb"


def test_iface_bus_pci(monkeypatch):
    monkeypatch.setattr(be.os.path, "realpath", lambda p: "/sys/bus/pci")
    assert be.iface_bus("wlan0") == "pci"


def test_iface_bus_error_returns_other(monkeypatch):
    def _boom(p):
        raise OSError

    monkeypatch.setattr(be.os.path, "realpath", _boom)
    assert be.iface_bus("wlan0") == "other"


# ─── select_monitor_interface (función pura) ──────────────────────────────────

def _if(iface, typ, phy, bus="usb"):
    return {"iface": iface, "type": typ, "phy": phy, "bus": bus,
            "mac": "00:00:00:00:00:00", "channel": "6", "external": bus == "usb"}


def test_smi_target_itself_is_monitor():
    after = [_if("wlan1", "monitor", "phy#1")]
    assert be.select_monitor_interface({"wlan1"}, after, "wlan1") == "wlan1"


def test_smi_new_monitor_name_derived():
    before = {"wlan1"}
    after = [_if("wlan1", "managed", "phy#1"), _if("wlan1mon", "monitor", "phy#1")]
    assert be.select_monitor_interface(before, after, "wlan1") == "wlan1mon"


def test_smi_new_monitor_same_phy_unrelated_name():
    before = {"wlan1"}
    after = [_if("wlan1", "managed", "phy#1"), _if("mon0", "monitor", "phy#1")]
    assert be.select_monitor_interface(before, after, "wlan1") == "mon0"


def test_smi_existing_monitor_on_target_phy():
    # El monitor ya existía (está en `before`), así que no es "nuevo":
    # se selecciona por la rama (c) "cualquier monitor en la misma phy".
    before = {"wlan1", "wlan1mon"}
    after = [_if("wlan1", "managed", "phy#1"), _if("wlan1mon", "monitor", "phy#1")]
    assert be.select_monitor_interface(before, after, "wlan1") == "wlan1mon"


def test_smi_never_leaks_unrelated_monitor_bug1():
    """Bug 1: un monitor ajeno (otra phy Y nombre no relacionado) NO se devuelve."""
    before = {"wlan1", "wlan0mon"}
    after = [_if("wlan1", "managed", "phy#1"),
             _if("wlan0mon", "monitor", "phy#0")]
    result = be.select_monitor_interface(before, after, "wlan1")
    assert result != "wlan0mon"
    assert result is None


def test_smi_unrelated_monitor_even_when_new():
    before = {"wlan1"}
    after = [_if("wlan1", "managed", "phy#1"),
             _if("wlan0mon", "monitor", "phy#0")]
    assert be.select_monitor_interface(before, after, "wlan1") is None


def test_smi_returns_none_when_nothing_matches():
    before = {"wlan1"}
    after = [_if("wlan1", "managed", "phy#1")]
    assert be.select_monitor_interface(before, after, "wlan1") is None


def test_smi_documented_limitation_renamed_absent_target():
    """Limitación documentada: target renombrado, ausente de `after`, y el
    monitor no deriva del nombre de target -> None (no se puede mapear la phy)."""
    before = {"wlan1"}
    after = [_if("mon0", "monitor", "phy#5")]
    assert be.select_monitor_interface(before, after, "wlan1") is None
