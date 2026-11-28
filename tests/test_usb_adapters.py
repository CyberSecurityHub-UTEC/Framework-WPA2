"""Tests de list_usb_wifi_adapters y chip_module (detección por chipset USB)."""

from __future__ import annotations

import glob

from csh_tui import backend as be


def _sysfs_reader(mapping):
    """Devuelve un _read_sysfs falso que resuelve por nombre de fichero sysfs."""

    def _read(path: str) -> str:
        key = path.rsplit("/", 1)[-1]
        return mapping.get(path, mapping.get(key, ""))

    return _read


def test_chip_module_known():
    assert be.chip_module("MT7612U") == "mt76x2u"
    assert be.chip_module("RTL8812AU") == "8812au"
    assert be.chip_module("AR9271") == "ath9k_htc"


def test_chip_module_unknown():
    assert be.chip_module("NOPE1234") == ""


def test_driverless_mt7612u_detected(monkeypatch):
    dev = "/sys/bus/usb/devices/1-1"
    monkeypatch.setattr(glob, "glob", lambda pat: [dev])
    monkeypatch.setattr(be, "_read_sysfs", _sysfs_reader({
        "idVendor": "0e8d", "idProduct": "7612",
        "product": "Wireless Adapter", "manufacturer": "MediaTek",
    }))
    monkeypatch.setattr(be, "_usb_dev_has_netdev", lambda d: (False, ""))

    adapters = be.list_usb_wifi_adapters()
    assert len(adapters) == 1
    a = adapters[0]
    assert a["chip"] == "MT7612U"
    assert a["module"] == "mt76x2u"
    assert a["usb_id"] == "0e8d:7612"
    assert a["driver_loaded"] is False
    assert a["product"] == "Wireless Adapter"


def test_unknown_vidpid_ignored(monkeypatch):
    dev = "/sys/bus/usb/devices/2-1"
    monkeypatch.setattr(glob, "glob", lambda pat: [dev])
    monkeypatch.setattr(be, "_read_sysfs", _sysfs_reader({
        "idVendor": "1234", "idProduct": "5678",
    }))
    monkeypatch.setattr(be, "_usb_dev_has_netdev", lambda d: (False, ""))
    assert be.list_usb_wifi_adapters() == []


def test_device_without_vid_skipped(monkeypatch):
    dev = "/sys/bus/usb/devices/usb1"
    monkeypatch.setattr(glob, "glob", lambda pat: [dev])
    monkeypatch.setattr(be, "_read_sysfs", _sysfs_reader({}))  # sin idVendor
    monkeypatch.setattr(be, "_usb_dev_has_netdev", lambda d: (False, ""))
    assert be.list_usb_wifi_adapters() == []


def test_bound_device_excluded_by_default(monkeypatch):
    dev = "/sys/bus/usb/devices/1-1"
    monkeypatch.setattr(glob, "glob", lambda pat: [dev])
    monkeypatch.setattr(be, "_read_sysfs", _sysfs_reader({
        "idVendor": "0e8d", "idProduct": "7612",
    }))
    # Ya tiene netdev (driver cargado) -> excluido salvo include_bound=True.
    monkeypatch.setattr(be, "_usb_dev_has_netdev", lambda d: (True, "wlan0"))

    assert be.list_usb_wifi_adapters() == []

    bound = be.list_usb_wifi_adapters(include_bound=True)
    assert len(bound) == 1
    assert bound[0]["driver_loaded"] is True
    assert bound[0]["iface"] == "wlan0"


def test_multiple_devices_mixed(monkeypatch):
    known = "/sys/bus/usb/devices/1-1"
    unknown = "/sys/bus/usb/devices/2-1"
    monkeypatch.setattr(glob, "glob", lambda pat: [unknown, known])

    def _read(path):
        name = path.rsplit("/", 1)[-1]
        if path.startswith(known):
            return {"idVendor": "0cf3", "idProduct": "9271"}.get(name, "")
        return {"idVendor": "9999", "idProduct": "0000"}.get(name, "")

    monkeypatch.setattr(be, "_read_sysfs", _read)
    monkeypatch.setattr(be, "_usb_dev_has_netdev", lambda d: (False, ""))

    adapters = be.list_usb_wifi_adapters()
    assert len(adapters) == 1
    assert adapters[0]["chip"] == "AR9271"
    assert adapters[0]["module"] == "ath9k_htc"
