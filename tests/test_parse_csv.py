"""Tests de parse_airodump_csv: parseo del CSV de airodump-ng."""
# Las filas CSV de ejemplo reproducen el ancho real de airodump-ng y superan a
# propósito el límite de 100 columnas; no las partimos para no falsear el dato.
# ruff: noqa: E501

from __future__ import annotations

from csh_tui import backend as be

AP_HEADER = ("BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
             "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, "
             "ESSID, Key")
STA_HEADER = ("Station MAC, First time seen, Last time seen, Power, # packets, "
              "BSSID, Probed ESSIDs")

FULL_CSV = f"""{AP_HEADER}

AA:BB:CC:DD:EE:01, 2024-01-01 10:00:00, 2024-01-01 10:05:00,  6,  54, WPA2, CCMP, PSK, -45,  120,    0,   0.  0.  0.  0,   7, HomeNet,
AA:BB:CC:DD:EE:02, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 11,  54, WPA2 WPA, CCMP TKIP, PSK, -70,   50,    0,   0.  0.  0.  0,   0, ,
AA:BB:CC:DD:EE:03, 2024-01-01 10:00:00, 2024-01-01 10:05:00,  1,  54, OPN, , , -80,   10,    0,   0.  0.  0.  0,   8, OpenWifi,
AA:BB:CC:DD:EE:04, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 36,  54, WPA3, CCMP, SAE, xx,   10,    0,   0.  0.  0.  0,   9, SecureNet,

{STA_HEADER}

11:22:33:44:55:66, 2024-01-01 10:00:00, 2024-01-01 10:05:00, -50,   20, AA:BB:CC:DD:EE:01,
11:22:33:44:55:77, 2024-01-01 10:00:00, 2024-01-01 10:05:00, -60,   15, AA:BB:CC:DD:EE:01, SomeProbe
88:88:88:88:88:88, 2024-01-01 10:00:00, 2024-01-01 10:05:00, -65,    5, AA:BB:CC:DD:EE:03, FreeWifi
"""


def _write(tmp_path, text: str):
    p = tmp_path / "scan-01.csv"
    p.write_text(text)
    return p


def test_ap_section_fields(tmp_path):
    nets, clients = be.parse_airodump_csv(_write(tmp_path, FULL_CSV))
    by = {n.bssid: n for n in nets}
    assert set(by) == {
        "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02",
        "AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04",
    }
    n1 = by["AA:BB:CC:DD:EE:01"]
    assert n1.channel == "6"
    assert n1.privacy == "WPA2"
    assert n1.cipher == "CCMP"
    assert n1.auth == "PSK"
    assert n1.power == -45
    assert n1.essid == "HomeNet"


def test_hidden_essid_becomes_placeholder(tmp_path):
    nets, _ = be.parse_airodump_csv(_write(tmp_path, FULL_CSV))
    by = {n.bssid: n for n in nets}
    hidden = by["AA:BB:CC:DD:EE:02"]
    assert hidden.essid == "<hidden>"
    assert hidden.hidden is True


def test_non_numeric_power_defaults_to_minus_100(tmp_path):
    nets, _ = be.parse_airodump_csv(_write(tmp_path, FULL_CSV))
    by = {n.bssid: n for n in nets}
    assert by["AA:BB:CC:DD:EE:04"].power == -100


def test_station_section_keyed_by_bssid(tmp_path):
    _, clients = be.parse_airodump_csv(_write(tmp_path, FULL_CSV))
    assert set(clients) == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:03"}
    macs = {c.mac for c in clients["AA:BB:CC:DD:EE:01"]}
    assert macs == {"11:22:33:44:55:66", "11:22:33:44:55:77"}
    probed = {c.probed for c in clients["AA:BB:CC:DD:EE:01"]}
    assert "SomeProbe" in probed


def test_client_counts_populated_on_networks(tmp_path):
    nets, _ = be.parse_airodump_csv(_write(tmp_path, FULL_CSV))
    by = {n.bssid: n for n in nets}
    assert by["AA:BB:CC:DD:EE:01"].clients == 2
    assert by["AA:BB:CC:DD:EE:03"].clients == 1
    assert by["AA:BB:CC:DD:EE:02"].clients == 0


def test_malformed_and_short_rows_do_not_crash(tmp_path):
    text = f"""{AP_HEADER}

AA:BB:CC:DD:EE:10, 2024-01-01, 2024-01-01, 6
not-a-mac-line-garbage,,,,
AA:BB:CC:DD:EE:11, 2024-01-01 10:00:00, 2024-01-01 10:05:00,  1,  54, WPA2, CCMP, PSK, -55,  10,  0, 0.0.0.0, 5, GoodNet,

{STA_HEADER}

short, row
"""
    nets, clients = be.parse_airodump_csv(_write(tmp_path, text))
    by = {n.bssid: n for n in nets}
    # La fila corta se parsea sin reventar (power cae a -100 por IndexError).
    assert by["AA:BB:CC:DD:EE:10"].power == -100
    assert by["AA:BB:CC:DD:EE:10"].channel == "6"
    assert by["AA:BB:CC:DD:EE:11"].essid == "GoodNet"


def test_missing_file_returns_empty(tmp_path):
    nets, clients = be.parse_airodump_csv(tmp_path / "nope.csv")
    assert nets == []
    assert clients == {}


def test_returns_tuple_list_and_dict(tmp_path):
    result = be.parse_airodump_csv(_write(tmp_path, FULL_CSV))
    assert isinstance(result, tuple) and len(result) == 2
    nets, clients = result
    assert isinstance(nets, list)
    assert isinstance(clients, dict)
    assert all(isinstance(n, be.Network) for n in nets)
