"""Tests E2E de la TUI con el Pilot de Textual (asyncio_mode=auto).

Todo el hardware/root/subprocess del backend se mockea para que la app arranque
en modo demo y poblemos la tabla con redes falsas deterministas.
"""

from __future__ import annotations

import pytest

from csh_tui import backend as be
from csh_tui.app import CSHApp, InterfaceScreen, ScannerScreen

FAKE_IFACES = [
    {"iface": "wlan0", "type": "managed", "phy": "phy#0", "bus": "pci",
     "mac": "aa:bb:cc:dd:ee:00", "channel": "6", "external": False},
]

FAKE_DRIVERLESS = [
    {"chip": "MT7612U", "usb_id": "0e8d:7612", "product": "USB WiFi",
     "manufacturer": "MediaTek", "module": "mt76x2u",
     "driver_loaded": False, "iface": ""},
]


def _fake_networks():
    return [
        be.Network(bssid="AA:AA:AA:AA:AA:01", channel="6", power=-40,
                   privacy="WPA2", cipher="CCMP", auth="PSK", essid="LabAP"),
        be.Network(bssid="BB:BB:BB:BB:BB:02", channel="11", power=-65,
                   privacy="WPA3", cipher="CCMP", auth="SAE", essid="Secure3"),
        be.Network(bssid="CC:CC:CC:CC:CC:03", channel="1", power=-70,
                   privacy="OPN", cipher="", auth="", essid="OpenCafe"),
    ]


@pytest.fixture
def tui_env(monkeypatch):
    """Backend inocuo: sin root, sin subprocess, interfaces/adaptadores falsos."""
    monkeypatch.setattr(be, "is_root", lambda: False)
    monkeypatch.setattr(be, "list_interfaces", lambda external_only=False: list(FAKE_IFACES))
    monkeypatch.setattr(be, "list_usb_wifi_adapters",
                        lambda include_bound=False: list(FAKE_DRIVERLESS))
    monkeypatch.setattr(be, "iface_type", lambda iface: "managed")
    monkeypatch.setattr(be, "iface_channel", lambda iface: "6")
    monkeypatch.setattr(be, "iface_mac", lambda iface: "aa:bb:cc:dd:ee:00")
    monkeypatch.setattr(be, "capabilities", lambda: {
        k: False for k in ("airodump-ng", "aireplay-ng", "aircrack-ng",
                            "tshark", "hcxpcapngtool", "hashcat", "crunch")})
    monkeypatch.setattr(be, "artifacts",
                        lambda: {"captures": [], "reports": [], "hashes": []})
    monkeypatch.setattr(be.subprocess, "run",
                        lambda *a, **k: type("P", (), {"stdout": "", "returncode": 0})())

    # Scanner demo determinista.
    def _start_demo(self):
        self.demo = True
        self.demo_csv = None

    monkeypatch.setattr(be.Scanner, "start_demo", _start_demo)
    monkeypatch.setattr(be.Scanner, "poll", lambda self: (_fake_networks(), {}))
    return monkeypatch


async def _goto_scanner(pilot):
    """Lleva la app desde el selector hasta ScannerScreen con wlan0."""
    screen = pilot.app.screen
    assert isinstance(screen, InterfaceScreen)
    screen._choose("wlan0")
    await pilot.pause()
    assert isinstance(pilot.app.screen, ScannerScreen)
    return pilot.app.screen


# ─── arranque / selector de interfaz ──────────────────────────────────────────

async def test_boots_to_interface_screen(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, InterfaceScreen)
        table = app.screen.query_one("#ifaces")
        # Debe estar la fila de la antena sin driver (key __nodrv__...).
        keys = [str(k.value) for k in table.rows]
        assert any(k.startswith("__nodrv__") for k in keys)
        # Y la interfaz managed real.
        assert any(k == "wlan0" for k in keys)


async def test_driverless_selection_warns_and_does_not_navigate(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        notes = []
        monkeypatch_notify(app, notes)
        screen._choose("__nodrv__0e8d:7612")
        await pilot.pause()
        # No navega a ScannerScreen.
        assert isinstance(app.screen, InterfaceScreen)
        # Avisa con un notify de severidad warning.
        assert notes and notes[-1]["severity"] == "warning"


async def test_select_real_interface_pushes_scanner(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await _goto_scanner(pilot)
        assert app.interface == "wlan0"


# ─── ScannerScreen: escaneo y filtros ─────────────────────────────────────────

async def test_scan_toggle_on_off(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = await _goto_scanner(pilot)
        assert screen.scanning is False
        await pilot.press("s")
        await pilot.pause()
        assert screen.scanning is True
        await pilot.press("s")
        await pilot.pause()
        assert screen.scanning is False


async def test_scanning_populates_table(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = await _goto_scanner(pilot)
        await pilot.press("s")
        # Deja correr el worker de poll y el call_from_thread.
        for _ in range(5):
            await pilot.pause()
        assert len(screen.networks) == 3
        table = screen.query_one("#nets")
        assert table.row_count == 3


async def test_cycle_encryption_filter(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = await _goto_scanner(pilot)
        assert screen.enc_idx == 0
        await pilot.press("e")
        await pilot.pause()
        assert screen.enc_idx == 1
        assert screen.ENC_FILTERS[screen.enc_idx] == "WPA2"


async def test_toggle_only_clients(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = await _goto_scanner(pilot)
        assert screen.only_clients is False
        await pilot.press("c")
        await pilot.pause()
        assert screen.only_clients is True


# ─── Regresión Bug 2: la tabla no se reconstruye si nada cambió ───────────────

async def test_apply_scan_stable_cursor_bug2(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = await _goto_scanner(pilot)
        screen.scanning = True
        nets = _fake_networks()
        screen._apply_scan(nets)
        await pilot.pause()
        table = screen.query_one("#nets")
        assert table.row_count == 3

        # Orden estable registrado tras el primer render.
        order1 = list(screen._row_order)
        assert len(order1) == 3

        # El usuario mueve el cursor a otra fila.
        table.move_cursor(row=2)
        await pilot.pause()
        moved_to = table.cursor_row
        bssid_before = screen.selected_bssid

        # Un refresh de poll con LOS MISMOS datos no debe reconstruir la tabla
        # (no llama a clear) ni mover el cursor / la selección.
        calls = {"n": 0}
        orig_clear = table.clear
        table.clear = lambda *a, **k: (calls.__setitem__("n", calls["n"] + 1),
                                       orig_clear(*a, **k))[1]
        screen._apply_scan(_fake_networks())
        await pilot.pause()
        assert calls["n"] == 0
        assert screen._row_order == order1
        assert table.cursor_row == moved_to
        assert screen.selected_bssid == bssid_before


# ─── Regresión Bug 1: flechas seleccionan, Enter abre, el clic no hace nada ───

async def test_arrows_select_enter_opens_bug1(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = await _goto_scanner(pilot)
        screen.scanning = True
        screen._apply_scan(_fake_networks())
        await pilot.pause()
        table = screen.query_one("#nets")
        table.focus()
        await pilot.pause()

        # Las flechas mueven la barra de selección y actualizan selected_bssid.
        await pilot.press("down")
        await pilot.pause()
        assert table.cursor_row == 1
        bssid_row1 = [r.key.value for r in table.ordered_rows][1]
        assert screen.selected_bssid == bssid_row1

        opened = {"n": 0}
        screen.action_open_target = lambda: opened.__setitem__("n", opened["n"] + 1)

        # Enter SÍ abre el objetivo de la fila resaltada.
        await pilot.press("enter")
        await pilot.pause()
        assert opened["n"] == 1


async def test_click_does_not_move_cursor_or_open_bug1(tui_env):
    """Un clic del touchpad no mueve el cursor ni abre el objetivo."""
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = await _goto_scanner(pilot)
        screen.scanning = True
        screen._apply_scan(_fake_networks())
        await pilot.pause()
        table = screen.query_one("#nets")
        table.focus()
        table.move_cursor(row=0)
        await pilot.pause()

        opened = {"n": 0}
        screen.action_open_target = lambda: opened.__setitem__("n", opened["n"] + 1)

        # Clic sobre la tabla (cae en una fila distinta a la resaltada): el
        # handler _on_click está neutralizado, así que ni mueve ni abre.
        await pilot.click("#nets", offset=(10, 4))
        await pilot.pause()
        assert table.cursor_row == 0
        assert opened["n"] == 0


async def test_render_table_skips_rebuild_on_same_signature(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = await _goto_scanner(pilot)
        screen.scanning = True
        screen.networks = _fake_networks()
        screen._render_table()
        table = screen.query_one("#nets")

        calls = {"n": 0}
        orig_clear = table.clear

        def _counting_clear(*a, **k):
            calls["n"] += 1
            return orig_clear(*a, **k)

        table.clear = _counting_clear
        # Segundo render con datos idénticos: no debe limpiar la tabla.
        screen._render_table()
        assert calls["n"] == 0
        # Cambiar los datos sí debe reconstruir.
        screen.networks = _fake_networks()[:1]
        screen._render_table()
        assert calls["n"] == 1


# ─── Regresión de salida: quit hace teardown y cierra sin colgarse ────────────

async def test_quit_tears_down_and_exits(tui_env):
    stop_flag = {"stopped": False}

    def _stop(self):
        stop_flag["stopped"] = True

    tui_env.setattr(be.Scanner, "stop", _stop)

    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = await _goto_scanner(pilot)
        await pilot.press("s")  # arranca el scanner (crea el objeto Scanner)
        await pilot.pause()
        assert screen.scanner is not None

        screen.action_quit()
        await pilot.pause()
        assert stop_flag["stopped"] is True
        assert screen.scanning is False
        assert screen.scan_timer is None
        assert app.is_running is False


async def test_q_key_exits_app(tui_env):
    app = CSHApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await _goto_scanner(pilot)
        await pilot.press("q")
        await pilot.pause()
        assert app.is_running is False


def monkeypatch_notify(app, sink):
    """Captura las llamadas a app.notify en una lista."""

    def _notify(message, *, title="", severity="information", timeout=None, **kw):
        sink.append({"message": message, "title": title, "severity": severity})

    app.notify = _notify
