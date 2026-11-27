"""
CSH WPA-2 Framework — consola visual (Textual).

Estilo inspirado en wifit3 (panel de filtros, tabla con señal/cifrado en color,
log con viñetas y footer de atajos), hecho propio para el flujo aircrack-ng de
este repositorio.

Uso exclusivo en laboratorio propio o con autorización explícita.
"""

from __future__ import annotations

import time
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, DataTable, Input, Label, RichLog, Static,
)

from . import backend as be

APP_TITLE = "CSH WPA-2 FRAMEWORK"
APP_VER = "v2.0"

# Paleta de marca (teal + ámbar sobre negro)
C_TEAL, C_TEALHI, C_CYAN = "#2dd4bf", "#5eead4", "#38bdf8"
C_AMBER, C_GREEN, C_RED = "#f5a623", "#4ade80", "#f43f5e"
C_VIOLET, C_DIM, C_INK = "#c084fc", "#58646d", "#d6e2e4"

ENC_COLORS = {
    "WPA3": C_VIOLET, "WPA2": C_GREEN, "WPA": C_AMBER,
    "WEP": C_RED, "OPN": C_CYAN, "?": C_DIM,
}


def status_glyph(net: be.Network) -> Text:
    """Marcador de estado propio en la primera columna."""
    if net.is_enterprise:
        return Text("⬢", style=C_AMBER)       # enterprise: fuera del flujo PSK
    if net.encryption == "WPA3":
        return Text("◇", style=C_VIOLET)       # SAE: no aircrack clásico
    if net.crackable:
        return Text("◆", style=C_TEAL)         # objetivo válido de laboratorio
    if net.encryption == "WEP":
        return Text("◆", style=C_RED)
    return Text("·", style=C_DIM)


def enc_text(net: be.Network) -> Text:
    enc = net.encryption
    color = ENC_COLORS.get(enc, C_DIM)
    suffix = ""
    if net.is_enterprise:
        suffix, color = "·EAP", C_AMBER
    elif enc in ("WPA", "WPA2"):
        suffix = "·PSK"
    t = Text(enc, style=f"bold {color}")
    if suffix:
        t.append(suffix, style=C_DIM)
    return t


def power_text(power: int) -> Text:
    """Medidor propio de 5 segmentos ▰▱ con rampa verde→ámbar→rojo."""
    if power <= -100:
        return Text("▱▱▱▱▱  ---", style=C_DIM)
    if power >= -52:
        lvl, color = 5, C_GREEN
    elif power >= -62:
        lvl, color = 4, C_GREEN
    elif power >= -70:
        lvl, color = 3, C_AMBER
    elif power >= -78:
        lvl, color = 2, C_AMBER
    elif power >= -86:
        lvl, color = 1, C_RED
    else:
        lvl, color = 0, C_RED
    bar = "".join("▰" if i < lvl else "▱" for i in range(5))
    t = Text(bar, style=color)
    t.append(f"  {power}", style=C_INK)
    return t


def ssid_text(net: be.Network) -> Text:
    if net.hidden:
        return Text("‹oculta›", style=f"italic {C_DIM}")
    return Text(net.essid, style=f"bold {C_INK}")


# ─────────────────────────────────────────────────────────────────────────────
#  Modal de confirmación de autorización (gating ético)
# ─────────────────────────────────────────────────────────────────────────────
class ConfirmScreen(ModalScreen[bool]):
    def __init__(self, action: str):
        super().__init__()
        self.action = action

    def compose(self) -> ComposeResult:
        with Container(id="dialog", classes="modal-wrap hazard"):
            yield Static("CONFIRMACIÓN DE AUTORIZACIÓN", classes="heading")
            yield Static(
                f"La acción «{self.action}» envía tramas y puede interrumpir "
                "clientes WiFi.\nContinúa SOLO en tu red, tu laboratorio o con "
                "permiso explícito.",
                classes="warn",
            )
            yield Static("Escribe AUTORIZADO para continuar:", classes="hint")
            yield Input(placeholder="AUTORIZADO", id="auth")
            with Horizontal():
                yield Button("Confirmar", variant="primary", id="ok")
                yield Button("Cancelar", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#dialog", Container).border_title = "⚠ autorización"
        self.query_one("#auth", Input).focus()

    @on(Button.Pressed, "#ok")
    @on(Input.Submitted, "#auth")
    def _confirm(self) -> None:
        val = self.query_one("#auth", Input).value.strip()
        self.dismiss(val == "AUTORIZADO")

    @on(Button.Pressed, "#cancel")
    def _cancel(self) -> None:
        self.dismiss(False)


# ─────────────────────────────────────────────────────────────────────────────
#  Pantalla de objetivo: acciones sobre un AP
# ─────────────────────────────────────────────────────────────────────────────
class TargetScreen(ModalScreen):
    BINDINGS = [("escape", "app.pop_screen", "Volver")]

    def __init__(self, net: be.Network, interface: str, demo: bool):
        super().__init__()
        self.net = net
        self.interface = interface
        self.demo = demo
        self.session: be.CaptureSession | None = None
        self._cap_timer = None
        self._crack_proc = None  # subprocess.Popen del aircrack en curso

    def compose(self) -> ComposeResult:
        with Container(id="dialog", classes="modal-wrap"):
            yield Static("", id="apinfo")
            with Horizontal():
                yield Button("Captura pasiva", id="passive", variant="primary")
                yield Button("Captura + deauth", id="deauth")
                yield Button("Detener", id="stopcap", disabled=True)
            with Horizontal():
                yield Button("Verificar handshake", id="verify")
                yield Button("Crack diccionario", id="crack")
                yield Button("→ hashcat 22000", id="hc")
            yield RichLog(id="actionlog", highlight=False, markup=True, wrap=True)
            yield Button("Cerrar", id="close", classes="-danger")

    def on_mount(self) -> None:
        d = self.query_one("#dialog", Container)
        d.border_title = f"🎯 {self.net.essid}"
        info = Text()
        info.append(f"{self.net.essid}\n", style="bold #e8e8f0")
        info.append(f"BSSID  {self.net.bssid}    ", style="#c8c8d4")
        info.append(f"CH {self.net.channel}    ", style="#c8c8d4")
        info.append(f"{be.channel_to_freq(self.net.channel)}\n", style="#8a8aa0")
        info.append("Cifrado  ")
        info.append_text(enc_text(self.net))
        info.append(f"    Clientes {self.net.clients}    ")
        info.append_text(power_text(self.net.power))
        self.query_one("#apinfo", Static).update(info)
        log = self.query_one("#actionlog", RichLog)
        if not self.net.crackable:
            log.write("[#ffb454]! Esta red no es WPA/WPA2-PSK: el flujo clásico puede no aplicar.[/]")
        if self.demo:
            log.write("[#ffb454]! Modo demo (sin root/monitor): las acciones están deshabilitadas.[/]")

    def _log(self, msg: str) -> None:
        self.query_one("#actionlog", RichLog).write(msg)

    def _guard(self) -> bool:
        if self.demo:
            self._log("[#ff6e6e]✗ No disponible en modo demo.[/]")
            return False
        return True

    # ── captura ──
    @on(Button.Pressed, "#passive")
    def _passive(self) -> None:
        if self._guard():
            self._begin_capture(deauth=False)

    @on(Button.Pressed, "#deauth")
    def _deauth(self) -> None:
        if not self._guard():
            return
        def after(ok: bool):
            if ok:
                self._begin_capture(deauth=True)
            else:
                self._log("[#ffb454]! Autorización cancelada.[/]")
        self.app.push_screen(ConfirmScreen("captura + deauth"), after)

    def _begin_capture(self, deauth: bool) -> None:
        self._set_running(True)
        self.session = be.CaptureSession(self.interface, self.net)
        self._log(f"[#9a8cff]▶ Captura iniciada[/] → {Path(self.session.cap).name}")
        self.session.start()
        if deauth:
            self.app.call_later(self._send_deauth)
        self._cap_timer = self.set_interval(2.0, self._watch_capture)

    def _send_deauth(self) -> None:
        if self.session:
            self.session.deauth(count=8)
            self._log("[#ffb454]↯ Deauth x8 enviado al AP[/]")

    def _watch_capture(self) -> None:
        if not self.session:
            return
        self._log(f"[#6f6f85]· {self.session.elapsed}s — escuchando…[/]")
        if self.session.captured():
            self._finish_capture(True)
        elif self.session.elapsed >= 300:
            self._finish_capture(False)

    @on(Button.Pressed, "#stopcap")
    def _stop(self) -> None:
        self._finish_capture(self.session.captured() if self.session else False)

    def _finish_capture(self, ok: bool) -> None:
        if self._cap_timer:
            self._cap_timer.stop()
            self._cap_timer = None
        if not self.session:
            return
        cap = self.session.finalize()
        self.session.stop()
        if ok:
            self._log(f"[#6ee787]✓ Handshake capturado[/] para {self.net.essid}")
            be.write_reports(self.net, "Capturado", cap or "",
                             self.session.filtered if Path(self.session.filtered).exists() else "")
            self._log("[#9a8cff]↳ Reportes .txt y .md generados en reports/[/]")
        else:
            self._log("[#ff6e6e]✗ Sin handshake[/] (asegura clientes conectados / amplía tiempo).")
        self.session = None
        self._set_running(False)

    def _set_running(self, running: bool) -> None:
        for bid in ("passive", "deauth", "verify", "crack", "hc"):
            self.query_one(f"#{bid}", Button).disabled = running
        self.query_one("#stopcap", Button).disabled = not running

    # ── verificar / crack ──
    @on(Button.Pressed, "#verify")
    def _verify(self) -> None:
        if self._guard():
            self._run_verify()

    @work(thread=True)
    def _run_verify(self) -> None:
        caps = sorted(be.CAPTURE_DIR.glob("*.cap"), key=lambda p: p.stat().st_mtime, reverse=True)
        cap = next((str(c) for c in caps if self.net.bssid.replace(":", "") in c.name), None)
        if not cap and caps:
            cap = str(caps[0])
        if not cap:
            self.app.call_from_thread(self._log, "[#ff6e6e]✗ No hay .cap para verificar.[/]")
            return
        self.app.call_from_thread(self._log, f"[#9a8cff]▶ Verificando[/] {Path(cap).name}")
        ok = be.has_handshake(cap, self.net.bssid)
        self.app.call_from_thread(
            self._log,
            "[#6ee787]✓ Handshake válido.[/]" if ok else "[#ff6e6e]✗ Sin handshake en ese CAP.[/]",
        )

    @on(Button.Pressed, "#crack")
    def _crack(self) -> None:
        if not self._guard():
            return
        def after(path):
            if path:
                self._run_crack(str(path))
        self.app.push_screen(WordlistScreen(pick=True), after)

    @work(thread=True)
    def _run_crack(self, wordlist: str) -> None:
        caps = sorted(be.CAPTURE_DIR.glob("*.cap"), key=lambda p: p.stat().st_mtime, reverse=True)
        cap = next((str(c) for c in caps if self.net.bssid.replace(":", "") in c.name),
                   str(caps[0]) if caps else None)
        if not cap:
            self.app.call_from_thread(self._log, "[#ff6e6e]✗ No hay .cap para crackear.[/]")
            return
        self.app.call_from_thread(self._log, f"[#9a8cff]▶ aircrack-ng[/] con {Path(wordlist).name}")
        import subprocess
        proc = subprocess.Popen(
            ["aircrack-ng", "-a2", "-b", self.net.bssid, "-w", wordlist, cap],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self._crack_proc = proc
        key = None
        try:
            for line in proc.stdout:  # type: ignore
                if "KEY FOUND" in line:
                    key = line.strip()
                    break
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
            self._crack_proc = None
        if key:
            self.app.call_from_thread(self._log, f"[#6ee787]✓ {key}[/]")
        else:
            self.app.call_from_thread(self._log, "[#ffb454]! Clave no encontrada o cancelada.[/]")

    @on(Button.Pressed, "#hc")
    def _hashcat(self) -> None:
        if not self._guard():
            return
        if not be.have("hcxpcapngtool"):
            self._log("[#ff6e6e]✗ hcxpcapngtool no instalado (sudo dnf install hcxtools).[/]")
            return
        self._run_convert()

    @work(thread=True)
    def _run_convert(self) -> None:
        caps = sorted(be.CAPTURE_DIR.glob("*.cap"), key=lambda p: p.stat().st_mtime, reverse=True)
        cap = next((str(c) for c in caps if self.net.bssid.replace(":", "") in c.name),
                   str(caps[0]) if caps else None)
        if not cap:
            self.app.call_from_thread(self._log, "[#ff6e6e]✗ No hay .cap para convertir.[/]")
            return
        out = str(be.HASH_DIR / (Path(cap).stem + ".22000"))
        ok = be.convert_22000(cap, out)
        if ok:
            self.app.call_from_thread(self._log, f"[#6ee787]✓ Hash 22000:[/] {out}")
            if be.have("hashcat"):
                self.app.call_from_thread(self._log, f"[#9a8cff]↳ hashcat -m 22000 -a 0 {Path(out).name} <dicc>[/]")
        else:
            self.app.call_from_thread(self._log, "[#ff6e6e]✗ Sin hash (¿la captura tiene handshake/PMKID?).[/]")

    @on(Button.Pressed, "#close")
    def _close(self) -> None:
        self._teardown()
        self.app.pop_screen()

    def _teardown(self) -> None:
        """Detiene captura, crack y workers para no dejar procesos huérfanos."""
        if self.session:
            self.session.stop()
            self.session = None
        if self._cap_timer:
            self._cap_timer.stop()
            self._cap_timer = None
        proc = self._crack_proc
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        self._crack_proc = None
        try:
            self.workers.cancel_all()
        except Exception:
            pass

    def on_unmount(self) -> None:
        # Red de seguridad: si la pantalla se desmonta por cualquier vía (p.ej. salir
        # de la app), no dejar aircrack/airodump corriendo.
        self._teardown()


# ─────────────────────────────────────────────────────────────────────────────
#  Diccionarios
# ─────────────────────────────────────────────────────────────────────────────
class WordlistScreen(ModalScreen):
    BINDINGS = [("escape", "app.pop_screen", "Volver")]

    def __init__(self, pick: bool = False):
        super().__init__()
        self.pick = pick
        self.rows: list[Path] = []

    def compose(self) -> ComposeResult:
        with Container(id="dialog", classes="modal-wrap"):
            yield Static("Selecciona un diccionario para el ataque."
                         if self.pick else "Diccionarios disponibles.", classes="hint")
            t = DataTable(id="wl", cursor_type="row", zebra_stripes=True)
            yield t
            with Horizontal():
                if self.pick:
                    yield Button("Usar este", id="use", variant="primary")
                yield Button("Importar rockyou", id="rockyou")
                yield Button("Cerrar", id="close", classes="-danger")

    def on_mount(self) -> None:
        self.query_one("#dialog", Container).border_title = "📚 diccionarios"
        t = self.query_one("#wl", DataTable)
        t.add_columns("Líneas", "Ruta")
        self._reload()

    def _reload(self) -> None:
        t = self.query_one("#wl", DataTable)
        t.clear()
        self.rows = be.discover_wordlists()
        if not self.rows:
            t.add_row("—", "No hay diccionarios. Importa rockyou o pon .txt en wordlists/")
        for p in self.rows:
            t.add_row(be.wordlist_lines(p), str(p))

    @on(Button.Pressed, "#use")
    def _use(self) -> None:
        t = self.query_one("#wl", DataTable)
        if self.rows and t.cursor_row < len(self.rows):
            self.dismiss(self.rows[t.cursor_row])

    @on(Button.Pressed, "#rockyou")
    def _rockyou(self) -> None:
        for src in ("/usr/share/wordlists/rockyou.txt", "/usr/share/wordlists/rockyou.txt.gz"):
            p = Path(src)
            if p.exists():
                dest = be.WORDLIST_DIR / "rockyou.txt"
                try:
                    if p.suffix == ".gz":
                        import gzip
                        dest.write_bytes(gzip.decompress(p.read_bytes()))
                    else:
                        dest.write_bytes(p.read_bytes())
                    self.app.bell()
                except Exception:
                    pass
                self._reload()
                return
        self.notify("rockyou no encontrado en el sistema", severity="warning")

    @on(Button.Pressed, "#close")
    def _close(self) -> None:
        self.dismiss(None) if self.pick else self.app.pop_screen()


# ─────────────────────────────────────────────────────────────────────────────
#  Vault: capturas, reportes y hashes
# ─────────────────────────────────────────────────────────────────────────────
class VaultScreen(ModalScreen):
    BINDINGS = [("escape", "app.pop_screen", "Volver")]

    def compose(self) -> ComposeResult:
        with Container(id="dialog", classes="modal-wrap"):
            yield Static("Artefactos de la sesión y anteriores.", classes="hint")
            yield DataTable(id="vault", cursor_type="row", zebra_stripes=True)
            yield Button("Cerrar", id="close", classes="-danger")

    def on_mount(self) -> None:
        self.query_one("#dialog", Container).border_title = "🗄 vault"
        t = self.query_one("#vault", DataTable)
        t.add_columns("Tipo", "Fecha", "Archivo")
        art = be.artifacts()
        labels = {"captures": ("CAP", "#6ee787"), "reports": ("REPORTE", "#9a8cff"),
                  "hashes": ("22000", "#d26bff")}
        empty = True
        for kind, items in art.items():
            label, color = labels[kind]
            for p in items[:30]:
                empty = False
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))
                t.add_row(Text(label, style=color), ts, p.name)
        if empty:
            t.add_row("—", "—", "Aún no hay artefactos. Captura un handshake primero.")

    @on(Button.Pressed, "#close")
    def _close(self) -> None:
        self.app.pop_screen()


# ─────────────────────────────────────────────────────────────────────────────
#  Pantalla principal: scanner
# ─────────────────────────────────────────────────────────────────────────────
class ScannerScreen(Screen):
    BINDINGS = [
        ("s", "toggle_scan", "Escanear"),
        ("enter", "open_target", "Objetivo"),
        ("e", "cycle_enc", "Cifrado"),
        ("c", "toggle_clients", "Clientes"),
        ("slash", "focus_filter", "Buscar"),
        ("escape", "defocus_filter", "Salir del filtro"),
        ("d", "dicts", "Diccionarios"),
        ("v", "vault", "Vault"),
        ("m", "monitor", "Monitor"),
        ("r", "restore", "Restaurar"),
        ("q", "app.quit", "Salir"),
    ]

    ENC_FILTERS = ["TODAS", "WPA2", "WPA", "WPA3", "WEP", "OPN"]

    def __init__(self):
        super().__init__()
        self.scanner: be.Scanner | None = None
        self.scanning = False
        self.networks: list[be.Network] = []
        self.enc_idx = 0
        self.only_clients = False
        self.ssid_filter = ""
        self.scan_timer = None
        self.selected_bssid: str | None = None
        self._resume_scan = False

    def compose(self) -> ComposeResult:
        yield Static(id="brandband")
        with Horizontal(id="body"):
            with Vertical(id="rail"):
                yield Static("", id="op", classes="card accent")
                yield Static("", id="sesion", classes="card")
                yield Static("", id="arsenal", classes="card")
                yield Static("", id="leyenda", classes="card")
            with Vertical(id="main"):
                with Container(id="filterbar"):
                    with Horizontal():
                        yield Label("BUSCAR")
                        yield Input(placeholder="nombre de red…", id="ssid")
                yield DataTable(id="nets", cursor_type="row", zebra_stripes=False)
                yield RichLog(id="log", markup=True, highlight=False, wrap=True)
        yield Static("", id="cmdbar")

    def on_mount(self) -> None:
        # Banda de marca
        self.query_one("#brandband", Static).update(Text.from_markup(
            f"[reverse b {C_TEAL}] CSH [/]  [b {C_INK}]WPA-2 AUDIT CONSOLE[/]  "
            f"[{C_DIM}]· auditoría WPA/WPA2 en laboratorio autorizado ·[/]  [{C_TEAL}]{APP_VER}[/]"
        ))
        # Títulos de tarjetas / paneles
        self.query_one("#op", Static).border_title = "OPERADOR"
        self.query_one("#sesion", Static).border_title = "SESIÓN"
        self.query_one("#arsenal", Static).border_title = "ARSENAL"
        self.query_one("#leyenda", Static).border_title = "LEYENDA"
        self.query_one("#filterbar", Container).border_title = "FILTROS"
        self.query_one("#log", RichLog).border_title = "ACTIVIDAD"
        self.query_one("#nets", DataTable).add_columns(" ", "RED", "BSSID", "CH", "SEÑAL", "CL", "SEGURIDAD")
        # Barra de comandos
        self._build_cmdbar()
        self._refresh_chrome()

        log = self.query_one("#log", RichLog)
        if not be.is_root():
            log.write(f"[{C_AMBER}]▸[/] Sin root: pulsa [b]s[/] para ver la consola en "
                      f"[b]modo demo[/]. Ejecuta con sudo para escanear en vivo.")
        else:
            log.write(f"[{C_TEAL}]▸[/] Pulsa [b]s[/] para escanear · [b]m[/] activa modo monitor.")

        # Foco en la tabla (no en el filtro): así las teclas de comando — incluida q — funcionan.
        self.query_one("#nets", DataTable).focus()

    def _build_cmdbar(self) -> None:
        keys = [("s", "escanear"), ("↵", "objetivo"), ("e", "cifrado"), ("c", "clientes"),
                ("/", "buscar"), ("d", "dicc"), ("v", "vault"), ("m", "monitor"),
                ("r", "restaurar"), ("q", "salir")]
        parts = "  ".join(f"[{C_AMBER} b]{k}[/][{C_DIM}] {lbl}[/]" for k, lbl in keys)
        self.query_one("#cmdbar", Static).update(Text.from_markup(parts))

    # ── chrome: rail + títulos dinámicos ──
    def _refresh_chrome(self) -> None:
        app: "CSHApp" = self.app  # type: ignore
        iface = app.interface or "—"
        typ = be.iface_type(iface) if app.interface else "—"
        ch = be.iface_channel(iface) if app.interface else "—"

        mode_color = C_GREEN if typ == "monitor" else (C_AMBER if typ != "—" else C_DIM)
        op = Text()
        op.append("● ", style=mode_color)
        op.append(f"{typ}\n", style=f"b {mode_color}")
        op.append("iface  ", style=C_DIM); op.append(f"{iface}\n", style=C_INK)
        op.append("canal  ", style=C_DIM); op.append(f"{ch}", style=C_INK)
        op.append(f"  ·  {be.channel_to_freq(ch)}\n" if ch not in ("—", "N/A") else "\n", style=C_DIM)
        op.append("mac    ", style=C_DIM); op.append(be.iface_mac(iface) if app.interface else "—", style=C_INK)
        self.query_one("#op", Static).update(op)

        vis = self._visible()
        objetivos = sum(1 for n in self.networks if n.crackable)
        clientes = sum(n.clients for n in self.networks)
        art = be.artifacts()
        state = (f"[{C_GREEN}]● escaneando[/]" if self.scanning else f"[{C_DIM}]○ en espera[/]")
        demo = f"  [{C_AMBER}]demo[/]" if (self.scanning and not be.is_root()) else ""
        self.query_one("#sesion", Static).update(Text.from_markup(
            f"{state}{demo}\n"
            f"[{C_DIM}]redes     [/][{C_INK} b]{len(self.networks)}[/]"
            f"   [{C_DIM}]visibles [/][{C_INK}]{len(vis)}[/]\n"
            f"[{C_DIM}]objetivos [/][{C_TEAL} b]{objetivos}[/]"
            f"   [{C_DIM}]clientes [/][{C_CYAN}]{clientes}[/]\n"
            f"[{C_DIM}]capturas  [/][{C_INK}]{len(art['captures'])}[/]"
            f"   [{C_DIM}]hashes   [/][{C_VIOLET}]{len(art['hashes'])}[/]"
        ))

        caps = be.capabilities()
        def dot(k):
            return f"[{C_GREEN}]●[/] {k}" if caps.get(k) else f"[{C_DIM}]○ {k}[/]"
        self.query_one("#arsenal", Static).update(Text.from_markup(
            f"{dot('airodump-ng')}   {dot('aireplay-ng')}\n"
            f"{dot('aircrack-ng')}   {dot('tshark')}\n"
            f"{dot('hashcat')}    {dot('hcxpcapngtool')}\n"
            f"{dot('crunch')}"
        ))

        self.query_one("#leyenda", Static).update(Text.from_markup(
            f"[{C_TEAL}]◆[/] WPA2/WPA  [{C_DIM}]objetivo PSK[/]\n"
            f"[{C_VIOLET}]◇[/] WPA3      [{C_DIM}]SAE, no aircrack[/]\n"
            f"[{C_AMBER}]⬢[/] EAP       [{C_DIM}]enterprise[/]\n"
            f"[{C_RED}]◆[/] WEP       [{C_DIM}]legado[/]"
        ))

        enc = self.ENC_FILTERS[self.enc_idx]
        cl = "sí" if self.only_clients else "no"
        self.query_one("#filterbar", Container).border_title = \
            f"FILTROS · cifrado {enc} · con clientes {cl}"
        scan_lbl = "escaneando" if self.scanning else "detenido"
        self.query_one("#nets", DataTable).border_title = f"RADAR · {scan_lbl} · {len(vis)} redes"

    # ── escaneo ──
    def action_toggle_scan(self) -> None:
        if self.scanning:
            self._stop_scan()
        else:
            self._start_scan()

    def _start_scan(self) -> None:
        app: "CSHApp" = self.app  # type: ignore
        self.scanner = be.Scanner(app.interface or "")
        log = self.query_one("#log", RichLog)
        if be.is_root() and app.interface and be.iface_type(app.interface) == "monitor":
            self.scanner.start()
            log.write("[#6ee787]●[/] Scanner iniciado (airodump-ng en vivo)")
        elif be.is_root() and app.interface:
            log.write("[#ffb454]![/] La interfaz no está en modo monitor. Pulsa [b]m[/] para activarlo.")
            return
        else:
            self.scanner.start_demo()
            if self.scanner.csv_path:
                log.write(f"[#ffb454]●[/] Modo demo: {self.scanner.csv_path.name}")
            else:
                log.write("[#ff6e6e]✗[/] Sin capturas previas para el modo demo.")
        self.scanning = True
        self.scan_timer = self.set_interval(1.5, self._poll)
        self._poll()
        self._refresh_chrome()

    def _stop_scan(self) -> None:
        self.scanning = False
        if self.scan_timer:
            self.scan_timer.stop()
            self.scan_timer = None
        if self.scanner:
            self.scanner.stop()
        self.query_one("#log", RichLog).write("[#6f6f85]○[/] Scanner detenido")
        self._refresh_chrome()

    def _poll(self) -> None:
        if not self.scanner:
            return
        nets, _ = self.scanner.poll()
        nets.sort(key=lambda n: n.power, reverse=True)
        self.networks = nets
        self._render_table()
        self._refresh_chrome()

    def _visible(self) -> list[be.Network]:
        enc = self.ENC_FILTERS[self.enc_idx]
        out = []
        for n in self.networks:
            if enc != "TODAS" and n.encryption != enc:
                continue
            if self.only_clients and n.clients == 0:
                continue
            if self.ssid_filter and self.ssid_filter.lower() not in n.essid.lower():
                continue
            out.append(n)
        return out

    def _render_table(self) -> None:
        t = self.query_one("#nets", DataTable)
        prev = self.selected_bssid
        t.clear()
        vis = self._visible()
        for n in vis:
            t.add_row(
                status_glyph(n),
                ssid_text(n),
                Text(n.bssid, style="#8a98a0"),
                Text(str(n.channel), style=C_INK),
                power_text(n.power),
                Text(str(n.clients), style=C_CYAN if n.clients else C_DIM),
                enc_text(n),
                key=n.bssid,
            )
        if prev:
            try:
                t.move_cursor(row=t.get_row_index(prev))
            except Exception:
                pass

    # ── interacción ──
    @on(DataTable.RowHighlighted, "#nets")
    def _row_hl(self, ev: DataTable.RowHighlighted) -> None:
        self.selected_bssid = ev.row_key.value if ev.row_key else None

    @on(DataTable.RowSelected, "#nets")
    def _row_selected(self, ev: DataTable.RowSelected) -> None:
        # Enter sobre la tabla abre el objetivo (DataTable consume la tecla Enter).
        if ev.row_key:
            self.selected_bssid = ev.row_key.value
        self.action_open_target()

    def action_defocus_filter(self) -> None:
        self.query_one("#nets", DataTable).focus()

    def _current_net(self) -> be.Network | None:
        if not self.selected_bssid:
            vis = self._visible()
            return vis[0] if vis else None
        return next((n for n in self.networks if n.bssid == self.selected_bssid), None)

    def action_open_target(self) -> None:
        net = self._current_net()
        if not net:
            self.query_one("#log", RichLog).write(f"[{C_AMBER}]▸[/] Selecciona una red primero.")
            return
        # Liberar la radio: un airodump de captura no puede competir con el del scanner
        # (channel-hopping) sobre la misma interfaz monitor. Se reanuda al volver.
        self._resume_scan = self.scanning
        if self.scanning:
            self._stop_scan()
        demo = not be.is_root()
        self.app.push_screen(TargetScreen(net, self.app.interface or "", demo))  # type: ignore

    def on_screen_resume(self) -> None:
        # Al cerrar el objetivo (u otro modal), reanudar el escaneo si estaba activo.
        if getattr(self, "_resume_scan", False) and not self.scanning:
            self._resume_scan = False
            self._start_scan()

    def action_cycle_enc(self) -> None:
        self.enc_idx = (self.enc_idx + 1) % len(self.ENC_FILTERS)
        self._render_table()
        self._refresh_chrome()

    def action_toggle_clients(self) -> None:
        self.only_clients = not self.only_clients
        self._render_table()
        self._refresh_chrome()

    def action_focus_filter(self) -> None:
        self.query_one("#ssid", Input).focus()

    def action_dicts(self) -> None:
        self.app.push_screen(WordlistScreen())

    def action_vault(self) -> None:
        self.app.push_screen(VaultScreen())

    @work(thread=True)
    def action_monitor(self) -> None:
        app: "CSHApp" = self.app  # type: ignore
        if not be.is_root():
            self.app.call_from_thread(
                self.query_one("#log", RichLog).write,
                "[#ff6e6e]✗[/] El modo monitor requiere sudo.")
            return
        if not app.interface:
            return
        self.app.call_from_thread(
            self.query_one("#log", RichLog).write,
            f"[#9a8cff]▶[/] Activando modo monitor en {app.interface}…")
        ok, newif, _ = be.enable_monitor(app.interface)
        app.interface = newif
        msg = (f"[#6ee787]✓[/] Monitor activo en {newif}" if ok
               else f"[#ff6e6e]✗[/] No se pudo activar monitor en {newif}")
        self.app.call_from_thread(self.query_one("#log", RichLog).write, msg)
        self.app.call_from_thread(self._refresh_chrome)

    @work(thread=True)
    def action_restore(self) -> None:
        app: "CSHApp" = self.app  # type: ignore
        if not be.is_root() or not app.interface:
            self.app.call_from_thread(
                self.query_one("#log", RichLog).write,
                "[#ff6e6e]✗[/] Restaurar requiere sudo e interfaz.")
            return
        if self.scanning:
            self.app.call_from_thread(self._stop_scan)
        self.app.call_from_thread(
            self.query_one("#log", RichLog).write,
            "[#9a8cff]▶[/] Restaurando WiFi normal (managed)…")
        ok, newif, _ = be.restore_managed(app.interface)
        app.interface = newif
        msg = (f"[#6ee787]✓[/] {newif} restaurada a managed (NetworkManager reactivado)"
               if ok else f"[#ff6e6e]✗[/] No se pudo restaurar {newif}")
        self.app.call_from_thread(self.query_one("#log", RichLog).write, msg)
        self.app.call_from_thread(self._refresh_chrome)

    # ── filtro de texto ──
    @on(Input.Changed, "#ssid")
    def _ssid_changed(self, ev: Input.Changed) -> None:
        self.ssid_filter = ev.value
        self._render_table()
        self._refresh_chrome()

    @on(Input.Submitted, "#ssid")
    def _ssid_submit(self) -> None:
        # Enter en el filtro devuelve el foco a la tabla (y así vuelven las teclas de comando).
        self.query_one("#nets", DataTable).focus()


class InterfaceScreen(Screen):
    """Pantalla inicial: elegir la interfaz WiFi a usar."""

    BINDINGS = [
        ("enter", "select", "Seleccionar"),
        ("r", "refresh", "Refrescar"),
        ("q", "app.quit", "Salir"),
    ]

    def compose(self) -> ComposeResult:
        yield Static(id="brandband")
        yield Static(id="pickhint")
        yield DataTable(id="ifaces", cursor_type="row", zebra_stripes=False)
        yield Static("", id="cmdbar")

    def on_mount(self) -> None:
        self.query_one("#brandband", Static).update(Text.from_markup(
            f"[reverse b {C_TEAL}] CSH [/]  [b {C_INK}]WPA-2 AUDIT CONSOLE[/]  "
            f"[{C_DIM}]· selección de interfaz ·[/]  [{C_TEAL}]{APP_VER}[/]"
        ))
        root = "root" if be.is_root() else "sin root (modo demo)"
        self.query_one("#pickhint", Static).update(Text.from_markup(
            f"[{C_DIM}]Elige la antena externa (USB) para la sesión.  "
            f"Sesión: [/][{C_TEAL}]{root}[/][{C_DIM}].  "
            f"Enter selecciona · r refresca.[/]"
        ))
        self.query_one("#cmdbar", Static).update(Text.from_markup(
            f"[{C_AMBER} b]↵[/][{C_DIM}] seleccionar[/]   "
            f"[{C_AMBER} b]r[/][{C_DIM}] refrescar[/]   "
            f"[{C_AMBER} b]q[/][{C_DIM}] salir[/]"
        ))
        t = self.query_one("#ifaces", DataTable)
        t.add_columns(" ", "INTERFAZ", "MODO", "MAC", "CANAL")
        t.border_title = "ANTENAS EXTERNAS (USB)"
        self._load()
        t.focus()

    def _load(self) -> None:
        t = self.query_one("#ifaces", DataTable)
        t.clear()
        ifs = be.list_interfaces(external_only=True)
        if not ifs:
            t.add_row("·", Text("No se detectó antena externa (USB)", style=C_AMBER), "", "", "")
            t.add_row("·", Text("Conecta la MT7612U y pulsa r para refrescar", style=C_DIM), "", "", "")
            return
        for i in ifs:
            typ = i["type"]
            tcolor = C_GREEN if typ == "monitor" else (C_AMBER if typ != "N/A" else C_DIM)
            t.add_row(
                Text("◆", style=C_TEAL),
                Text(i["iface"], style=f"b {C_INK}"),
                Text(typ, style=tcolor),
                Text(i["mac"], style="#8a98a0"),
                Text(str(i["channel"]), style=C_INK),
                key=i["iface"],
            )

    def action_refresh(self) -> None:
        self._load()

    @on(DataTable.RowSelected, "#ifaces")
    def _row_selected(self, ev: DataTable.RowSelected) -> None:
        self._choose(ev.row_key.value if ev.row_key else None)

    def action_select(self) -> None:
        t = self.query_one("#ifaces", DataTable)
        try:
            key = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
        except Exception:
            key = None
        self._choose(key)

    def _choose(self, iface: str | None) -> None:
        if not iface:
            return
        self.app.interface = iface  # type: ignore
        self.app.push_screen(ScannerScreen())


class CSHApp(App):
    CSS_PATH = "theme.tcss"
    TITLE = APP_TITLE
    BINDINGS = [("ctrl+q", "quit", "Salir")]

    def __init__(self, interface: str | None = None):
        super().__init__()
        self.interface = interface

    def on_mount(self) -> None:
        # Si se pasó -i, directo al radar; si no, mostrar el selector.
        if self.interface:
            self.push_screen(ScannerScreen())
        else:
            self.push_screen(InterfaceScreen())
