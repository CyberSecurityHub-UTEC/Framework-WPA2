"""Fixtures compartidas para la suite del CSH WPA-2 Framework.

Regla de oro de estos tests: NUNCA se toca hardware, root ni subprocess real.
CI no tiene herramientas WiFi ni privilegios, así que todo acceso a
`subprocess`, `/sys`, `os.geteuid` o `shutil.which` se mockea con monkeypatch.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Garantiza que el paquete `csh_tui` sea importable aunque no se haya hecho
# `pip install -e .` (añade la raíz del repo al sys.path).
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csh_tui import backend as be  # noqa: E402


class FakeProc:
    """Sustituto mínimo de subprocess.CompletedProcess."""

    def __init__(self, stdout: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


@pytest.fixture
def net_factory():
    """Construye objetos be.Network con valores por defecto sensatos."""

    def _make(**kw) -> be.Network:
        base = dict(bssid="AA:BB:CC:DD:EE:FF", channel="6", power=-50,
                    privacy="WPA2", cipher="CCMP", auth="PSK", essid="LabNet")
        base.update(kw)
        return be.Network(**base)

    return _make


@pytest.fixture
def no_subprocess(monkeypatch):
    """Bloquea cualquier subprocess.run real en el backend (devuelve vacío)."""

    def _fake_run(*args, **kwargs):
        return FakeProc(stdout="")

    monkeypatch.setattr(be.subprocess, "run", _fake_run)
    return _fake_run
