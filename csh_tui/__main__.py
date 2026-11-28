"""Punto de entrada: python -m csh_tui  (o el lanzador ./csh.sh)."""

from __future__ import annotations

import argparse

from .app import CSHApp


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="csh-console",
        description="CSH WPA-2 Framework — consola visual de laboratorio (Textual).",
    )
    ap.add_argument("-i", "--interface", help="Interfaz WiFi (managed o monitor).")
    args = ap.parse_args()
    # mouse=False: la consola se maneja SOLO con teclado (flechas + Enter). Así
    # el terminal no entra en modo de reporte de ratón y un click del touchpad
    # no inyecta secuencias SGR (cuyo "release" termina en «m») que se colaban
    # como pulsaciones de tecla —p. ej. reactivando el modo monitor—.
    CSHApp(interface=args.interface).run(mouse=False)


if __name__ == "__main__":
    main()
