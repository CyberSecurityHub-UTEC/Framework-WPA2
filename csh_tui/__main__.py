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
    CSHApp(interface=args.interface).run()


if __name__ == "__main__":
    main()
