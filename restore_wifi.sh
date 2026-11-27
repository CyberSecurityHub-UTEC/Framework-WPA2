#!/usr/bin/env bash
# restore_wifi.sh — Devolver una interfaz de modo monitor a modo managed (WiFi normal)
# en Fedora, y reactivar NetworkManager.
#
# Uso:
#   sudo ./restore_wifi.sh [INTERFACE]
#
# Si no se indica interfaz, se intenta detectar automáticamente la que esté en monitor.

set -uo pipefail

BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"
BLUE="\033[34m"; CYAN="\033[36m"; RESET="\033[0m"

line()        { echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }
box_title()   { line; echo -e "${BOLD}${CYAN}  $1${RESET}"; line; }
status_ok()   { echo -e "${GREEN}✓${RESET} $1"; }
status_warn() { echo -e "${YELLOW}!${RESET} $1"; }
status_err()  { echo -e "${RED}✗${RESET} $1"; }

clear
box_title "RESTAURAR WIFI NORMAL (MANAGED) — FEDORA"

if [[ $EUID -ne 0 ]]; then
    status_err "Ejecuta este script con sudo:"
    echo "    sudo $0 ${1:-}"
    exit 1
fi

for cmd in iw ip systemctl; do
    command -v "$cmd" >/dev/null 2>&1 || { status_err "Falta: $cmd"; exit 1; }
done

INTERFACE="${1:-}"

# Autodetección de la interfaz en modo monitor si no se pasó una.
if [[ -z "$INTERFACE" ]]; then
    INTERFACE="$(iw dev 2>/dev/null | awk '
        /Interface/ {iface=$2}
        /type monitor/ {print iface; exit}
    ')"
fi

if [[ -z "$INTERFACE" ]]; then
    status_warn "No se detectó ninguna interfaz en modo monitor."
    echo ""
    echo "Interfaces WiFi disponibles:"
    iw dev | awk '/Interface/ {print "    - " $2}'
    exit 1
fi

if ! iw dev "$INTERFACE" info >/dev/null 2>&1; then
    status_err "Interfaz '$INTERFACE' no encontrada."
    exit 1
fi

box_title "RESTAURANDO $INTERFACE"

# 1) Si fue creada por airmon-ng (p.ej. wlan0mon), intentar detenerla limpiamente.
if command -v airmon-ng >/dev/null 2>&1; then
    status_warn "Intentando 'airmon-ng stop $INTERFACE'..."
    airmon-ng stop "$INTERFACE" >/dev/null 2>&1 || true
    sleep 1
fi

# 2) Determinar qué interfaz quedó viva para forzar managed con iw.
RESTORE_IFACE="$INTERFACE"
if ! iw dev "$RESTORE_IFACE" info >/dev/null 2>&1; then
    RESTORE_IFACE="$(iw dev 2>/dev/null | awk '/Interface/ {print $2; exit}')"
fi

if [[ -n "$RESTORE_IFACE" ]]; then
    status_warn "Forzando modo managed en $RESTORE_IFACE"
    ip link set "$RESTORE_IFACE" down 2>/dev/null || true
    iw dev "$RESTORE_IFACE" set type managed 2>/dev/null || true
    ip link set "$RESTORE_IFACE" up 2>/dev/null || true
fi

status_warn "Reactivando NetworkManager"
systemctl start NetworkManager >/dev/null 2>&1 || true
sleep 1

box_title "RESULTADO"
TYPE="$(iw dev "$RESTORE_IFACE" info 2>/dev/null | awk '/type/ {print $2; exit}')"
if [[ "$TYPE" != "monitor" ]]; then
    status_ok "Interfaz '$RESTORE_IFACE' restaurada a modo '${TYPE:-managed}'."
    status_ok "NetworkManager reactivado. Tu WiFi debería reconectarse."
else
    status_err "No se pudo confirmar el cambio. Hazlo manualmente:"
    echo "    sudo ip link set $RESTORE_IFACE down"
    echo "    sudo iw dev $RESTORE_IFACE set type managed"
    echo "    sudo ip link set $RESTORE_IFACE up"
    echo "    sudo systemctl restart NetworkManager"
fi
line
