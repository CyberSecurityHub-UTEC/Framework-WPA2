#!/usr/bin/env bash
# activate_monitor.sh — Activar modo monitor en Fedora con interfaz visual
# Uso:
#   sudo ./activate_monitor.sh [INTERFACE]

set -euo pipefail

INTERFACE="${1:-wlp0s20f0u1}"

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

line() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

box_title() {
    line
    echo -e "${BOLD}${CYAN}  $1${RESET}"
    line
}

status_ok() {
    echo -e "${GREEN}✓${RESET} $1"
}

status_warn() {
    echo -e "${YELLOW}!${RESET} $1"
}

status_error() {
    echo -e "${RED}✗${RESET} $1"
}

get_field() {
    local iface="$1"
    local pattern="$2"

    iw dev "$iface" info 2>/dev/null | awk -v pat="$pattern" '
        $0 ~ pat {
            sub(/^[ \t]+/, "")
            print
            exit
        }
    '
}

get_channel() {
    local iface="$1"

    iw dev "$iface" info 2>/dev/null | awk '
        /channel/ {
            print $2
            exit
        }
    '
}

get_frequency() {
    local iface="$1"

    iw dev "$iface" info 2>/dev/null | awk '
        /channel/ {
            gsub(/[()]/, "", $3)
            print $3 " MHz"
            exit
        }
    '
}

get_type() {
    local iface="$1"

    iw dev "$iface" info 2>/dev/null | awk '
        /type/ {
            print $2
            exit
        }
    '
}

get_txpower() {
    local iface="$1"

    iw dev "$iface" info 2>/dev/null | awk '
        /txpower/ {
            print $2 " " $3
            exit
        }
    '
}

show_interface_info() {
    local iface="$1"

    local type
    local channel
    local frequency
    local txpower
    local mac

    type="$(get_type "$iface")"
    channel="$(get_channel "$iface")"
    frequency="$(get_frequency "$iface")"
    txpower="$(get_txpower "$iface")"
    mac="$(iw dev "$iface" info 2>/dev/null | awk '/addr/ {print $2; exit}')"

    [[ -z "$type" ]] && type="N/A"
    [[ -z "$channel" ]] && channel="N/A"
    [[ -z "$frequency" ]] && frequency="N/A"
    [[ -z "$txpower" ]] && txpower="N/A"
    [[ -z "$mac" ]] && mac="N/A"

    echo -e "${BOLD}Interfaz:${RESET}      $iface"
    echo -e "${BOLD}Modo:${RESET}          $type"
    echo -e "${BOLD}MAC:${RESET}           $mac"
    echo -e "${BOLD}Canal:${RESET}         $channel"
    echo -e "${BOLD}Frecuencia:${RESET}    $frequency"
    echo -e "${BOLD}Potencia TX:${RESET}   $txpower"
}

clear
box_title "WIFI MONITOR MODE — FEDORA"

echo -e "${BOLD}Objetivo:${RESET} activar modo monitor en la interfaz WiFi"
echo ""

if [[ $EUID -ne 0 ]]; then
    status_error "Ejecuta este script con sudo:"
    echo "    sudo $0 $INTERFACE"
    exit 1
fi

box_title "VERIFICANDO DEPENDENCIAS"

for cmd in iw airmon-ng ip systemctl; do
    if command -v "$cmd" >/dev/null 2>&1; then
        status_ok "$cmd instalado"
    else
        status_error "Falta instalar: $cmd"
        echo ""
        echo "Instala lo necesario con:"
        echo "    sudo dnf install aircrack-ng iw iproute"
        exit 1
    fi
done

echo ""

box_title "INTERFAZ SELECCIONADA"

if ! iw dev "$INTERFACE" info >/dev/null 2>&1; then
    status_error "Interfaz '$INTERFACE' no encontrada"
    echo ""
    status_warn "Interfaces WiFi disponibles:"
    iw dev | awk '/Interface/ {print "    - " $2}'
    exit 1
fi

show_interface_info "$INTERFACE"

echo ""
box_title "ACTIVANDO MODO MONITOR"

status_warn "Deteniendo NetworkManager temporalmente"
systemctl stop NetworkManager || true

status_warn "Eliminando procesos que pueden interferir"
airmon-ng check kill >/dev/null 2>&1 || true

status_warn "Bajando interfaz $INTERFACE"
ip link set "$INTERFACE" down

status_warn "Intentando activar modo monitor con iw"

if iw dev "$INTERFACE" set type monitor 2>/dev/null; then
    MONITOR_INTERFACE="$INTERFACE"
    status_ok "Modo monitor activado con iw"
else
    status_warn "iw falló. Intentando con airmon-ng"
    airmon-ng start "$INTERFACE"

    sleep 1

    MONITOR_INTERFACE="$(iw dev | awk '
        /Interface/ {iface=$2}
        /type monitor/ {print iface}
    ' | head -n 1)"
fi

if [[ -z "${MONITOR_INTERFACE:-}" ]]; then
    status_error "No se pudo detectar una interfaz en modo monitor"
    echo ""
    iw dev
    exit 1
fi

ip link set "$MONITOR_INTERFACE" up

echo ""
box_title "MODO MONITOR ACTIVADO"

status_ok "Interfaz monitor lista: $MONITOR_INTERFACE"
echo ""

show_interface_info "$MONITOR_INTERFACE"

echo ""
box_title "COMANDOS ÚTILES"

echo -e "${BOLD}Escanear redes:${RESET}"
echo "    sudo airodump-ng $MONITOR_INTERFACE"
echo ""

echo -e "${BOLD}Escanear un canal específico:${RESET}"
echo "    sudo iw dev $MONITOR_INTERFACE set channel 6"
echo "    sudo airodump-ng -c 6 $MONITOR_INTERFACE"
echo ""

echo -e "${BOLD}Ver estado actual:${RESET}"
echo "    iw dev $MONITOR_INTERFACE info"
echo ""

echo -e "${BOLD}Restaurar WiFi normal:${RESET}"
echo "    sudo ip link set $MONITOR_INTERFACE down"
echo "    sudo iw dev $MONITOR_INTERFACE set type managed"
echo "    sudo ip link set $MONITOR_INTERFACE up"
echo "    sudo systemctl restart NetworkManager"

echo ""
line
echo -e "${GREEN}${BOLD}Listo. Usa la interfaz: $MONITOR_INTERFACE${RESET}"
line