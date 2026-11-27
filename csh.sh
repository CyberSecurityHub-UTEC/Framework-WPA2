#!/usr/bin/env bash
# csh.sh — Lanzador de la consola visual CSH WPA-2 Framework (Textual).
#
# Prepara el entorno con uv (una sola vez) y arranca la TUI. Para escanear en
# vivo y capturar handshakes necesitas root; sin root arranca en MODO DEMO.
#
# Uso:
#   ./csh.sh                  # auto: usa sudo si está disponible
#   ./csh.sh -i wlan0mon      # indicando interfaz
#   ./csh.sh --demo           # forzar modo demo sin sudo (solo ver la UI)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DEMO=0
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --demo) DEMO=1; shift ;;
        *) ARGS+=("$1"); shift ;;
    esac
done

# 1) Dependencias Python mediante uv (preferido) o venv + pip.
PY=""
if [[ -x ".venv/bin/python" ]]; then
    PY=".venv/bin/python"
elif command -v uv >/dev/null 2>&1; then
    echo "[*] Preparando entorno con uv…"
    uv venv || { echo "[!] 'uv venv' falló."; exit 1; }
    uv pip install "textual>=0.60" || { echo "[!] No se pudo instalar textual con uv."; exit 1; }
    PY=".venv/bin/python"
else
    echo "[*] uv no encontrado; usando python -m venv…"
    python3 -m venv .venv || { echo "[!] No se pudo crear el venv."; exit 1; }
    .venv/bin/pip install --upgrade pip "textual>=0.60" || { echo "[!] No se pudo instalar textual con pip."; exit 1; }
    PY=".venv/bin/python"
fi

# Verificar que Textual realmente está disponible antes de arrancar.
if ! "$PY" -c "import textual" 2>/dev/null; then
    echo "[!] Textual no está disponible en $PY."
    echo "    Instala manualmente:  uv pip install 'textual>=0.60'   (o pip install)"
    exit 1
fi

# 2) Ejecutar. Si no somos root y no se pidió demo, intentar sudo conservando el venv.
run() { exec "$PY" -m csh_tui "${ARGS[@]+"${ARGS[@]}"}"; }

if [[ $EUID -eq 0 || $DEMO -eq 1 ]]; then
    run
elif command -v sudo >/dev/null 2>&1; then
    echo "[*] Escaneo en vivo requiere root. Elevando con sudo…"
    echo "    (Ctrl+C y usa ./csh.sh --demo para solo ver la interfaz)"
    exec sudo -E "$PY" -m csh_tui "${ARGS[@]+"${ARGS[@]}"}"
else
    echo "[!] Sin sudo: arrancando en MODO DEMO (solo visualización)."
    run
fi
