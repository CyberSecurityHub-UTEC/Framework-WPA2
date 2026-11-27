<div align="center">
  <img src="CSH_Logo.png" alt="CSH" width="180"/>

  # CSH WPA-2 Framework

  **Consola de laboratorio para auditoría de redes WPA/WPA2 en Fedora Linux**

  Scan → Captura de handshake → Deauth dirigido → Verificación → Cracking (aircrack-ng / hashcat)

  `v2.0` · **Consola visual (Textual)** + consola clásica (Bash) · inspirado en [wifite3](https://github.com/derv82/wifit3)
</div>

---

## 🖥️ Dos interfaces, un mismo flujo

| Interfaz | Comando | Cuándo usarla |
|---|---|---|
| **Consola visual (Textual)** — pantalla completa, tabla en vivo con señal/cifrado en color, panel de filtros, log con viñetas y atajos de teclado, estilo wifite3. | `./csh.sh` | Experiencia principal, la más visual. Requiere Python (se instala solo con `uv`). |
| **Consola clásica (Bash)** — menús de texto, sin dependencias de Python. | `sudo ./main.sh` | Fallback ligero o entornos sin Python. Mismas capacidades base. |

> La consola visual arranca en **modo demo** (carga capturas previas) si la ejecutas sin `sudo`, para que puedas ver la interfaz sin tocar la tarjeta WiFi.

---

## ⚠️ Aviso ético y legal — léelo primero

Esta herramienta está pensada **exclusivamente** para:

- Tu **propia** red WiFi.
- Un **laboratorio controlado** del que seas responsable.
- Pruebas con **autorización explícita y por escrito** del dueño de la red.

Capturar handshakes, enviar tramas de *deauth* o interceptar tráfico de redes ajenas **sin permiso es ilegal** en la mayoría de jurisdicciones (en Perú, Ley de Delitos Informáticos N.° 30096). El autor y los colaboradores **no se hacen responsables** del uso indebido. La consola incluye confirmaciones de autorización por una razón: respétalas.

> Úsalo para **aprender a defender**, no para atacar a terceros.

---

## ✨ Características

| Área | Qué hace |
|---|---|
| **Recon** | Escaneo con `airodump-ng`, tabla estilo wifite con color por cifrado, **barras de señal**, conteo de **clientes asociados** y detección de WPA3/SAE. |
| **Modo monitor** | Activación guiada (`airmon-ng`/`iw`) y **restauración a modo managed** con reactivación de NetworkManager. |
| **Captura** | Handshake pasivo, o con **deauth finito / continuo**, dirigido al AP o a un cliente concreto. Dashboard en vivo durante la captura. |
| **Verificación** | Comprobación de handshake con `aircrack-ng` y generación de **CAP filtrado** al objetivo (`tshark`). |
| **Cracking (CPU)** | Ataque de diccionario con `aircrack-ng`. |
| **Cracking (GPU)** | Conversión a formato **`.22000`** (`hcxpcapngtool`) y cracking con **`hashcat -m 22000`**. |
| **Diccionarios** | Detección/importación de **rockyou**, generación de wordlists por patrón con **`crunch`** (celulares, PINs, plantillas personalizadas). |
| **Reportes** | Reporte por sesión en **`.txt` y Markdown** con todos los datos del objetivo y siguientes pasos. |

---

## 📦 Requisitos

### Obligatorias
```bash
sudo dnf install aircrack-ng iw iproute procps-ng chafa
```
- `aircrack-ng` (airodump-ng, aireplay-ng, aircrack-ng, airmon-ng)
- `iw`, `ip` — gestión de la interfaz
- `chafa` — render del logo en terminal (consola Bash)

### Para la consola visual (Textual)
```bash
sudo dnf install uv          # gestor de entornos Python de Astral
# (El lanzador ./csh.sh instala Textual automáticamente la primera vez.)
```
- Python ≥ 3.10 y [`uv`](https://docs.astral.sh/uv/). Si no hay `uv`, el lanzador usa `python -m venv` + `pip`.

### Opcionales (desbloquean funciones extra)
```bash
sudo dnf install wireshark-cli hcxtools hashcat crunch wordlists
```
| Paquete | Desbloquea |
|---|---|
| `wireshark-cli` (`tshark`) | CAP filtrado por objetivo |
| `hcxtools` (`hcxpcapngtool`) | Conversión `.cap` → `.22000` |
| `hashcat` | Cracking por GPU (modo 22000) |
| `crunch` | Generador de diccionarios por patrón |
| `wordlists` | rockyou en `/usr/share/wordlists/` |

La consola **autodetecta** qué herramientas tienes y lo muestra en el dashboard; nunca falla por falta de una opcional.

> Necesitas un adaptador WiFi compatible con **modo monitor** e **inyección** de paquetes.

---

## 🚀 Uso rápido

### Consola visual (recomendada)
```bash
# Instala Textual (una sola vez) y arranca; pide sudo para escanear en vivo
./csh.sh
./csh.sh -i wlp0s20f0u1mon     # indicando interfaz
./csh.sh --demo                # solo ver la UI, sin sudo (modo demo)
```
**Atajos:** `s` escanear · `Enter` objetivo · `e` cifrado · `c` solo con clientes · `/` buscar SSID · `d` diccionarios · `v` vault · `m` modo monitor · `r` restaurar WiFi · `q` salir.

### Consola clásica (Bash)
```bash
# 1. (Opcional) Activar modo monitor desde fuera de la consola
sudo ./activate_monitor.sh wlp0s20f0u1

# 2. Lanzar la consola
sudo ./main.sh
sudo ./main.sh -i wlp0s20f0u1 --scan-time 15

# 3. Al terminar, devolver la tarjeta a WiFi normal
sudo ./restore_wifi.sh
#   (también dentro de la consola: Configuración → Restaurar WiFi)
```

### Opciones de línea de comandos
```
-i, --interface IFACE     Interfaz WiFi (managed o monitor)
    --scan-time SEGUNDOS   Duración del escaneo inicial (def. 12)
    --capture-time SEG     Timeout de captura (def. 300)
    --no-color             Desactiva colores ANSI
-h, --help                Ayuda
```

---

## 🧭 Flujo de trabajo típico

```
┌─ 1. Escanear ────────────┐   Menú → 1
│  Elige el objetivo de la │   (tabla con señal, cifrado y clientes)
│  lista detectada         │
└──────────────┬───────────┘
               ▼
┌─ 2. Capturar handshake ──┐   Menú → 3
│  Pasiva, o con deauth     │   Necesitas ≥1 cliente conectado.
│  dirigido a un cliente    │   El dashboard avisa cuando hay handshake.
└──────────────┬───────────┘
               ▼
┌─ 3a. Verificar ──────────┐   Menú → 4
│  aircrack-ng confirma el  │
│  handshake en el .cap     │
└──────────────┬───────────┘
               ▼
┌─ 3b. Crackear ───────────┐   Menú → 5 (aircrack, CPU)
│  Diccionario autorizado   │   Menú → 6 (hashcat 22000, GPU)
└──────────────┬───────────┘
               ▼
┌─ 4. Restaurar WiFi ──────┐   Configuración → 3  (o ./restore_wifi.sh)
└──────────────────────────┘
```

---

## 🔑 Cracking con hashcat (GPU)

Mucho más rápido que CPU cuando tienes GPU. Desde la consola: **Menú → 6**.

1. Selecciona el `.cap` capturado.
2. Se convierte a `.22000` con `hcxpcapngtool` → se guarda en `hashes/`.
3. Elige un diccionario y se ejecuta:
   ```bash
   hashcat -m 22000 -a 0 hashes/<objetivo>.22000 <diccionario>
   ```
4. Ver resultado:
   ```bash
   hashcat -m 22000 hashes/<objetivo>.22000 --show
   ```

Si no tienes GPU en esta máquina, la consola te deja el `.22000` listo para crackear en otra.

---

## 📚 Gestión de diccionarios (Menú → 7)

- **Importar rockyou** del sistema a `wordlists/` (descomprime `.gz` automáticamente).
- **Generar por patrón** con `crunch`:
  - Celulares Perú: `9XXXXXXX` (8 dígitos).
  - PINs numéricos de longitud fija.
  - Plantilla personalizada (`@`=letra, `,`=MAYÚS, `%`=dígito, `^`=símbolo).
- **Fijar diccionario por defecto** para los ataques.

---

## 🗂️ Estructura del repositorio

```
Framework-WPA2/
├── csh.sh               # Lanzador de la consola visual (Textual)
├── csh_tui/             # App Textual (interfaz visual)
│   ├── app.py           #   pantallas: scanner, objetivo, vault, diccionarios
│   ├── backend.py       #   envoltorio aircrack-ng / hashcat / reportes
│   └── theme.tcss       #   tema visual (estilo wifite3)
├── pyproject.toml       # Dependencias Python (textual)
├── main.sh              # Consola clásica (TUI Bash)
├── activate_monitor.sh  # Activar modo monitor (standalone)
├── restore_wifi.sh      # Restaurar modo managed (standalone)
├── CSH_Logo.png         # Logo (render con chafa)
├── captures/            # .cap / .csv de airodump
├── hashes/              # Capturas convertidas a .22000
├── reports/             # Reportes .txt y .md por sesión
├── wordlists/           # Diccionarios
└── README.md
```

---

## 🛠️ Solución de problemas

| Síntoma | Solución |
|---|---|
| `No se detectaron interfaces WiFi` | `iw dev`, `rfkill list` (desbloquea con `rfkill unblock wifi`), revisa firmware. |
| El modo monitor desconecta la red | Es esperado. Usa `restore_wifi.sh` o la opción de restaurar al terminar. |
| No aparece handshake | Debe haber un cliente conectado; usa deauth dirigido y amplía el timeout. |
| `hcxpcapngtool: 0 hashes` | La captura no contiene handshake/PMKID válido; vuelve a capturar. |
| WPA3 no crackea | Correcto: SAE no se valida con aircrack clásico; la consola lo marca en magenta. |
| El logo no se ve | `sudo dnf install chafa`. |

---

## 📄 Licencia

Ver [LICENSE](LICENSE). Uso educativo y de auditoría autorizada únicamente.
