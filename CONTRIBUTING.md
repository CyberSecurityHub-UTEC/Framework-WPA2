# Guía de contribución — CSH WPA2 Framework

> Contexto para futuras sesiones de Claude Code y para contribuidores humanos.

## Propósito del proyecto

CSH WPA2 Framework es una **consola visual de laboratorio** (TUI en
[Textual](https://textual.textualize.io/)) para auditoría de redes WPA/WPA2.
Envuelve la cadena de herramientas **aircrack-ng** (`airodump-ng`, `aireplay-ng`,
`aircrack-ng`, etc.) detrás de una interfaz de texto.

**Uso ético / solo laboratorio.** Esta herramienta es exclusivamente para fines
educativos y de auditoría sobre redes propias o con autorización explícita por
escrito. Interceptar o atacar redes de terceros sin permiso es ilegal. Úsala solo
en un entorno de laboratorio controlado.

## Requisitos

- Python **>= 3.10**
- Linux (la TUI corre sin las herramientas wifi; estas solo hacen falta en uso real)
- Para uso real: aircrack-ng y privilegios de root/monitor mode. **No** se requieren
  para desarrollar ni para correr las pruebas.

## Puesta en marcha

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

`".[dev]"` instala el paquete en modo editable junto con las dependencias de
desarrollo: `pytest`, `pytest-asyncio`, `pytest-cov` y `ruff`.

## Correr la TUI

```bash
csh-console
# equivalente:
python -m csh_tui
```

## Pruebas

```bash
pytest
```

Las pruebas **mockean todas las llamadas a `subprocess`**, así que no necesitan
herramientas wifi, interfaces en modo monitor ni root. Deben poder correr en CI y
en cualquier máquina de desarrollo.

Con cobertura (como en CI):

```bash
pytest --cov=csh_tui --cov-report=term-missing
```

## Lint

```bash
ruff check .
# autocorregir lo que se pueda:
ruff check . --fix
```

La configuración de `ruff` y `pytest` vive en `pyproject.toml`
(`[tool.ruff]`, `[tool.ruff.lint]`, `[tool.pytest.ini_options]`).

## Mapa de arquitectura

| Archivo                | Responsabilidad                                                              |
| ---------------------- | --------------------------------------------------------------------------- |
| `csh_tui/backend.py`   | Lógica pura + *wrappers* de `subprocess` sobre aircrack-ng. **Sin UI.**      |
| `csh_tui/app.py`       | Interfaz Textual (widgets, pantallas, manejo de eventos). **Sin lógica cruda.** |
| `csh_tui/__main__.py`  | Punto de entrada (`main()`), expuesto como `csh-console`.                    |
| `csh_tui/theme.tcss`   | Estilos de la TUI (Textual CSS).                                             |
| `tests/`               | Pruebas con pytest; **mockean `subprocess`** (unitarias y e2e de la TUI).    |

Regla práctica: toda ejecución de comandos externos se concentra en `backend.py`
para que las pruebas puedan mockearla en un solo punto. `app.py` llama a
`backend.py`, nunca a `subprocess` directamente.

## Convención de commits

Usamos **[Conventional Commits](https://www.conventionalcommits.org/)** con *scope*:

```
<tipo>(<scope>): <resumen en imperativo>

<cuerpo opcional en español o inglés>

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

- **Tipos:** `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`.
- **Scope:** área afectada, p. ej. `iface`, `tui`, `backend`, `ci`.
- **Resumen:** modo imperativo, en minúscula, sin punto final
  (p. ej. `fix(iface): no perder antena USB en el selector`).
- **Cuerpo:** opcional, en español o inglés; explica el *por qué*.
- **Trailer obligatorio** cuando el commit lo genera Claude Code:

  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

## Convención de Pull Requests

- **Título descriptivo** en el mismo estilo de los commits.
- **Cuerpo** con tres secciones:
  - **Context** — qué problema o necesidad motiva el cambio.
  - **Changes** — qué se modificó, archivo/módulo a alto nivel.
  - **Testing** — cómo se verificó (`pytest`, `ruff check .`, pruebas manuales).
- Enlaza los bugs relacionados (ver `bugs.md`).
- **Trailer obligatorio** al final de la descripción:

  ```
  🤖 Generated with [Claude Code](https://claude.com/claude-code)
  ```

## Bugs

Los bugs conocidos y pendientes se registran en **`bugs.md`** en la raíz del repo.
Al abrir un PR que corrige uno, enlázalo y actualiza `bugs.md` si procede.
