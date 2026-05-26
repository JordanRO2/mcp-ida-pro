# Comparación con upstream (mrexodia/ida-pro-mcp) + Plan de port

Generado: 2026-05-25 · rama `main`

## Remotos
- **origin** (tu fork): `git@github.com:JordanRO2/MCP-IDA-PRO.git`
- **upstream** (original): `https://github.com/mrexodia/ida-pro-mcp.git`

## Estado real (corregido)
El `main` actual **NO es la versión DDD**. El commit base del fork es
`6d5c3d5 "sync: reset to upstream and apply fork customizations"`: se hizo reset a la
estructura plana del upstream y encima se aplicaron las personalizaciones. Ambos forks son
**v2.0.0 con el mismo layout `ida_mcp/api_*.py`**, así que portar/mergear es viable
(no hay conflicto estructural por DDD; esa fue la v1.0.0 abandonada).

## Divergencia
- Merge-base: `5bdafa2` (2026-03-18, PR #302).
- **Tu fork:** 15 commits adelante. **Upstream:** 139 commits adelante (hasta PR #428, 2026-05-26).

### Tus personalizaciones propias (no tocar al portar)
`api_security.py` (+24 tests), timeouts por llamada en todas las tools, paginación,
logging persistente a archivo, hardening de `py_eval`, type resource, capa `compat`,
session expiry.

## Candidatos a portar (archivos nuevos en upstream)

| Feature | Archivos | Deps en nuestro código | Esfuerzo | Valor |
|---|---|---|---|---|
| **sigmaker** | `ida_mcp/_sigmaker.py` (1048) + `api_sigmaker.py` (347) | `rpc.tool`, `sync.idasync`, `utils.parse_address` ✓, `utils.normalize_list_input` ✓ | **Bajo** | **Alto** |
| **trace** | `ida_mcp/trace.py` (336) + `trace_dump.py` (55) | `rpc.MCP_SERVER` ✓, `registry.methods["tools/call"]` ✓ (monkeypatch en runtime) | **Bajo** | Medio |
| **profile** | `ida_mcp/profile.py` + `profiles/readonly.txt`, `triage.txt` | solo stdlib; falta cablear `--profile` en `server.py` | Medio | Medio (seguridad) |
| **discovery** | `ida_mcp/api_discovery.py` + `discovery.py` | ⚠ `zeromcp.EXTERNAL_BASE_HEADER` y `get_current_request_external_base_url` **NO existen** en nuestro zeromcp | Alto | Bajo |
| **idalib_supervisor** | `idalib_supervisor.py` (1579) | arquitectura headless completa | Alto | Bajo (solo headless) |

### sigmaker — tools que agrega
`make_signature`, `make_signature_for_function`, `make_signature_for_range`. Motor vendored
(`_sigmaker.py`, solo stdlib + `idaapi`/`idc`), sin dependencia pip. **Port limpio.**

### trace — mecanismo
`trace.configure_idb()` en `__init__.py` + `install_tracer()` que envuelve en runtime
`MCP_SERVER.registry.methods["tools/call"]` y graba cada llamada en un netnode del IDB.
No requiere editar `mcp.py`. **Port limpio.**

## Bugfixes en archivos compartidos (requieren cherry-pick o merge)
16 archivos `.py` tocados por ambos lados. Fixes valiosos del upstream:
- **Debugger** (`api_debug.py`): breakpoints condicionales, fixes de `dbg_start`
  (modo batch, IP grace, reporte de fallos), fix de deadlock en `call_stack` con `@idasync` reentrante.
- **Compatibilidad** (`compat.py`/`utils.py`): IDA 8.3 y IDA 9.0 early builds.
- **`open_file`** restaurado y corregido (paths de ejecutable, Linux).
- `refactor(search_text)`: híbrido `find_text` + `generate_disassembly`.
- Fix de output schema para resultados con forma de unión; trim de whitespace en disasm/decompile.

## Estrategia recomendada
1. **Tier 1 (ya, limpio):** portar **sigmaker** y **trace** copiando archivos + import en `__init__.py`. Sin tocar archivos compartidos.
2. **Tier 2 (con cuidado):** cherry-pick / port manual de fixes de **debugger** y **compat IDA 8.3/9.0** desde `api_debug.py`/`compat.py`. Diff por función.
3. **Tier 2:** **profile** (perfiles readonly/triage) — copiar + cablear `--profile`.
4. **Tier 3 (diferir):** **discovery** (requiere portar antes los cambios de zeromcp) e **idalib_supervisor** (solo si usas modo headless).

> Un `git merge upstream/main` traería todo de una pero exige resolver 16 archivos en conflicto
> protegiendo `api_security`, timeouts y logging. Preferir port selectivo salvo que se quiera sincronizar a fondo.
