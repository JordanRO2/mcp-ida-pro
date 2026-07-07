"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import idaapi
import ida_kernwin
import ida_netnode
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


# Per-database persistence of the configured MCP endpoint (netnode). All access
# is best-effort: any failure (no open database, etc.) falls back to defaults so
# the plugin never breaks. Distinct from the "$ ida_mcp.<key>" config blobs.
_NETNODE_ENDPOINT = "$ ida_mcp.endpoint"
_ALT_PORT = 0
_SUP_HOST = 0


def _persisted_endpoint() -> "tuple[str, int] | None":
    """Return (host, port) saved in this database, or None if not set."""
    try:
        node = ida_netnode.netnode(_NETNODE_ENDPOINT)
        port = node.altval(_ALT_PORT)  # 0 == not set
        host = node.supstr(_SUP_HOST)
        if port and host:
            return host, int(port)
    except Exception:
        pass
    return None


def _persist_endpoint(host: str, port: int) -> None:
    """Save (host, port) into this database's netnode. Best-effort."""
    try:
        node = ida_netnode.netnode(_NETNODE_ENDPOINT, 0, True)
        node.altset(_ALT_PORT, port)
        node.supset(_SUP_HOST, host)
    except Exception:
        pass


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server host and port."""

    def __init__(self, host: str, port: int):
        form_str = r"""STARTITEM 0
MCP Server Configuration

<Host:{host}>
<Port:{port}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "port": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        old_host = self.plugin.host
        old_port = self.plugin.port

        form = MCPConfigForm(self.plugin.host, self.plugin.port)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        port = form.port.value
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        if host == old_host and port == old_port:
            print(f"[MCP] Configuration unchanged: {host}:{port}")
            return 1

        self.plugin.host = host
        self.plugin.port = port
        # Persist per-database so the endpoint survives close/reopen.
        _persist_endpoint(host, port)
        print(f"[MCP] Configuration updated (saved to database): {host}:{port}")

        # Apply new endpoint immediately if the server is running.
        if self.plugin.mcp is not None:
            print("[MCP] Applying configuration change without manual restart...")
            self.plugin.run(0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment until the UI is fully ready, then auto-starts the server."""

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        # Auto-start the MCP server once the UI is ready, so the user does not
        # have to press Ctrl+Alt+M manually. Opt out with IDA_MCP_NO_AUTOSTART.
        import os as _os

        if not _os.environ.get("IDA_MCP_NO_AUTOSTART"):
            try:
                self.plugin._start_server()
            except Exception as e:
                print(f"[MCP] Auto-start failed: {e}")
        self.unhook()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, server auto-starts when the UI is ready "
            f"(press {hotkey} to restart, or set IDA_MCP_NO_AUTOSTART to disable)"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        # Prefer an endpoint persisted in this database (survives close/reopen),
        # else fall back to the defaults.
        saved = _persisted_endpoint()
        if saved is not None:
            self.host, self.port = saved
        else:
            self.host = self.DEFAULT_HOST
            self.port = self.DEFAULT_PORT

        # Register a separate menu item for host/port configuration
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        # Defer menu attachment + auto-start until the UI is fully initialized
        self._ui_hooks = MCPUIHooks(self)
        self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def _remove_connection_file(self):
        """Best-effort removal of the connection file (import-safe)."""
        try:
            if TYPE_CHECKING:
                from .ida_mcp.infrastructure.connection import remove_connection_file
            else:
                from ida_mcp.infrastructure.connection import remove_connection_file
            remove_connection_file()
        except Exception:
            pass

    def _maybe_launch_supervisor(self):
        """Start ONE shared idalib supervisor if none is running yet.

        The first IDA instance to open launches it; later instances see it
        already listening and just rely on their discovery registration to be
        adopted. Opt out with IDA_MCP_NO_SUPERVISOR. Best-effort: any failure
        only means parallel mode must be started manually (idalib-mcp).
        """
        import os
        import json
        import socket
        import subprocess

        if os.environ.get("IDA_MCP_NO_SUPERVISOR"):
            return

        # Load the launch spec written at install time; fall back to env/derived.
        cfg = {}
        try:
            appdata = os.environ.get("APPDATA") or os.path.join(
                os.path.expanduser("~"), "AppData", "Roaming"
            )
            cfg_path = os.path.join(appdata, "Hex-Rays", "IDA Pro", "mcp", "supervisor.json")
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            pass

        host = os.environ.get("IDA_MCP_SUPERVISOR_HOST", cfg.get("host", "127.0.0.1"))
        port = int(os.environ.get("IDA_MCP_SUPERVISOR_PORT", cfg.get("port", 8745)))

        # Already running (shared across IDA instances)? Then do nothing.
        try:
            with socket.create_connection((host, port), timeout=0.5):
                print(f"[MCP] Shared supervisor already running on {host}:{port}")
                return
        except OSError:
            pass

        python = os.environ.get("IDA_MCP_SUPERVISOR_PYTHON") or cfg.get("python")
        if not python or not os.path.exists(python):
            print(
                "[MCP] No supervisor Python configured; parallel mode is manual "
                "(run 'idalib-mcp'). Reinstall with 'ida-pro-mcp --install' to enable auto-start."
            )
            return

        env = dict(os.environ)
        # Workers spawned by the supervisor need idalib -> point IDADIR at this
        # IDA install, and PYTHONPATH at the source (for a dev/symlink checkout).
        try:
            env["IDADIR"] = idaapi.idadir("")
        except Exception:
            pass
        src = cfg.get("src")
        if not src:
            # Derive from this loader's real location (symlinked dev checkout).
            real = os.path.realpath(__file__)
            src = os.path.dirname(os.path.dirname(real))
        if src and os.path.isdir(src):
            env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")

        creationflags = 0
        if os.name == "nt":
            creationflags = (
                getattr(subprocess, "DETACHED_PROCESS", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            )
        try:
            subprocess.Popen(
                [python, "-m", cfg.get("module", "ida_pro_mcp.idalib_supervisor"),
                 "--host", host, "--port", str(port)],
                env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                start_new_session=(os.name != "nt"),
            )
            print(f"[MCP] Launched shared idalib supervisor on {host}:{port} "
                  f"(connect your MCP client here for parallel/multi-agent mode)")
        except Exception as e:
            print(f"[MCP] Could not launch supervisor (non-fatal): {e}")

    def _deregister_discovery(self):
        """Best-effort removal of this GUI instance's discovery registration."""
        port = getattr(self, "_discovery_port", None)
        if port is None:
            return
        try:
            from ida_mcp.discovery import unregister_instance
            unregister_instance(port)
        except Exception:
            pass
        self._discovery_port = None

    def _start_server(self):
        """(Re)start the MCP HTTP server. Used by both auto-start and the hotkey."""
        if self.mcp:
            self.mcp.stop()
            self.mcp = None
            self._remove_connection_file()
            self._deregister_discovery()

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
            from .ida_mcp.infrastructure.connection import (
                generate_token,
                read_stable_token,
                write_connection_file,
                remove_connection_file,
            )
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
            from ida_mcp.infrastructure.connection import (
                generate_token,
                read_stable_token,
                write_connection_file,
                remove_connection_file,
            )
            from ida_mcp.discovery import register_instance

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        # Generate a fresh session token for this server lifetime. It is always
        # written to the connection file and accepted if presented; it is only
        # *required* when IDA_MCP_REQUIRE_TOKEN is set (enforced in the handler).
        token = read_stable_token() or generate_token()
        MCP_SERVER.auth_token = token

        # Discover an available port starting at the configured one. The first
        # free port in the range is bound; the actual bound port is recorded in
        # the connection file so the bridge can find it without configuration.
        port = self.port
        max_port = port + 100
        while port < max_port:
            try:
                MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"  Config: http://{self.host}:{port}/config.html")
                self.mcp = MCP_SERVER
                try:
                    path = write_connection_file(port, token)
                    print(f"  Connection file: {path}")
                except Exception as e:
                    print(f"[MCP] Failed to write connection file: {e}")
                # Register this live GUI instance in the discovery registry so a
                # unified idalib supervisor can ADOPT it (route tools to the DB
                # you are looking at) alongside its headless workers, instead of
                # this being a separate MCP endpoint.
                try:
                    import ida_nalt
                    import ida_loader
                    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
                    binary = ida_nalt.get_root_filename() or (
                        __import__("os").path.basename(idb_path)
                    )
                    register_instance(
                        self.host, port, __import__("os").getpid(),
                        binary, idb_path, backend="gui",
                        session_id=f"gui-{binary}",
                    )
                    self._discovery_port = port
                    print(f"  Registered GUI instance in discovery (:{port})")
                except Exception as e:
                    print(f"[MCP] discovery register failed (non-fatal): {e}")
                # Ensure a single SHARED idalib supervisor is running so this
                # (and any other) open IDA is adoptable and parallel headless
                # copies can be spawned — all through one MCP endpoint.
                self._maybe_launch_supervisor()
                return
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    port += 1
                else:
                    # Clean up any stale connection file from a previous run.
                    remove_connection_file()
                    raise
        # No port was available: ensure no stale connection file is left behind.
        remove_connection_file()
        print(f"[MCP] Error: No available port in range {self.port}-{max_port - 1}")

    def run(self, arg):
        # Manual (re)start via Ctrl+Alt+M / Edit -> Plugins -> MCP.
        self._start_server()

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        self._deregister_discovery()
        if self.mcp:
            self.mcp.stop()
            self.mcp = None
            self._remove_connection_file()


def PLUGIN_ENTRY():
    return MCP()


