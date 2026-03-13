"""Frida script runner and trace helper. Optional dependency."""

from pathlib import Path
from typing import Any

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    frida = None  # type: ignore


def frida_run_script(
    script_content: str,
    target: str,
    *,
    script_path: str | Path | None = None,
    timeout_seconds: int = 30,
    spawn: bool = False,
) -> dict[str, Any]:
    """
    Run a Frida script against target (process name or PID).
    script_content: JS source. script_path: optional path to script file (if set, script_content can be empty).
    Returns dict with output, error, and success flag.
    Requires a running target (device/simulator or local process); use spawn=True to spawn by name.
    """
    if not FRIDA_AVAILABLE:
        return {
            "success": False,
            "output": "",
            "error": "frida is not installed. Install with: pip install -e '.[reverse]'",
        }
    script = script_content.strip()
    if script_path:
        path = Path(script_path)
        if path.exists():
            script = path.read_text()
    if not script:
        return {"success": False, "output": "", "error": "No script content or valid script_path"}
    output: list[str] = []
    try:
        if target.isdigit():
            session = frida.attach(int(target))
        else:
            if spawn:
                session = frida.spawn([target])
                session.resume()
            else:
                session = frida.attach(target)
        script_obj = session.create_script(script)

        def on_message(message: Any, data: Any) -> None:
            if message.get("type") == "send":
                output.append(message.get("payload", ""))
            elif message.get("type") == "error":
                output.append(f"[error] {message.get('stack', message)}")

        script_obj.on("message", on_message)
        script_obj.load()
        import time
        time.sleep(timeout_seconds)
        session.detach()
        return {"success": True, "output": "\n".join(output), "error": ""}
    except frida.ProcessNotFoundError:
        return {
            "success": False,
            "output": "",
            "error": f"Process not found: {target}. Ensure the target is running or use spawn=True.",
        }
    except Exception as e:
        return {"success": False, "output": "\n".join(output), "error": str(e)}


def frida_trace_script_for_symbols(
    symbols: list[str],
    *,
    module_name: str | None = None,
    include_args: bool = True,
) -> str:
    """
    Generate a Frida script that hooks the given symbols and logs calls/return.
    symbols: list of symbol names (e.g. from ReverseContextReport probable_entry_points).
    module_name: if set, resolve symbols in that module; otherwise use Process.getModuleByAddress.
    include_args: log first few arguments.
    """
    mod = f"module_name = {repr(module_name)};" if module_name else "module_name = null;"
    syms_json = repr(symbols)
    return f"""
{mod}
var symbols = {syms_json};
var includeArgs = {str(include_args).lower()};

function hookSymbol(addr, name) {{
  try {{
    Interceptor.attach(addr, {{
      onEnter: function(args) {{
        var msg = "[enter] " + name;
        if (includeArgs) {{
          msg += " args=" + [args[0], args[1], args[2]].map(function(a) {{ return a ? a.toString() : ''; }}).join(", ");
        }}
        send(msg);
      }},
      onLeave: function(retval) {{
        send("[leave] " + name + " ret=" + (retval ? retval.toString() : ""));
      }}
    }});
    send("[hooked] " + name + " @ " + addr);
  }} catch (e) {{
    send("[hook failed] " + name + " " + e);
  }}
}}

Process.enumerateModules().forEach(function(m) {{
  if (module_name && m.name !== module_name) return;
  symbols.forEach(function(symName) {{
    var addr = Module.findExportByName(m.name, symName);
    if (!addr) addr = Module.findExportByName(m.name, "_" + symName);
    if (addr) hookSymbol(addr, symName);
  }});
}});
send("[trace] ready for " + symbols.length + " symbols");
"""


def frida_run_trace(
    target: str,
    symbols: list[str],
    *,
    module_name: str | None = None,
    timeout_seconds: int = 15,
    spawn: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Generate and run a Frida trace script for the given symbols (e.g. from ReverseContextReport).
    Returns trace output or, if dry_run=True, only the generated script text.
    spawn: spawn process by name instead of attach.
    """
    if not FRIDA_AVAILABLE:
        return {
            "success": False,
            "output": "",
            "error": "frida is not installed. Install with: pip install -e '.[reverse]'",
            "script": "",
        }
    script = frida_trace_script_for_symbols(symbols, module_name=module_name)
    if dry_run:
        return {"success": True, "output": "", "error": "", "script": script}
    out = frida_run_script(
        script, target, timeout_seconds=timeout_seconds, spawn=spawn
    )
    out["script"] = script
    return out
