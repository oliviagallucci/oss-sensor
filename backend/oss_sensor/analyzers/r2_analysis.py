"""radare2 analysis via r2pipe: symbols, imports, disassembly. Optional dependency."""

from pathlib import Path
from typing import Any

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False
    r2pipe = None  # type: ignore


def _open_r2(binary_path: str | Path) -> Any:
    if not R2_AVAILABLE:
        raise RuntimeError("r2pipe is not installed. Install with: pip install -e '.[reverse]'")
    path = Path(binary_path)
    if not path.exists():
        raise FileNotFoundError(f"Binary not found: {path}")
    return r2pipe.open(str(path.resolve()))


def r2_symbols(binary_path: str | Path) -> list[dict[str, Any]]:
    """Return list of symbols from binary (name, address, type). Uses r2 isj/is."""
    r = _open_r2(binary_path)
    try:
        r.cmd("aaa")  # analyze
        data = r.cmdj("isj")
        if not data:
            return []
        out: list[dict[str, Any]] = []
        for ent in data if isinstance(data, list) else [data]:
            if isinstance(ent, dict):
                out.append({
                    "name": ent.get("name", ""),
                    "vaddr": ent.get("vaddr"),
                    "type": ent.get("type", ""),
                })
        return out[:2000]
    finally:
        r.quit()


def r2_imports(binary_path: str | Path) -> list[dict[str, Any]]:
    """Return list of imports (name, ordinal, plt). Uses r2 iij."""
    r = _open_r2(binary_path)
    try:
        r.cmd("aaa")
        data = r.cmdj("iij")
        if not data:
            return []
        out: list[dict[str, Any]] = []
        for ent in (data if isinstance(data, list) else [data]):
            if isinstance(ent, dict):
                out.append({
                    "name": ent.get("name", ""),
                    "ordinal": ent.get("ordinal"),
                    "plt": ent.get("plt"),
                })
        return out
    finally:
        r.quit()


def r2_disasm_at(binary_path: str | Path, address_or_symbol: str) -> str:
    """Disassemble at given address or symbol name. Returns text (pdf at that location)."""
    r = _open_r2(binary_path)
    try:
        r.cmd("aaa")
        return r.cmd(f"pd 50 @ {address_or_symbol}") or ""
    finally:
        r.quit()


def r2_function_disasm(binary_path: str | Path, symbol_or_address: str) -> str:
    """Disassemble full function at symbol or address (pdf)."""
    r = _open_r2(binary_path)
    try:
        r.cmd("aaa")
        return r.cmd(f"pdf @ {symbol_or_address}") or ""
    finally:
        r.quit()


def r2_function_list(binary_path: str | Path) -> list[dict[str, Any]]:
    """List functions (name, offset, size). Uses r2 aflj."""
    r = _open_r2(binary_path)
    try:
        r.cmd("aaa")
        data = r.cmdj("aflj")
        if not data:
            return []
        out: list[dict[str, Any]] = []
        for ent in (data if isinstance(data, list) else [data]):
            if isinstance(ent, dict):
                out.append({
                    "name": ent.get("name", ""),
                    "offset": ent.get("offset"),
                    "size": ent.get("size"),
                })
        return out[:500]
    finally:
        r.quit()


def r2_extract_features(binary_path: str | Path) -> dict[str, Any]:
    """
    Extract binary features via r2 suitable for EvidenceBundle / binary_features.
    Returns dict with keys: strings (from r2 if available), imports, symbols;
    compatible with features_to_list() when converted.
    """
    if not R2_AVAILABLE:
        return {"strings": [], "imports": [], "symbols": [], "objc_metadata": {}}
    path = Path(binary_path)
    if not path.exists():
        return {"strings": [], "imports": [], "symbols": [], "objc_metadata": {}}
    r = _open_r2(binary_path)
    try:
        r.cmd("aaa")
        result: dict[str, Any] = {
            "strings": [],
            "imports": [],
            "symbols": [],
            "objc_metadata": {},
        }
        syms_j = r.cmdj("isj")
        if syms_j:
            for s in (syms_j if isinstance(syms_j, list) else [syms_j]):
                if isinstance(s, dict) and s.get("name"):
                    result["symbols"].append(s["name"])
        imps_j = r.cmdj("iij")
        if imps_j:
            for i in (imps_j if isinstance(imps_j, list) else [imps_j]):
                if isinstance(i, dict) and i.get("name"):
                    result["imports"].append(i["name"])
        izj = r.cmdj("izj")
        if izj:
            for z in (izj if isinstance(izj, list) else [izj]):
                if isinstance(z, dict) and z.get("string"):
                    result["strings"].append(z["string"])
        if not result["strings"]:
            rax = r.cmd("izz")
            if rax:
                for line in rax.split("\n"):
                    if "string" in line.lower():
                        parts = line.split()
                        for p in parts:
                            if (p.startswith("'") or p.startswith('"')) and len(p) > 2:
                                result["strings"].append(p.strip("'\""))
        result["strings"] = list(dict.fromkeys(result["strings"]))[:2000]
        result["imports"] = list(dict.fromkeys(result["imports"]))
        result["symbols"] = list(dict.fromkeys(result["symbols"]))
        return result
    finally:
        r.quit()


def r2_analyze(
    binary_path: str | Path,
    action: str,
    target: str | None = None,
) -> str | dict[str, Any]:
    """
    High-level r2 analysis. action: symbols, imports, disasm_at, function_summary, function_list.
    For disasm_at and function_summary, pass target (address or symbol).
    """
    path = Path(binary_path)
    if not path.exists():
        return f"Error: binary not found: {path}"
    if not R2_AVAILABLE:
        return "Error: r2pipe not installed. Install with: pip install -e '.[reverse]'"
    try:
        if action == "symbols":
            return {"symbols": r2_symbols(binary_path)}
        if action == "imports":
            return {"imports": r2_imports(binary_path)}
        if action == "function_list":
            return {"functions": r2_function_list(binary_path)}
        if action == "disasm_at" and target:
            return {"disasm": r2_disasm_at(binary_path, target)}
        if action == "function_summary" and target:
            return {"disasm": r2_function_disasm(binary_path, target)}
        return f"Unknown action or missing target: action={action!r}, target={target!r}"
    except Exception as e:
        return f"Error: {e}"
