"""Optional radare2-backed binary feature extraction. Used when r2 and r2pipe are available."""

from pathlib import Path
from typing import Any

# Lazy import so backend works without [reverse] deps
def _r2_available() -> bool:
    try:
        import r2pipe  # noqa: F401
        return True
    except ImportError:
        return False


def extract_binary_features_r2(macho_path: Path) -> dict[str, Any] | None:
    """
    Extract binary features using radare2 (r2pipe). Returns same shape as
    binary_features.extract_binary_features, or None if r2/r2pipe unavailable or on error.
    """
    if not _r2_available():
        return None
    try:
        import r2pipe
    except ImportError:
        return None

    if not macho_path.is_file():
        return None
    try:
        raw = macho_path.read_bytes()[:4]
        if raw not in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
            return None
    except Exception:
        return None

    result: dict[str, Any] = {
        "strings": [],
        "imports": [],
        "symbols": [],
        "objc_metadata": {},
    }
    try:
        r2 = r2pipe.open(str(macho_path), flags=["-2"])  # -2: disable stderr
        # Minimal analysis so afl has something (avoid full aaa for speed)
        r2.cmd("e bin.cache=true")
        r2.cmd("aaa")  # analyze; can be slow on large bins

        # Strings (izzj)
        izz = r2.cmdj("izzj")
        if isinstance(izz, list):
            for item in izz[:1500]:
                if isinstance(item, dict) and "string" in item:
                    s = item["string"]
                    if isinstance(s, bytes):
                        try:
                            s = s.decode("utf-8", errors="replace")
                        except Exception:
                            continue
                    if isinstance(s, str) and len(s) >= 6 and all(c.isprintable() or c in "\n\r\t" for c in s):
                        result["strings"].append(s)

        # Imports (iij)
        ii = r2.cmdj("iij")
        if isinstance(ii, list):
            for item in ii[:500]:
                if isinstance(item, dict) and "name" in item:
                    result["imports"].append(str(item["name"]))

        # Symbols (isj)
        isj = r2.cmdj("isj")
        if isinstance(isj, list):
            for item in isj[:500]:
                if isinstance(item, dict) and "name" in item:
                    result["symbols"].append(str(item["name"]))

        # Functions (aflj) - add as symbols with address for diffing
        afl = r2.cmdj("aflj")
        if isinstance(afl, list):
            for item in afl[:1000]:
                if isinstance(item, dict) and "name" in item:
                    name = str(item["name"])
                    if name and not name.startswith("fcn."):  # skip unnamed
                        result["symbols"].append(name)

        r2.quit()
    except Exception:
        return None

    result["strings"] = list(dict.fromkeys(result["strings"]))[:2000]
    result["imports"] = list(dict.fromkeys(result["imports"]))
    result["symbols"] = list(dict.fromkeys(result["symbols"]))
    return result
