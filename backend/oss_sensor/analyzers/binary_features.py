"""Binary feature extraction: strings, imports, symbols, ObjC metadata (deterministic)."""

import re
from pathlib import Path
from typing import Any

from oss_sensor.models import BinaryFeature


def _read_strings(path: Path, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary (simplified; production: use 'strings' or lief)."""
    data = path.read_bytes()
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    return [m.decode("ascii", errors="replace") for m in pattern.findall(data)]


def _fake_imports(path: Path) -> list[str]:
    """Stub: return placeholder imports; production would use otool -L / parse Mach-O."""
    return [
        "/usr/lib/libSystem.B.dylib",
        "/usr/lib/libobjc.A.dylib",
    ]


def _fake_symbols(path: Path) -> list[str]:
    """Stub: return placeholder symbols; production would use nm or dyld info."""
    return [
        "_main",
        "_malloc",
        "_free",
    ]


def _fake_objc(path: Path) -> dict[str, Any]:
    """Stub: ObjC metadata if present; production would use class-dump or otool -ov."""
    return {}


def extract_binary_features(macho_dir: Path) -> dict[str, Any]:
    """
    Extract deterministic features from Mach-O(s) in directory.
    Returns dict suitable for storage: strings, imports, symbols, objc_metadata.
    All entries are lists or dicts keyed by file name for multi-binary dirs.
    """
    result: dict[str, Any] = {
        "strings": [],
        "imports": [],
        "symbols": [],
        "objc_metadata": {},
    }
    files = list(macho_dir.iterdir()) if macho_dir.is_dir() else [macho_dir]
    for p in files:
        if not p.is_file():
            continue
        try:
            raw = p.read_bytes()[:4]
            # Mach-O magic
            if raw in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
                result["strings"].extend(_read_strings(p))
                result["imports"].extend(_fake_imports(p))
                result["symbols"].extend(_fake_symbols(p))
                objc = _fake_objc(p)
                if objc:
                    result["objc_metadata"][p.name] = objc
        except Exception:
            pass
    result["strings"] = list(dict.fromkeys(result["strings"]))[:2000]  # dedupe, cap
    result["imports"] = list(dict.fromkeys(result["imports"]))
    result["symbols"] = list(dict.fromkeys(result["symbols"]))
    return result


def features_to_list(features_dict: dict[str, Any], artifact_id: str) -> list[BinaryFeature]:
    """Convert stored features dict to list of BinaryFeature for evidence bundle."""
    out: list[BinaryFeature] = []
    for s in features_dict.get("strings", [])[:500]:
        out.append(
            BinaryFeature(
                feature_type="strings",
                value=s,
                address=None,
                source_file=None,
            )
        )
    for imp in features_dict.get("imports", []):
        out.append(
            BinaryFeature(
                feature_type="imports",
                value=imp,
                address=None,
                source_file=None,
            )
        )
    for sym in features_dict.get("symbols", []):
        out.append(
            BinaryFeature(
                feature_type="symbols",
                value=sym,
                address=None,
                source_file=None,
            )
        )
    for name, meta in features_dict.get("objc_metadata", {}).items():
        out.append(
            BinaryFeature(
                feature_type="objc_metadata",
                value=str(meta),
                address=None,
                source_file=name,
            )
        )
    return out
