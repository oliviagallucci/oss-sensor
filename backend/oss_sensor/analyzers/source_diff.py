"""Source diff extraction and deterministic feature extraction (alloc math, bounds, parsing, privilege)."""

import re
import hashlib
from pathlib import Path
from typing import Iterator

from oss_sensor.models import DiffHunk, SourceFeature


def _normalize_line(line: str) -> str:
    return line.rstrip("\n")


def _hunk_id(file_path: str, old_start: int, new_start: int, lines: list[str]) -> str:
    content = f"{file_path}:{old_start}:{new_start}:" + "|".join(lines[:5])
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def parse_unified_hunks(
    from_dir: Path,
    to_dir: Path,
    file_pairs: list[tuple[Path, Path]],
) -> list[DiffHunk]:
    """Produce diff hunks between two directory trees for given file pairs.
    Uses simple line-by-line diff; in production could use difflib.unified_diff.
    """
    hunks: list[DiffHunk] = []
    for from_path, to_path in file_pairs:
        from_lines = from_path.read_text().splitlines() if from_path.exists() else []
        to_lines = to_path.read_text().splitlines() if to_path.exists() else []
        # Simple diff: find contiguous blocks of changes
        i, j = 0, 0
        old_start, old_count = 0, 0
        new_start, new_count = 0, 0
        chunk: list[str] = []
        while i < len(from_lines) or j < len(to_lines):
            if i < len(from_lines) and j < len(to_lines) and from_lines[i] == to_lines[j]:
                if chunk:
                    hid = _hunk_id(str(from_path), old_start, new_start, chunk)
                    hunks.append(
                        DiffHunk(
                            file_path=str(from_path.relative_to(from_dir) if from_dir != from_path else from_path.name),
                            old_start=old_start,
                            old_count=old_count,
                            new_start=new_start,
                            new_count=new_count,
                            lines=chunk,
                            hunk_id=hid,
                        )
                    )
                    chunk = []
                i += 1
                j += 1
                continue
            if chunk == []:
                old_start = i + 1
                new_start = j + 1
                old_count = 0
                new_count = 0
            if i < len(from_lines):
                chunk.append("- " + _normalize_line(from_lines[i]))
                old_count += 1
                i += 1
            if j < len(to_lines) and (not chunk or not chunk[-1].startswith("+ ")):
                if chunk and chunk[-1].startswith("- "):
                    pass  # already advanced i
                chunk.append("+ " + _normalize_line(to_lines[j]))
                new_count += 1
                j += 1
        if chunk:
            hid = _hunk_id(str(from_path), old_start, new_start, chunk)
            hunks.append(
                DiffHunk(
                    file_path=str(from_path.relative_to(from_dir) if from_dir != from_path else from_path.name),
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    lines=chunk,
                    hunk_id=hid,
                )
            )
    return hunks


def _iter_lines_in_hunk(hunk: DiffHunk) -> Iterator[str]:
    for line in hunk.lines:
        if line.startswith("+ "):
            yield line[2:]
        elif line.startswith("- "):
            yield line[2:]


# Patterns for deterministic feature detection (rules-only, no LLM)
ALLOC_MATH_PATTERNS = [
    re.compile(r"\b(malloc|calloc|realloc|kalloc|ALLOC)\s*\(\s*[^)]*\*", re.I),
    re.compile(r"size\s*=\s*[^;]*\*", re.I),
    re.compile(r"length\s*\*\s*sizeof", re.I),
    re.compile(r"count\s*\*\s*sizeof", re.I),
]
BOUNDS_CHECK_PATTERNS = [
    re.compile(r"\b(bounds_check|range_check|overflow_check)\b", re.I),
    re.compile(r"if\s*\(\s*\w+\s*[<>]=?\s*", re.I),
    re.compile(r"assert\s*\(\s*[^)]*[<>]", re.I),
]
PARSING_PATTERNS = [
    re.compile(r"\b(parse|deserialize|decode|unpack)\b", re.I),
    re.compile(r"sscanf|fscanf|scanf", re.I),
    re.compile(r"json_|xml_|plist_", re.I),
]
PRIVILEGE_PATTERNS = [
    re.compile(r"\b(entitlement|sandbox|privilege|capability|root_only)\b", re.I),
    re.compile(r"check_entitlement|require_entitlement", re.I),
    re.compile(r"SECURITY_|kauth_", re.I),
]


def extract_source_features(hunks: list[DiffHunk]) -> list[SourceFeature]:
    """Extract deterministic features from diff hunks (alloc math, bounds, parsing, privilege)."""
    features: list[SourceFeature] = []
    for hunk in hunks:
        snippet = "\n".join(hunk.lines[:20])
        line_range = (hunk.old_start, hunk.old_start + hunk.old_count)
        for pattern_list, ftype in [
            (ALLOC_MATH_PATTERNS, "alloc_math"),
            (BOUNDS_CHECK_PATTERNS, "bounds_check"),
            (PARSING_PATTERNS, "parsing"),
            (PRIVILEGE_PATTERNS, "privilege_check"),
        ]:
            for p in pattern_list:
                if p.search(snippet):
                    features.append(
                        SourceFeature(
                            feature_type=ftype,
                            description=f"Pattern match: {ftype}",
                            hunk_id=hunk.hunk_id,
                            file_path=hunk.file_path,
                            line_range=line_range,
                            snippet=snippet[:500],
                        )
                    )
                    break
    return features


def extract_source_diff(
    from_dir: Path,
    to_dir: Path,
    component: str,
) -> tuple[list[DiffHunk], list[SourceFeature]]:
    """
    Extract unified diff hunks between from_dir and to_dir for component,
    then extract deterministic features from those hunks.
    Returns (hunks, source_features); all IDs are stable (hunk_id).
    """
    from_dir = Path(from_dir)
    to_dir = Path(to_dir)
    file_pairs: list[tuple[Path, Path]] = []
    for f in from_dir.rglob("*"):
        if f.is_file() and not f.name.startswith("."):
            rel = f.relative_to(from_dir)
            to_path = to_dir / rel
            file_pairs.append((f, to_path))
    for f in to_dir.rglob("*"):
        if f.is_file() and not f.name.startswith("."):
            rel = f.relative_to(to_dir)
            from_path = from_dir / rel
            if (from_path, f) not in [(a, b) for a, b in file_pairs]:
                file_pairs.append((from_path, f))
    # Dedupe by relative path
    seen: set[str] = set()
    unique_pairs: list[tuple[Path, Path]] = []
    for a, b in file_pairs:
        key = str(a.relative_to(from_dir) if a.is_relative_to(from_dir) else a.name)
        if key not in seen:
            seen.add(key)
            unique_pairs.append((a, b))
    hunks = parse_unified_hunks(from_dir, to_dir, unique_pairs)
    features = extract_source_features(hunks)
    return hunks, features
