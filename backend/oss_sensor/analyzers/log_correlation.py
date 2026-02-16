"""Log correlation: extract message templates, match to binary strings."""

import re
from pathlib import Path
from typing import Any

from oss_sensor.models import LogTemplate


def extract_log_templates(log_dir: Path) -> list[LogTemplate]:
    """
    Extract message templates from logarchive or crash dir.
    Synthetic: look for format-string-like lines; production would parse os_log content.
    """
    templates: list[LogTemplate] = []
    seen: set[str] = set()
    if not log_dir.exists():
        return templates
    for p in log_dir.rglob("*"):
        if not p.is_file():
            continue
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        # Simple template: lines with %@, %d, %s, %u etc.
        for line in text.splitlines()[:500]:
            if "%" in line and re.search(r"%[@dDsSuUxXfF]", line):
                # Normalize to template
                tpl = re.sub(r"%[@dDsSuUxXfF]", "%@", line)
                tpl = re.sub(r"\s+", " ", tpl).strip()
                if len(tpl) < 200 and tpl not in seen:
                    seen.add(tpl)
                    tid = f"tpl_{abs(hash(tpl)) % 10**8}"
                    templates.append(
                        LogTemplate(
                            template_id=tid,
                            subsystem="default",
                            category="default",
                            format_string=tpl,
                            sample_messages=[line.strip()[:200]],
                        )
                    )
        # Also treat unique short lines as potential templates
        for line in text.splitlines()[:200]:
            line = line.strip()
            if 10 < len(line) < 120 and " " in line and line not in seen:
                seen.add(line)
                tid = f"tpl_{abs(hash(line)) % 10**8}"
                templates.append(
                    LogTemplate(
                        template_id=tid,
                        subsystem="default",
                        category="default",
                        format_string=line,
                        sample_messages=[line[:200]],
                    )
                )
    return templates[:100]


def correlate_log_to_binary(
    templates: list[LogTemplate],
    binary_strings: list[str],
) -> list[tuple[str, str]]:
    """Match log template format strings (or samples) to binary string table. Returns (template_id, string)."""
    pairs: list[tuple[str, str]] = []
    str_set = set(binary_strings)
    for t in templates:
        for s in (t.format_string, *t.sample_messages):
            if s in str_set:
                pairs.append((t.template_id, s))
                break
            # Substring match
            for b in binary_strings:
                if s[:50] in b or b in s:
                    pairs.append((t.template_id, b))
                    break
    return pairs
