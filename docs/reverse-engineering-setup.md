# Automated RE with Cursor + MCP (radare2, Frida, AI)

OSS-Sensor exposes an **MCP (Model Context Protocol) server** so Cursor’s AI can drive the full reverse-engineering pipeline: queue, diffs, reports, pipeline steps, **radare2** analysis, and **Frida** tracing. You can automate each step from chat.

## What the agent can do

- **Queue and diffs:** `get_queue`, `get_diff`, `get_reports` to inspect the prioritized queue and evidence.
- **Pipeline steps:** `run_pipeline_step` to run `ingest_source`, `ingest_binary`, `ingest_logs`, `diff`, `score`, or `report` with the right arguments.
- **radare2:** `r2_analyze` (symbols, imports, disasm at address/symbol, function list/summary) and `r2_extract_features` for real binary features (replacing stubs when r2 is installed).
- **Frida:** `frida_run_script` to run a Frida script against a process, and `frida_trace_export` to generate/run a trace script for symbols (e.g. from `ReverseContextReport.probable_entry_points`).

Typical automation flow: **get_queue → pick diff_id → get_diff + get_reports → r2_analyze on the binary path from the diff → frida_trace_export for entry points (if the target is runnable) → summarize or suggest next step.**

## Install

1. **Backend with MCP** (required for Cursor):
   ```bash
   cd backend
   uv sync   # or: pip install -e .
   ```
   The `mcp` package is a main dependency; the server runs without r2/Frida (those tools will return a message to install the optional extra).

2. **Optional: radare2 + Frida** (for `r2_*` and `frida_*` tools):
   ```bash
   cd backend
   uv sync --extra reverse   # or: pip install -e ".[reverse]"
   ```
   You also need **radare2** on your PATH (`brew install radare2`). Frida targets a running process (simulator/device or local binary).

## Cursor MCP configuration

Add the OSS-Sensor MCP server so Cursor’s agent can call the tools.

### Option A: Project config (recommended)

Create or edit **`.cursor/mcp.json`** in the repo root:

```json
{
  "mcpServers": {
    "oss-sensor": {
      "command": "python",
      "args": ["-m", "oss_sensor.mcp"],
      "cwd": "${workspaceFolder}/backend",
      "env": {}
    }
  }
}
```

- **cwd** must be the `backend` directory so `oss_sensor` is importable and the default `data/` DB path works.
- To use a venv: set `"command": "${workspaceFolder}/backend/.venv/bin/python"` (or the path to your venv’s Python).

### Option B: Cursor Settings (Tools & MCP)

1. Open **Cursor Settings** (Cmd+, / Ctrl+,) → **Tools & MCP**.
2. **Add new MCP server**.
3. **Name:** `oss-sensor`.
4. **Type:** `command`.
5. **Command:** path to Python that has `oss_sensor` installed, e.g. `backend/.venv/bin/python`.
6. **Arguments:** `-m oss_sensor.mcp`.
7. **Working directory:** path to the repo’s `backend` folder (e.g. `backend` or full path).

Restart Cursor after changing MCP config so the server is loaded.

## Environment

- **DATABASE_URL:** Default is `sqlite+aiosqlite:///./data/oss_sensor.db` (relative to `cwd`, i.e. `backend/`). Set if you use another DB.
- **LLM_***:** Optional; only needed if you run `report` with `with_llm=True` for enriched reports.

## Safety and Frida

- **Frida** attaches to or spawns real processes. Use only against targets you are authorized to analyze.
- **frida_trace_export** has a `dry_run` option that only returns the generated script without executing it.
- MCP tool descriptions state that Frida requires a running target (or `spawn=True`).

## Summary of MCP tools

| Tool | Purpose |
|------|--------|
| `get_queue` | Ranked queue; optional filters (component, state, min_score, build_from, build_to). |
| `get_diff` | Full diff by `diff_id`: evidence bundle, score, state, notes. |
| `get_reports` | All reports for a `diff_id`: triage, reverse_context, vuln_hypotheses, fuzz_plan, telemetry. |
| `run_pipeline_step` | Run one step: ingest_source, ingest_binary, ingest_logs, diff, score, report (with required args per step). |
| `r2_analyze` | radare2 on a binary: action = symbols \| imports \| function_list \| disasm_at \| function_summary; optional target. |
| `r2_extract_features` | Extract symbols/imports/strings via r2 (EvidenceBundle-compatible). |
| `frida_run_script` | Run a Frida script against target (process name or PID); optional script_path, timeout, spawn. |
| `frida_trace_export` | Generate/run Frida trace for symbols (e.g. from reverse_context report); optional dry_run, spawn. |
