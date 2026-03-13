#!/usr/bin/env bash
# OSS-Sensor setup: install tools and deps so you can run the demo and app immediately.
# Usage: ./setup.sh [--demo] [--mcp] [--reverse]
#   --demo    Also run the demo pipeline (ingest + diff + score + report).
#   --mcp     Configure Cursor MCP (.cursor/mcp.json) so the AI can use queue/diff/reports and pipeline tools.
#   --reverse Install radare2/Frida Python deps (r2_analyze, frida_run_script, etc.); optional radare2 on PATH.

set -e
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SELF_DIR"
RUN_DEMO=false
RUN_MCP=false
RUN_REVERSE=false
for arg in "$@"; do
  [ "$arg" = "--demo" ] && RUN_DEMO=true
  [ "$arg" = "--mcp" ] && RUN_MCP=true
  [ "$arg" = "--reverse" ] && RUN_REVERSE=true
done

echo "=== OSS-Sensor setup ==="

# --- Check Python ---
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Install Python 3.10+ (e.g. from python.org or brew install python@3.11)."
  exit 1
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "  Python: $(python3 --version)"

# --- Check Node ---
if ! command -v npm &>/dev/null; then
  echo "ERROR: npm not found. Install Node.js 18+ (e.g. from nodejs.org or brew install node)."
  exit 1
fi
echo "  Node:   $(node --version) ($(npm --version))"

# --- Backend: venv + install ---
echo ""
echo "--- Backend ---"
if [ ! -d ".venv" ]; then
  echo "  Creating .venv ..."
  python3 -m venv .venv
fi
echo "  Installing backend (oss-sensor + deps) ..."
if [ "$RUN_REVERSE" = true ]; then
  .venv/bin/pip install -q -e "backend/.[dev,reverse]"
else
  .venv/bin/pip install -q -e "backend/.[dev]"
fi
echo "  Backend OK."

# --- Cursor MCP config (optional) ---
if [ "$RUN_MCP" = true ]; then
  mkdir -p .cursor
  cat > .cursor/mcp.json << 'MCPEOF'
{
  "mcpServers": {
    "oss-sensor": {
      "command": "../.venv/bin/python",
      "args": ["-m", "oss_sensor.mcp"],
      "cwd": "backend"
    }
  }
}
MCPEOF
  echo "  Cursor MCP: .cursor/mcp.json configured."
fi

# --- Frontend: npm install ---
echo ""
echo "--- Frontend ---"
echo "  Installing frontend deps ..."
(cd frontend && npm install --no-audit --no-fund)
echo "  Frontend OK."

# --- Demo (optional) ---
# Run CLI from backend/ so DB is backend/data/ and matches make serve-api.
if [ "$RUN_DEMO" = true ]; then
  echo ""
  echo "--- Demo pipeline ---"
  (cd backend && ../.venv/bin/python -m oss_sensor.cli ingest-source --build-id B1 --component xnu ../demo/fixtures/source_b1)
  (cd backend && ../.venv/bin/python -m oss_sensor.cli ingest-source --build-id B2 --component xnu ../demo/fixtures/source_b2)
  (cd backend && ../.venv/bin/python -m oss_sensor.cli ingest-binary --build-id B1 --component syslogd ../demo/fixtures/binary_b1)
  (cd backend && ../.venv/bin/python -m oss_sensor.cli ingest-binary --build-id B2 --component syslogd ../demo/fixtures/binary_b2)
  (cd backend && ../.venv/bin/python -m oss_sensor.cli ingest-logs --build-id B1 ../demo/fixtures/logs_b1)
  (cd backend && ../.venv/bin/python -m oss_sensor.cli ingest-logs --build-id B2 ../demo/fixtures/logs_b2)
  (cd backend && ../.venv/bin/python -m oss_sensor.cli diff --from B1 --to B2 --component syslogd)
  (cd backend && ../.venv/bin/python -m oss_sensor.cli score --diff-id 1)
  (cd backend && ../.venv/bin/python -m oss_sensor.cli report --diff-id 1)
  echo "  Demo OK (queue has one diff)."
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Activate the venv and run the app:"
echo "  source .venv/bin/activate"
echo "  make serve-api      # terminal 1: API on http://localhost:8000"
echo "  make serve-frontend # terminal 2: UI  on http://localhost:3000"
echo ""
if [ "$RUN_MCP" = true ]; then
  echo "Cursor MCP: .cursor/mcp.json configured. Restart Cursor to use the RE tools."
  echo ""
fi
if [ "$RUN_REVERSE" = true ] && ! command -v r2 &>/dev/null && ! command -v radare2 &>/dev/null; then
  echo "Optional: install radare2 for r2_analyze (e.g. brew install radare2)."
  echo ""
fi
if [ "$RUN_DEMO" = false ]; then
  echo "To load the demo data, run:  ./setup.sh --demo"
  echo ""
fi
echo "See README.md for CLI usage and how it works."
