#!/usr/bin/env bash
# OSS-Sensor setup: install tools and deps so you can run the demo and app immediately.
# Usage: ./setup.sh [--demo]
#   --demo  Also run the demo pipeline (ingest + diff + score + report).

set -e
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SELF_DIR"
RUN_DEMO=false
for arg in "$@"; do
  [ "$arg" = "--demo" ] && RUN_DEMO=true
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
.venv/bin/pip install -q -e "backend/.[dev]"
echo "  Backend OK."

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
if [ "$RUN_DEMO" = false ]; then
  echo "To load the demo data, run:  ./setup.sh --demo"
  echo ""
fi
echo "See README.md for CLI usage and how it works."
