.PHONY: all build up down test lint demo quickstart clean install-backend install-frontend

# Default: build and run tests
all: install-backend install-frontend test

# --- Backend ---
install-backend:
	cd backend && python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

install-frontend:
	cd frontend && npm install

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

# --- Tests ---
test: test-backend test-frontend

test-backend:
	cd backend && python -m pytest tests/ -v --tb=short

test-frontend:
	cd frontend && npm run test -- --run

# --- Lint ---
lint: lint-backend lint-frontend

lint-backend:
	cd backend && ruff check . && mypy oss_sensor --ignore-missing-imports

lint-frontend:
	cd frontend && npm run lint

# --- Demo: run full pipeline with fixtures (run from repo root with venv activated) ---
# Uses python3 from PATH so your activated .venv is used; requires greenlet (pip install -e ".[dev]" in backend).
DEMO_FIXTURES = ../demo/fixtures
demo:
	cd backend && python3 -m oss_sensor.cli ingest-source --build-id B1 --component xnu $(DEMO_FIXTURES)/source_b1
	cd backend && python3 -m oss_sensor.cli ingest-source --build-id B2 --component xnu $(DEMO_FIXTURES)/source_b2
	cd backend && python3 -m oss_sensor.cli ingest-binary --build-id B1 --component syslogd $(DEMO_FIXTURES)/binary_b1
	cd backend && python3 -m oss_sensor.cli ingest-binary --build-id B2 --component syslogd $(DEMO_FIXTURES)/binary_b2
	cd backend && python3 -m oss_sensor.cli ingest-logs --build-id B1 $(DEMO_FIXTURES)/logs_b1
	cd backend && python3 -m oss_sensor.cli ingest-logs --build-id B2 $(DEMO_FIXTURES)/logs_b2
	cd backend && python3 -m oss_sensor.cli diff --from B1 --to B2 --component syslogd
	cd backend && python3 -m oss_sensor.cli score --diff-id 1
	cd backend && python3 -m oss_sensor.cli report --diff-id 1
	@echo "Demo complete. Run 'make serve-api' and 'make serve-frontend' then open http://localhost:3000"

# --- Quickstart: API + frontend (local dev) ---
serve-api:
	cd backend && uvicorn oss_sensor.main:app --reload --host 0.0.0.0 --port 8000

serve-frontend:
	cd frontend && npm run dev

quickstart: demo serve-api serve-frontend

# --- Clean ---
clean:
	rm -rf backend/dist backend/*.egg-info backend/.pytest_cache backend/htmlcov backend/.coverage
	rm -rf frontend/node_modules frontend/dist
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
