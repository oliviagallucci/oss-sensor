# OSS-Sensor

TLDR: OSS-Sensor is a local-first platform that operationalizes Apple partial open source, binaries, and unified logs into a prioritized vulnerability research queue. The mental model is: diff → hypothesis → harness with tight evidence provenance and low hallucination risk.

Local-first platform that turns **Apple partial open source + binaries + unified logs** into a **prioritized vulnerability research queue**. You get: what changed, why it looks security-relevant, and what to reverse or fuzz—with every claim tied to evidence IDs (avoids hallucination).

**Mental model:** diff → hypothesis → harness.

---

## Quick start (get it working in a few minutes)

### What you need

- **Python 3.10+** and **Node 18+** (and `npm`). Install from [python.org](https://www.python.org/), [nodejs.org](https://nodejs.org/), or e.g. `brew install python@3.11 node`.

### One-time setup

From the repo root:

```bash
chmod +x setup.sh
./setup.sh --demo
```

This will:

1. Create a Python venv (`.venv`) and install the backend and all deps (including `greenlet` for the DB).
2. Run `npm install` in the frontend.
3. Run the **demo pipeline** so the queue already has one diff (B1→B2 for `syslogd`).

No need to `cd backend` or use `make install-*` manually—the script does it.

### Run the app

In **two terminals** (from the repo root, with the venv activated in both if you like):

```bash
source .venv/bin/activate   # optional but recommended
make serve-api              # Terminal 1 → http://localhost:8000
make serve-frontend         # Terminal 2 → http://localhost:3000
```

Open **http://localhost:3000**: you’ll see the Queue and can open a diff to see evidence, score, reports, and fuzz plan.

---

## How it works (high level)

1. **You give it two “builds” (e.g. old vs new).** For each build you can ingest:
   - **Source** (OSS tarball or repo) → diffed later.
   - **Binaries** (e.g. Mach-Os) → strings, symbols, imports extracted.
   - **Logs** (logarchive/crash dir) → message templates extracted and matched to binary strings.

2. **You run a diff** for a component (e.g. `syslogd`). The pipeline:
   - Builds **source diffs** and extracts features (alloc math, bounds checks, parsing, privilege).
   - Builds a **binary diff** (stub: by symbol name; interface ready for e.g. Diaphora).
   - Correlates **log templates** to binary strings.
   - Stores an **evidence bundle** (hunks, features, refs) and creates a **queue item**.

3. **Scoring** runs on that diff: total score + **reasons**, each with **evidence_refs** pointing at hunks/strings/symbols/templates. Deterministic and reproducible (no LLM required).

4. **Reports** are generated from that evidence: triage, reverse context, vuln hypotheses, **fuzz plan**, telemetry recommendations. All cite artifact/evidence IDs only. Optional LLM can enrich when configured.

5. **API + UI** let you browse the ranked queue, open a diff, see the evidence and reports, and triage (state + notes).

So: **ingest → diff → score → report**; then use the queue and diff views to decide what to reverse or fuzz. The demo uses synthetic fixtures (no Apple IP) so you can run it end-to-end immediately.

---

## Commands you’ll use

After setup, from repo root with venv activated:

| Goal | Command |
|------|--------|
| Load demo data (if you didn’t use `./setup.sh --demo`) | `make demo` |
| Start API | `make serve-api` |
| Start UI | `make serve-frontend` |
| Run tests | `make test` |

CLI (run from repo root so paths are simple; backend runs via `.venv` or `python -m`):

```bash
source .venv/bin/activate
cd backend
python -m oss_sensor.cli ingest-source --build-id B1 --component xnu ../demo/fixtures/source_b1
python -m oss_sensor.cli ingest-binary --build-id B1 --component syslogd ../demo/fixtures/binary_b1
python -m oss_sensor.cli ingest-logs --build-id B1 ../demo/fixtures/logs_b1
# … same for B2, then:
python -m oss_sensor.cli diff --from B1 --to B2 --component syslogd
python -m oss_sensor.cli score --diff-id 1
python -m oss_sensor.cli report --diff-id 1
```

`--component` is a label you choose (e.g. `xnu`, `syslogd`, `launchd`). The diff uses whatever you ingested for that component and the two build IDs.

---

## Project layout

```
oss-sensor/
├── setup.sh           # One-shot install + optional demo
├── Makefile           # serve-api, serve-frontend, demo, test
├── backend/           # Python (FastAPI + CLI + analyzers + scoring)
├── frontend/          # React + Vite (queue + diff views)
├── demo/fixtures/     # Synthetic B1/B2 source, binary, logs (no Apple IP)
└── docs/
    └── architecture.md
```

---

## Configuration

- **STORAGE_MODE**: `derived_features_only` (default) or `full_source_internal`.
- **LLM_PROVIDER** / **LLM_API_KEY**: leave unset for rules-only; set for optional report enrichment.
- **DATABASE_URL**: default `sqlite+aiosqlite:///./data/oss_sensor.db` (relative to process CWD; `data/` is created automatically).

---

## Docker

```bash
docker compose up --build
```

API: http://localhost:8000  
UI: http://localhost:3000 (proxies `/api` to the API).

---

## Design doc

[docs/architecture.md](docs/architecture.md) — components, data model, and workflow in detail.

---

## License

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0). See [LICENSE](LICENSE) for the full text.
