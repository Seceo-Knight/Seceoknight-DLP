# Repository Playbook (For AI Coding Agents)

This is the quick-reference checklist for LLMs working in this repo. The source of truth is `.cursorrules`; always cross-check it plus `README.md`, `INSTALLATION_GUIDE.md`, `TESTING_COMMANDS.md`, and `plan.md`.

## Project Structure & Architecture
- `server/app/`: FastAPI backend (API, core, models, services, Google Drive polling/tasks). Tests in `server/tests/`.
- `dashboard/src/`: React/Vite front end (Pages + App routers, shared components, lib/api, types).
- `agents/endpoint/{windows,linux}/`: Endpoint agents (`agent.py`, `agent_config.json`). Shared deps at `agents/requirements.txt`.
- Supporting dirs: `ml/` (models), `config/`, `docs/`, `archive/docs/` for historical notes.
- Platform stack: PostgreSQL (users/policies), MongoDB (events), Redis (sessions + OAuth state + caches), OpenSearch (search/analytics). Google Drive cloud monitoring uses OAuth (credentials in `.env`), Celery workers (`google_drive_polling_tasks`), and per-folder baselines in SQL tables (`google_drive_connections`, `google_drive_protected_folders`).
- Event pipeline: ingestion → `EventProcessor` → `DatabasePolicyEvaluator` → actions stored in Mongo/OpenSearch. Google Drive events flow through `google_drive_event_normalizer.py`.

## Build & Runtime Commands
- Install deps: `make install` (prod) / `make install-dev` (with tooling).
- Tests: `make test`, `make test-backend`, `make test-dashboard`, `make test-fast`, `make test-coverage`.
- Lint/format/type: `make lint`, `make format`, `make type-check`, `npx tsc --noEmit`.
- Containers:
  - Bring up databases first for fresh installs: `docker compose up -d postgres mongodb redis opensearch`
  - Initialize DB: `docker compose run --rm manager python init_db.py`
  - Build/start stack: `docker compose build` then `docker compose up -d`
  - Stop/clean: `docker compose down`
  - Logs: `docker compose logs -f manager`, `docker compose logs dashboard`, etc.
- Restart services quickly: `docker compose restart manager dashboard`.
- Celery (Drive polling) runs in `celery-worker` + `celery-beat`; inspect via `docker compose logs celery-worker`.
- UI caches: if dashboard changes aren’t visible after a normal rebuild, run `docker compose build --no-cache dashboard && docker compose up -d dashboard` to force a clean image.

## Coding Standards
- Python: PEP 8, 4 spaces, type hints everywhere, structured logging via structlog, format with black/isort, lint with flake8.
- TypeScript/React: strict TS, functional components, PascalCase components, camelCase props/funcs, Prettier + ESLint.
- API routes kebab-case; JSON payload keys snake_case. Keep docstrings for public APIs.

## Workflow Expectations
- Maintain `plan.md`: reset/start for each task, list steps, mark ✅ upon completion.
- Google Drive features: follow `INSTALLATION_GUIDE.md` for OAuth client creation (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`). Document baseline behavior and manual refresh endpoints.
- Windows agent edits must be copied to `/mnt/d/SeceoKnightAgent/` for manual validation. Linux agents installed via `agents/endpoint/linux/install.sh`.
- Document every behavior change (`README.md`, `INSTALLATION_GUIDE.md`, `TESTING_COMMANDS.md`, `CHANGELOG.md`, `archive/docs/` as needed).

## Testing Guidance
- Backend: pytest (`server/tests/`), naming `test_*.py`. Frontend: React Testing Library/Jest (`*.test.tsx`). Target coverage ≈87%.
- Use `make test-coverage` for HTML report (`server/htmlcov/index.html`).
- When touching agents/Drive integration: run stack (`make docker-up`), start agent or Drive policy, trigger `/api/v1/health`, verify events on dashboard (use manual refresh button or `POST /api/v1/google-drive/poll`).

## Commits & PRs
- Conventional commits (`feat|fix|chore|docs|test|refactor[:scope]: summary`).
- Before PR: run lint, tests, type checks; call out skips. Provide summary, linked issue, screenshots for UI changes, deployment/credential notes, rollout steps.
- Keep diffs focused; update `plan.md` and relevant docs.

## Security & Config Tips
- Never commit secrets; start from `.env.example`. Keep `credentials.json` out of git. Rotate default creds (admin/changeme123!).
- Sensitive info belongs in env vars. `.secrets.baseline` is enforced.
- Ensure `agent_config.json` uses the correct API base URL before distributing binaries.

## Handy Commands
- Health/status: `curl http://localhost:55000/health`, `docker compose ps`, `docker compose logs manager --tail 50`.
- Databases: `docker compose exec postgres psql -U dlp_user -d seceoknight_dlp`, `docker compose exec mongodb mongosh ...`.
- Google Drive manual poll: `curl -X POST https://YOUR_SERVER_IP/api/v1/google-drive/poll -H "Authorization: Bearer $TOKEN"`.
- Reset folder baseline: `POST /api/v1/google-drive/connections/{id}/baseline` with optional `folderIds`.

## When Unsure
- Read `.cursorrules` first.
- Keep `plan.md` synchronized with your steps.
- Ask before destructive operations.
- Log/document everything you touch (code, docs, infra, tests).
