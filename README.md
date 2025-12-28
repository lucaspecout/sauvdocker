# DockBack

DockBack is a self-hosted, Dockerized backup manager for Docker resources on the host. It discovers containers and volumes, runs backup jobs via a runner container, and stores artifacts locally (and optionally in S3-compatible storage).

> ⚠️ **Security warning:** DockBack mounts `/var/run/docker.sock` to talk to the Docker Engine API. Any process with access to the socket effectively has root access on the host. Run DockBack only on trusted hosts and limit access to the UI.

## Architecture overview

- **API (FastAPI)**: Auth (JWT cookies + MFA), discovery, plans, jobs, settings, audit log. Generates the initial admin password on first boot.
- **Worker (Celery)**: Executes backup/restore/upload tasks. Creates archives via isolated runner containers.
- **Web (React + Vite)**: UI for dashboard, resources, plans, backups, restore wizard, settings, users, audit log.
- **Postgres/Redis**: Metadata storage and job queue.
- **Optional MinIO**: S3-compatible test storage.

## Features

- Auto-discover containers and volumes via Docker Engine API.
- Backup targets:
  - **Volumes**: runner container mounts the target volume read-only and writes a compressed archive to `/data/backups`.
  - **Containers**: backup attached volumes and store `docker inspect` output.
  - **Images (optional)**: `docker save` to tar.
- Restore targets with safety lock and confirmation flow.
- Backup plans with cron schedule, retention policy, checksum validation.
- S3-compatible uploads with retry-ready tasks.
- SMTP alerts for failures.
- Security: random admin password on first run, Argon2id hashes, MFA/TOTP, recovery codes, RBAC, audit log, encrypted settings at rest.

## Quick start (production)

```bash
docker compose up --build
```

Access:
- API: http://localhost:8080
- Web: http://localhost:3000

The first run prints a one-time admin password in the API container logs.

## Development

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

## Configuration

Environment variables (API/worker):
- `DATABASE_URL` (default `postgresql+psycopg2://dockback:dockback@postgres:5432/dockback`)
- `REDIS_URL` (default `redis://redis:6379/0`)
- `DOCKBACK_DATA_DIR` (default `/data/backups`)
- `DOCKBACK_SECRET_KEY`
- `DOCKBACK_BASE_URL`
- `DOCKBACK_ENCRYPTION_KEY_FILE`

Create an encryption key file at `./secrets/dockback_encryption_key` (already generated in this repo).

## Tests

```bash
pytest -q
```

## Healthchecks

- API: `GET /health`
- Worker: `celery -A app.celery_app inspect ping`
- Web: `GET /`

## API endpoints (high level)

- `/auth/*`: login, logout, refresh, change password, MFA setup
- `/resources/*`: containers, volumes
- `/plans/*`: backup plans CRUD
- `/jobs/*`: job listing and trigger
- `/settings/*`: encrypted settings
- `/users/*`: user management
- `/audit/*`: audit log
