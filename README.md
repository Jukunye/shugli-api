# Shugli API

Backend API for **Shugli** — the Backoffice + HRIS platform.

> **Project status:** Early development. Nothing here is stable yet —
> schema, APIs, and UI are all subject to change. Not accepting external
> contributions or deployments at this time.

**Shugli platform** · [Marketing](https://github.com/Jukunye/shugli) · [App](https://github.com/Jukunye/shugli-app) · **API** (this repo)

---

## What this is

The server-side layer of Shugli. It owns authentication, authorization,
the audit engine, and all persistence for the platform. The frontend
([`shugli-app`](https://github.com/Jukunye/shugli-app)) is a thin client
over this API.

**Responsibilities:**

- Auth: login/logout, session management, forgot-password
- RBAC: roles, permissions, per-request permission middleware
- Universal CRUD: dynamic, config-driven entity endpoints
- Audit engine: automatic interception of all mutations (who/what/when/before/after)
- File storage: documents, versions, expiry metadata
- Notifications

## Stack

| Layer          | Choice                      |
| :------------- | :-------------------------- |
| Language       | Python                      |
| Framework      | FastAPI                     |
| Database       | SQLite (local development)  |
| ORM            | SQLAlchemy                  |
| Migrations     | Alembic                     |
| Object storage | Local filesystem (dev only) |

> **Note:** SQLite and local file storage are for local development only.
> Production will move to PostgreSQL and S3-compatible object storage
> (Cloudflare R2). Migrations are managed with Alembic so the switch is
> a config change, not a rewrite.
