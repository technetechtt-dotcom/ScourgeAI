# Development status — version 0.3.2

This file is the implementation record. It is not a production-readiness claim. The service does not dispatch responders, immobilise vehicles, or call a language model.

Automated check on this tree: `ruff` clean, `mypy` clean on the listed modules, **32 pytest tests passed** and **1 skipped** on SQLite. The skipped test is `tests/test_postgres_live.py`, which runs only when `TIC_POSTGRES_URL` is set. With that URL pointed at a temporary PostgreSQL 16 container, the same test **passed**: it opened a pooled connection, created the schema, and wrote and deleted one organisation row. Docker Compose was not started. Port 5432 was already published by another local database, and `docker-compose.yml` binds that port. The temporary container used port 5434 and was removed after the check. The GitHub Actions job that starts its own PostgreSQL service is in `.github/workflows/ci.yml` and was not executed from this machine.

## Audit findings that 0.3 keeps

Version 0.2 already had signed ingestion, idempotent event IDs, tenant/product reads, deterministic SOS and device rules, recommendation review that does not execute an action, a template brief, a timeline, and a read-only page. Those behaviours remain. The nine original tests still pass inside the larger suite.

## Status by phase

| Area | State | Evidence and limit |
| --- | --- | --- |
| PostgreSQL driver, URL, and QueuePool settings | Completed for a disposable database | `build_engine` sets pool size, overflow, timeout, and `pool_pre_ping`. A temporary PostgreSQL 16 accepted one transaction. This was not a soak test, a failover test, or a run of Compose. |
| Alembic migration | Completed for a new database | `alembic upgrade head` is tested against a temporary SQLite file and creates every model table. |
| Existing SQLite data | Partial | Startup adds missing tables, columns, and indexes. It does not rebuild an old file. |
| Models | Completed | Organisations, users, sessions, nonces, incidents, security events, assessments, recommendations, evidence, device state, model versions, agent executions, audit, outbox, dead letters, cross-domain grants, and rate buckets. |
| Tenant access | Completed for application queries | List and detail routes go through `TenantScope`. A user token for another organisation receives HTTP 403. A client secret for the wrong tenant still receives HTTP 401. |
| Backup and restore | Partial | SQLite backup uses the SQLite backup API and has a round-trip test. PostgreSQL `pg_dump` / `pg_restore` commands are printed and are not executed unless `--execute-postgres` is passed and the tool exists. |
| Passwords and sessions | Completed | scrypt password hashes. Session tokens are random and only their SHA-256 is stored. Logout revokes the token. |
| Roles | Completed | Operator, supervisor, administrator, developer, and service. Operators can read records. Supervisors can review and change incident status. Administrators can also manage users and grants. The developer role can do every one of those actions and is the only role that can maintain the platform: refresh the model catalogue, register or retire a model version, and requeue dead letters. Maintenance does not dispatch, immobilise, edit evidence, or enable a language model. Service is the client-secret role and can review. |
| MFA | Required before a full session | A password match without MFA returns an enrollment token only. Confirming the authenticator returns eight one-time recovery codes. A later sign-in requires the current code or one recovery code. Five failed attempts lock the account for 15 minutes. This is not a replacement for a production identity provider. |
| Service authentication | Partial | HMAC-SHA256 over `timestamp + "." + body`, five-minute window, constant-time compare, from `TIC_CLIENT_SECRETS`. Every new event requires `X-Event-Nonce`. Optional HS256 bearer tokens are accepted only when `TIC_OIDC_HMAC_SECRET` is set. That check is local. It is not a connection to an identity provider. Optional mTLS rejects `/v1` when `TIC_MTLS_REQUIRED=1` unless the TLS peer certificate is on the connection scope. It does not trust a client header. Health, readiness, metrics, and the dashboard stay open. Both gates are off by default. `TIC_ENV=production` refuses to start with placeholder client secrets, without `TIC_DATA_KEY`, or with device signatures switched off. Unsigned telemetry is rejected when that flag or `TIC_REQUIRE_DEVICE_SIGNATURE=1` is set. |
| Review identity | Completed for this API | The stored reviewer is the authenticated principal. A client-secret review is `client:{product}` even if the body supplies another name. |
| Rate limit | Partial | The request path stores hits in `rate_buckets`, and a second database session sees the same count. It is not a separate broker, and the window is not shared with a process that uses another database. |
| Replay protection | Partial | `X-Event-Nonce` is optional so old clients still work. Reuse of a nonce with a new event returns 409. Re-delivery of the same event ID stays idempotent. |
| Device signatures | Partial | Optional `X-Device-Key-Id` and `X-Device-Signature` over the raw body. Keys live in `TIC_DEVICE_KEYS`. A client claim of `signature_verified` without a matching key is rejected. Unsigned events remain unverified client claims. |
| Audit | Completed for application events | Ingestion, login, MFA, review, questions, user creation, user updates, grants, status changes, catalogue refresh, model updates, and dead-letter requeue append audit rows. There is no external immutable log or legal hold. |
| Agents | Completed as deterministic code | Eight agents: threat intelligence, incident copilot, guardian safety, ArxVigil vehicle trust, evidence intelligence, search and location, operations intelligence, AI governance. Each has responsibilities, schemas, tool lists, forbidden actions, confidence, uncertainty, and an execution row. They do not receive a database session. |
| Language model | Unimplemented by decision | `app.llm.complete` raises `LLMDisabled`. No provider is called, including when a caller passes evidence identifiers. `llm_enabled` stays false. |
| Guardian adapter | Completed for the event vocabulary | Manual, volume, safe word, duress, wearable, vehicle, panic, journey deviation, missed check-in, connectivity loss, location, acknowledgement, heartbeat, and responder status. Later events join an open SOS for the same subject. |
| SOS fail-open | Completed | If the rules engine raises, an explicit SOS is still stored as `EMERGENCY` and `live_dispatch` stays false. Test: `test_sos_is_kept_when_rules_fail`. |
| Platform SOS features | Unimplemented | Background microphone access and hardware-button interception are not assumed and are not implemented. |
| ArxVigil adapter | Completed for the event vocabulary | Includes JS-CORE telemetry, JS-GHOST status, JS-SEED witness, heartbeat, primary loss, backup activation, power cut, suspected interference, GNSS integrity, unexpected movement, and tamper. |
| Vehicle trust | Completed as classification | Labels are `missing`, `contradictory`, `unverified_client_claim`, `confirmed_hardware_event`, or `mixed`. A verified label means the device HMAC matched. It does not prove a physical fact beyond that. |
| Backup tracker | Monitored here, executed only as a device function | The API records `NOT_APPLICABLE`, `PENDING_OBSERVATION`, `NOT_OBSERVED`, or `CONFIRMED_BY_DEVICE_EVENT`. `activated_by_backend` is always false. `app.jamshield_device.local_backup_tracker_decision` returns `activate_secondary_tracker_locally` after 10 seconds of primary loss. Ingest does not import or call it. This service does not activate a tracker. |
| Immobilisation | Unimplemented by decision | No route contains it. Governance blocks `activate_immobilisation`. |
| Cross-domain divergence | Partial | Without a grant, Guardian and ArxVigil rows are not compared. With a grant, numeric coordinates more than 0.01 degrees apart are `contradictory`. That is not a theft finding. |
| Incident copilot | Completed as a template | Brief, timeline, handover, facts versus predictions, evidence hashes, and safe questions. Human review remains required. |
| Dashboard | Completed against the API | Overview, live incidents, both products, detail, timeline, investigations, device health, evidence, recommendations, model registry, monitoring, audit, organisation management, and platform maintenance. Counts are from API payloads. Empty and error text is explicit. After sign-in the page opens `GET /v1/stream` and reloads the current view when the revision changes. The feed is a one-second revision check in this process, not a message bus. Layout stacks on narrow screens. The maintenance page is available to the developer role. |
| Background work | Partial | Outbox rows are written in the ingest transaction and are idempotent per event. Workers claim pending rows. On PostgreSQL the claim uses `FOR UPDATE SKIP LOCKED`. A claim older than 30 seconds returns to pending. A failing row becomes a dead letter after five attempts. `external_dispatch` stays false. The worker runs only when `TIC_WORKER=1`. `TIC_WORKER_COUNT` starts that many threads in one process. There is no separate queue service. |
| Health and metrics | Completed for this process | `/health`, `/ready`, and Prometheus text at `/metrics`. Counters reset when the process restarts. |
| CI | Completed in the workflow file | The default job installs dependencies and runs Ruff, mypy on five modules, compileall, and pytest. A second job starts PostgreSQL 16 and runs `tests/test_postgres_live.py`. That Actions job was not run from this session. |
| Docker Compose | Present, not executed here | `docker-compose.yml` starts PostgreSQL 16 and the API on port 5432. It was not started because that port was already in use. The development database password in that file is for local use only. |

## Intentionally absent

- Responder dispatch, SMS, and emergency-service integration.
- Remote immobilisation or any other vehicle command.
- A language model, including a hidden fallback.
- Operating-system capture of a safe word, volume button, or microphone.
- Cloud execution of the JamShield 10-second backup activation.
- A live identity provider, a deployed mutual-TLS trust store, a hardware security module, and a distributed queue such as Redis or RabbitMQ.
- A claim that stored telemetry is proof of a crime.

## Local checks

```text
python -m ruff check app tests scripts
python -m mypy app/passwords.py app/totp.py app/backup.py app/vehicle.py app/tenancy.py
python -m pytest -q
```

Latest default result: 32 passed, 1 skipped. The live PostgreSQL test passed separately against a temporary server and is skipped without `TIC_POSTGRES_URL`. One Starlette deprecation warning remains, from FastAPI's test client importing `httpx`.
