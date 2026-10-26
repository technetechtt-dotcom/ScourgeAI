# ScourgeAI — Prototype v0.1

Shared *proposed* AI intelligence foundation for **Guardian AI** (personal safety) and **ArxVigil AI / JamShield** (vehicle/asset security). Based on the supplied October 2026 master specifications.

**NOT A LIVE EMERGENCY SYSTEM.** No SMS, responder dispatch, mobile device triggers, hardware failover, vehicle commands, ML models, or real emergency service integration is implemented. This release provides a rules-based event ingestion and explainable incident prototype only. Do not rely on it to protect people, vehicles, or assets.

## Quick start (Python 3.11+)

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
export TIC_CLIENT_SECRETS='{"demo:guardian":"development-change-me","demo:arxvigil":"development-change-me-too"}'
# Windows PowerShell: $env:TIC_CLIENT_SECRETS='{"demo:guardian":"development-change-me","demo:arxvigil":"development-change-me-too"}'
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for OpenAPI documentation and `http://127.0.0.1:8000/dashboard` for the operator console. SQLite is the default. PostgreSQL is available with `DATABASE_URL=postgresql+psycopg://...` and `python -m alembic upgrade head`. Version 0.3 status, including what is only partially implemented, is in `docs/DEVELOPMENT_STATUS.md`.

## Run tests

```bash
pytest -q
```

## Try the demonstration

```bash
python scripts_demo.py
```

Demo sign-in password for every account below is `correct-horse-battery`. The first sign-in enrolls an authenticator and shows one-time recovery codes. Later sign-ins require that code or a recovery code. There is no email sender: an administrator or developer issues a password-reset token from the API.

| Organisation | Email | Role |
| --- | --- | --- |
| demo | operator@example.com | operator |
| demo | supervisor@example.com | supervisor |
| demo | admin@example.com | administrator |
| demo | developer@example.com | developer |
| field | field.operator@example.com | operator |

`developer@example.com` can use every console action in its organisation: read records, review recommendations, change incident status, manage users, and create cross-domain grants. Platform maintenance on that account refreshes the model catalogue, registers or retires a model version, and requeues dead letters. Those updates do not dispatch, immobilise, edit evidence, or enable a language model.

The demo assumes `demo:guardian` has secret `development-change-me`. It signs the exact JSON body using `HMAC-SHA256(secret, timestamp + '.' + body)` in `X-Event-Signature` with UTC Unix timestamp in `X-Event-Timestamp`. Post `application/json` to `/v1/events`. The HMAC authenticates the configured API client, **not** a physical sensor or real device identity.

Read APIs: `/v1/incidents?tenant_id=demo&product=guardian` with header `X-Client-Secret: development-change-me`. This is a prototype-only scheme. Production requires OIDC service tokens, user sessions, role/attribute policy enforcement, nonrepudiable hardware identity and robust key lifecycle.

## Implemented
- JSON schema validation and two products' separate ingestion paths
- Client HMAC body signatures with 5-minute timestamp tolerance (development credential strategy)
- Idempotent event IDs, duplicate detection and collision rejection
- Tenant/product/subject scoped incident grouping
- Deterministic SOS priority rule; correlation of security signals, no invented theft verdict
- Evidence-linked risk assessments, uncertainty notes and recommendation records
- Human approval/rejection recorded without executing external actions
- SQLite database, audit rows, OpenAPI and baseline tests

## Design limitations / mandatory next work
1. **Safety:** dedicated fail-safe SOS and JamShield local failover services; never depend on this AI API. Hardware-in-loop tests required.
2. **Ingestion:** authenticated devices, certificate identity, nonce/sequence replay protection, clock synchronization semantics, rate limits, mTLS, schema registry, size controls.
3. **Reliability:** durable broker, transactional outbox, worker queue, retries, DLQ, high availability, backup/restore and alerting. Current ingestion is synchronous; external dispatch does not exist.
4. **Incident correctness:** bounded correlation windows, terminal incident lifecycle, policy versioning and signal provenance; current grouping uses the first open incident per product/subject.
5. **IAM:** a live identity provider, certificate deployment, recovery codes, and managed keys. Optional HS256 bearer checks and an optional mTLS gate are off unless configured. Human roles use TOTP, and the stored secret is sealed. Review records use the authenticated principal.
6. **Audit and evidence:** immutable append-only audit with strong retention, per-record integrity protections, chain of custody, object store and legal hold.
7. **Cross-product:** explicit opt-in grants, data minimisation, scoped sharing and purpose limitation before linking Guardian and ArxVigil events. CURRENTLY ISOLATED.
8. **AI:** supervised evaluation datasets, explanations with source pointers, model registry, shadow deployments, LLM orchestration in read-only mode and prompt-injection defenses. CURRENTLY RULES ONLY.
9. **Privacy/legal:** POPIA processing assessments, partner arrangements, data residency, breach process and consent retention.
10. **Operational:** risk validation, field pilots, incident command, emergency services partnerships and resilience tests before public release.

## Suggested repository tree

```
app/engine.py     # explainable rules
app/main.py       # FastAPI endpoints, authentication, persistence
app/models.py     # incident, evidence and audit entities
app/schemas.py    # canonical input schema
scripts_demo.py   # sends a signed SOS example
 tests/           # automated regression tests
```

This is a deliberately small modular foundation, not a claim of production readiness.

## Version 0.2 update — October 2026

Version 0.2 builds on the v0.1 prototype. It adds:

- **Development dashboard:** visit `http://127.0.0.1:8000/dashboard`; enter tenant, product, and the corresponding *development-only* client secret. It reads and displays incidents and operator briefs. Do not expose the page to the Internet with production secrets.
- **Grounded incident brief:** `GET /v1/incidents/{incident_id}/brief?tenant_id=...&product=...` with `X-Client-Secret` header. Includes source event IDs, observed facts, inferences, uncertainties and pending operator suggestions. This is a deterministic narrative template, **not an LLM or trained AI**.
- **Incident chronology:** `GET /v1/incidents/{incident_id}/timeline` using the same scoped authentication. Returns event IDs, timestamps and original payload hashes.
- **Product adapters:** Guardian and ArxVigil only accept their configured prototype event vocabulary; other event types receive HTTP 422 until adapter support is added.
- **Recommendation deduplication:** repeatedly matching the same rule does not create another identical pending recommendation.
- **Regression tests:** test event ingest, risk rules, scoped access, AI briefing, timeline, event adapters and dashboard.

### Demo event types

Guardian: `sos.manual`, `sos.volume`, `sos.safeword`, `sos.duress`, `sos.wearable`, `sos.vehicle`, `panic.activated`, `journey.route_deviation`, `journey.checkin_missed`, `device.network_lost`, `device.location_updated`, `guardian.acknowledged`, `device.heartbeat`.

ArxVigil: `panic.activated`, `device.power_cut`, `device.tamper`, `vehicle.unauthorized_movement`, `device.primary_signal_lost`, `device.backup_activated`, `vehicle.position_divergence`, `device.heartbeat`, `device.network_lost`, `vehicle.location_updated`, `device.battery_low`.

**Current limits:** incident grouping is still simplistic; timestamps and physical device claims are not independently verified; the development read API uses shared secrets; writes are synchronous SQLite by default; tests use a development database; there are no persistent queues, real user authentication, hardware failover, live dispatch, real mobile integration, or LLM. No production use or public deployment is authorised.
