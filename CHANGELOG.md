# Changelog

## 0.3.1
- Seal MFA secrets before they are stored, and require TOTP for operators as well as supervisors and administrators.
- Record recommendation reviews as the authenticated principal. A client-secret caller is `client:{product}`.
- Share rate-limit buckets through the database, and let more than one outbox worker claim rows.
- Replace dashboard polling with a server-sent event feed that reconnects.
- Add an optional HS256 bearer check and an optional client-certificate gate. Both stay off unless configured.
- Keep language-model calls refused. The JamShield 10-second backup decision stays in a device module that the API does not call. There is still no remote immobilisation.

## 0.3.0
- Add PostgreSQL driver and pool settings, Alembic initial migration, additive SQLite schema updates, and tenant-scoped queries.
- Add organisations, users, sessions, TOTP for privileged roles, service HMAC, rate limiting, event nonces, and device-body signatures.
- Add evidence, device state, model registry, agent execution, outbox, and dead-letter records.
- Add eight deterministic agents. Language-model calls stay disabled. Agents cannot dispatch, suppress an SOS, immobilise, or modify evidence.
- Keep explicit SOS incidents when the rules engine fails, and attach later Guardian events to an open SOS for the same subject.
- Add JamShield event types, vehicle-trust classification, backup-tracker observation, and cross-domain comparison only after a grant.
- Extend the incident brief with facts, predictions, evidence hashes, handover, and grounded questions.
- Replace the single preview page with an operator console that reads the API, including loading, empty, and error states.
- Add health, readiness, Prometheus text, a single-process outbox worker, Docker Compose, and CI.
- This is not a production emergency system. See `docs/DEVELOPMENT_STATUS.md`.

## 0.2.0
- Add source-linked, deterministic Incident Copilot brief and endpoint.
- Add tenant-scoped event chronology with stored payload hashes.
- Add Guardian and ArxVigil event vocabulary validation.
- Add responsive read-only monitoring dashboard.
- Suppress duplicate identical pending recommendations.
- Add 4 new regression tests (9 passing total).

## 0.1.0
- Initial signed API event ingestion, deterministic rule assessment, incident storage, review and audit prototype.
- Add PostgreSQL driver and pool settings, Alembic initial migration, additive SQLite schema updates, and tenant-scoped queries.
- Add organisations, users, sessions, TOTP for privileged roles, service HMAC, rate limiting, event nonces, and device-body signatures.
- Add evidence, device state, model registry, agent execution, outbox, and dead-letter records.
- Add eight deterministic agents. Language-model calls stay disabled. Agents cannot dispatch, suppress an SOS, immobilise, or modify evidence.
- Keep explicit SOS incidents when the rules engine fails, and attach later Guardian events to an open SOS for the same subject.
- Add JamShield event types, vehicle-trust classification, backup-tracker observation, and cross-domain comparison only after a grant.
- Extend the incident brief with facts, predictions, evidence hashes, handover, and grounded questions.
- Replace the single preview page with an operator console that reads the API, including loading, empty, and error states.
- Add health, readiness, Prometheus text, a single-process outbox worker, Docker Compose, and CI.
- This is not a production emergency system. See `docs/DEVELOPMENT_STATUS.md`.

## 0.2.0
- Add source-linked, deterministic Incident Copilot brief and endpoint.
- Add tenant-scoped event chronology with stored payload hashes.
- Add Guardian and ArxVigil event vocabulary validation.
- Add responsive read-only monitoring dashboard.
- Suppress duplicate identical pending recommendations.
- Add 4 new regression tests (9 passing total).

## 0.1.0
- Initial signed API event ingestion, deterministic rule assessment, incident storage, review and audit prototype.
