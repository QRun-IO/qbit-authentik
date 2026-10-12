# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (phase 1, read-only MVP)
- Tables: `authentikGroupMember` (virtual membership table: by group, by user, by key, or a bounded sweep), `authentikSession` and `authentikEvent` (both need `identity.audit.read`).
- `GroupGraph` and `EffectivePermissionResolver`: groups, including inherited parents, become QQQ permissions. `identity.*` and catalog wildcards are expanded; unknown names are reported, never granted. Groups show inherited superuser status and effective permissions; users show effective permissions.
- Identity drift report widget (`identity.admin`). It checks the server version, blueprint status, the service account (type, groups, superuser, protection, extra self-minted tokens), break-glass presence, the last identity administrator, `qqq.io/*` attribute validity, and service-account changes to protected or superuser objects (lockout detection).

### Added (phase 0)
- Phase 0 foundations: `AuthentikQBitConfig`, `AuthentikQBitProducer`, `AuthentikActionUtil` (bearer auth, page/page_size paging, filter mapping that rejects unsupported filters, 10 rps token-bucket throttle, log redaction), read-only Users and Groups tables, Identity app.
- Pinned Authentik 2026.8.3 OpenAPI schema and schema drift tests.
- Testcontainers contract tests against Authentik 2026.8.3 (bootstrap on an empty instance, superuser floor, blueprint re-apply safety, access-check behaviour) and a fixture recorder.
