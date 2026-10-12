# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- **Table names are lowercase snake_case with the `authentik_` prefix** (owner naming rule, 2026-10-12): `authentik_user`, `authentik_group`, `authentik_group_member`, `authentik_session`, `authentik_event` (were `authentikUser`, ...). New `AuthentikQBitConfig.applyTablePrefix` and `toSnakeCase`; apps, widgets, the backend and processes keep camelCase names (`authentikAdmin`, `authentikApi`). The old names are kept as `@Deprecated` `AuthentikTables.LEGACY_*_TABLE_NAME` constants. See [UPGRADE.md](UPGRADE.md).

### Documentation
- README: "Adopting in another app" section (coordinates, configuration, secrets, permissions, limitations) linking the QQQ adoption checklist; examples use neutral names instead of one host's (#3).

### Added (phase 1, read-only MVP)
- Tables: `authentik_group_member` (virtual membership table: by group, by user, by key, or a bounded sweep), `authentik_session` and `authentik_event` (both need `identity.audit.read`).
- `GroupGraph` and `EffectivePermissionResolver`: groups, including inherited parents, become QQQ permissions. `identity.*` and catalog wildcards are expanded; unknown names are reported, never granted. Groups show inherited superuser status and effective permissions; users show effective permissions.
- `AuthentikGroupPermissionMapper`: an authentication customizer that turns the token's `groups` claim into QQQ session permissions through the resolver. It supports static fallbacks and `bootstrapOperators`; if Authentik cannot be read it grants only the static fallbacks, never everything.
- Review hardening:
  - `search` accepts plain text only; Authentik's query language could reach sensitive fields.
  - The group graph is thread-safe.
  - A failed group-graph read shows "Unavailable", never empty permissions.
  - Malformed `qqq.io/*` attributes are reported.
  - Operator filters can't widen the user scope, so count and query agree.
  - Membership rows are always scope-checked.
  - Missing pagination is an error.
  - Sorting by the key falls back to the default order.
  - Booleans are strict.
  - `..` keys are refused.
  - https is required (except loopback or `allowInsecureHttp`).
  - `groupScopeNamePrefix` is refused until implemented.
  - Drift checks that cannot run report ERROR ("result unknown"); service-account tokens are filtered server-side; deleted targets are flagged; only human users count as identity admins.
- Identity drift report widget (`identity.admin`). It checks the server version, blueprint status, the service account (type, groups, superuser, protection, extra self-minted tokens), break-glass presence, the last identity administrator, `qqq.io/*` attribute validity, and service-account changes to protected or superuser objects (lockout detection).

### Added (phase 0)
- Phase 0 foundations: `AuthentikQBitConfig`, `AuthentikQBitProducer`, `AuthentikActionUtil` (bearer auth, page/page_size paging, filter mapping that rejects unsupported filters, 10 rps token-bucket throttle, log redaction), read-only Users and Groups tables, Identity app.
- Pinned Authentik 2026.8.3 OpenAPI schema and schema drift tests.
- Testcontainers contract tests against Authentik 2026.8.3 (bootstrap on an empty instance, superuser floor, blueprint re-apply safety, access-check behaviour) and a fixture recorder.
