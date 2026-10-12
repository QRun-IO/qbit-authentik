# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (v1: full user lifecycle and group/permission management, phases 2-3)
- **Writes through the Authentik API**, behind the features `USERS`, `GROUPS`, `MEMBERSHIP`, `CREDENTIALS` and `SESSIONS` (read-only stays the default; `readOnly` is a hard kill switch). Every change goes through `AuthentikAdmin`: it plans against live Authentik data (the guardrails of DESIGN.md 5.4), audits first, calls Authentik, posts a `custom_qqq_admin_action` event naming the operator, and finishes the audit row. `AuthentikActionUtil.write` needs a `WriteAuthorization`, which only `AuthentikGuard.authorize` can mint.
- **Actions** (table and record actions with Review and Result steps; none in the nav): Create User, Invite User, Edit User, Deactivate User, Reactivate User, Add To Group, Remove From Group, Send Password Reset Email, Reset MFA, Revoke App Passwords, Revoke Sessions, Create Group, Edit Group, Edit Permissions And App Access, Add Members, Remove Members, Cancel Invitation, Approve And Apply, Reject.
- **Safety**: the subset (no escalation) rule evaluated from the operator's live groups; protected accounts and superuser groups; no self-edits; last-administrator protection; reasons; typed confirmations (and a typed count above 25 targets); a 100-target cap; stale checks by fingerprint (groups have no `last_updated`); attribute edits merge only the `qqq.io/*` keys into the current attributes; two-person approval for granting `authentik.*`.
- **Local tables** `authentik_admin_action` (append-only audit) and `authentik_approval_request` (DDL in `docs/schema.sql`), on the new `localBackendName`.
- **Read tables** `authentik_application`, `authentik_policy_binding`, `authentik_blueprint`, `authentik_role`, `authentik_token` (metadata only, never a key) and `authentik_invitation`. Sub-tables appear as child lists on their parents; the nav lists only the main tables.
- **Home**: the `authentikHome` widget (needs attention, people, groups and permissions, recent changes, connection).
- Config: `localBackendName` (replaces `mirrorBackendName`), `twoPersonApproval`, `schedulerName`, `linkPrefix`.
- Tests: an in-memory Authentik for the rules, process tests through `RunProcessAction`, and write contract tests on Authentik 2026.8.3 (`QbitWriteContractIT`, including the recovery email arriving in Mailpit).

### Fixed
- Count reported no distinct count, so a process Review showed no total; group lists now include member pks (member counts were 0).
- Spec: multi-value filters are repeated plain names (`type=a&type=b`), never `type[]=a` (which Authentik silently ignores); stale role-state, `check_access`, re-parenting-risk, private-repo and backend-name wording corrected (spec revision 4).

### Not in this release
- The Authentik webhook, the local mirror tables and reconcile, the access-matrix widget, snapshot export, RBAC role management (phase 4) and the Alerts producer integration. `MIRROR`, `WEBHOOK`, `ACCESS_MATRIX`, `SNAPSHOT_EXPORT` and `RBAC` are refused by config validation.


### Changed
- **Permissions renamed `identity.*` → `authentik.*`** (same suffixes; owner naming rule, 2026-10-12; spec #1065 amended). Legacy names are reported as unknown and never granted. The old names are kept as `@Deprecated` `IdentityPermission.LEGACY_PREFIX`/`LEGACY_WILDCARD`/`getLegacyShortName()`. Update the `qqq.io/permissions` group attributes before deploying; see [UPGRADE.md](UPGRADE.md).
- **Table names are lowercase snake_case with the `authentik_` prefix** (owner naming rule, 2026-10-12): `authentik_user`, `authentik_group`, `authentik_group_member`, `authentik_session`, `authentik_event` (were `authentikUser`, ...). New `AuthentikQBitConfig.applyTablePrefix` and `toSnakeCase`; apps, widgets, the backend and processes keep camelCase names (`authentikAdmin`, `authentikApi`). The old names are kept as `@Deprecated` `AuthentikTables.LEGACY_*_TABLE_NAME` constants. See [UPGRADE.md](UPGRADE.md).

### Documentation
- README: "Adopting in another app" section (coordinates, configuration, secrets, permissions, limitations) linking the QQQ adoption checklist; examples use neutral names instead of one host's (#3).

### Added (phase 1, read-only MVP)
- Tables: `authentik_group_member` (virtual membership table: by group, by user, by key, or a bounded sweep), `authentik_session` and `authentik_event` (both need `authentik.audit.read`).
- `GroupGraph` and `EffectivePermissionResolver`: groups, including inherited parents, become QQQ permissions. `authentik.*` and catalog wildcards are expanded; unknown names are reported, never granted. Groups show inherited superuser status and effective permissions; users show effective permissions.
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
- Identity drift report widget (`authentik.admin`). It checks the server version, blueprint status, the service account (type, groups, superuser, protection, extra self-minted tokens), break-glass presence, the last identity administrator, `qqq.io/*` attribute validity, and service-account changes to protected or superuser objects (lockout detection).

### Added (phase 0)
- Phase 0 foundations: `AuthentikQBitConfig`, `AuthentikQBitProducer`, `AuthentikActionUtil` (bearer auth, page/page_size paging, filter mapping that rejects unsupported filters, 10 rps token-bucket throttle, log redaction), read-only Users and Groups tables, Identity app.
- Pinned Authentik 2026.8.3 OpenAPI schema and schema drift tests.
- Testcontainers contract tests against Authentik 2026.8.3 (bootstrap on an empty instance, superuser floor, blueprint re-apply safety, access-check behaviour) and a fixture recorder.
