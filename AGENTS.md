# AGENTS.md / CLAUDE.md

Shared guidance for agents working in this repository. Keep AGENTS.md and CLAUDE.md in sync.

## Project Overview

**QBit Authentik**: a QQQ QBit to manage Authentik users, groups, memberships and group-granted QQQ permissions from a QQQ app. Authentik's database is the source of truth; the qbit reads live and writes through the Authentik API (never its DB). Design: `docs/DESIGN.md` (approved spec, QRun-IO/qqq#1065). Current line: 0.1 = the full user lifecycle and group/permission management (phases 0-3), read-only by default.

## Build Commands

```bash
./mvnw compile          # always use the wrapper: Maven 3.10 cannot read the parent POM
./mvnw test             # unit tests, offline, on recorded fixtures (src/test/resources/fixtures/2026.8.3)
./mvnw test -Dtest=ClassName
./mvnw verify -DskipITs # compile, unit tests and JaCoCo; no contract ITs
CI=true ./mvnw verify   # + contract ITs: Authentik 2026.8.3 server+worker, Postgres, Mailpit (Testcontainers), JaCoCo gate
./mvnw verify -Dit.test=QbitReadContractIT -Dtest=none -Dsurefire.failIfNoSpecifiedTests=false
./mvnw verify -Dauthentik.fixtures.record=true              # refresh unit fixtures from the contract ITs
./mvnw test -Dtest=SchemaDriftTest -Dauthentik.schema.file=/path/to/schema.yml   # drift vs another release
```

- **Contract ITs** (`*IT`, package `contract`) share one `AuthentikTestStack` per JVM; first boot takes ~1.5-3 minutes. `@ExtendWith(RequiresDockerCondition.class)`: skipped without Docker locally, failed with `CI=true`.
- The stack boots with `src/test/resources/blueprints/*.yaml` already in `/blueprints/custom`: that IS contract test (h) (bootstrap on an empty instance).
- `TestApi` uses HTTP/1.1 on purpose: Java's HttpClient tries an h2c upgrade on plain-http POSTs, which Authentik answers with "400 Invalid HTTP request received."
- Tests that grant extra permissions to the service-account role must remove them again (they are additive and shared).

## Architecture

- `AuthentikQBitProducer` validates the config, registers an `AuthentikRuntime` for the API backend, then runs the component producers in `metadata/`.
- `AuthentikRuntime` (registry by API backend name): config, `TokenBucketThrottle` (10 rps, burst 20 by default), `AuthentikGuard`, `AuthentikFilterMapper`, response cache, and the table-name to `AuthentikTableSpec` map.
- `client/AuthentikActionUtil extends BaseAPIActionUtil` is the only code that talks to Authentik.
  - `doQuery`/`doCount`/`doGet` use page/page_size paging (max 100). Key-only filters become per-id GETs. The user scope and type filters are applied server-side and re-checked per record.
  - The generic table writes (`doInsert`/`doUpdate`/`doDelete`) are refused. Changes use `write(WriteAuthorization, ...)` or `writeAs(bearer, WriteAuthorization, ...)`, and only `AuthentikGuard.authorize(AdminAction)` mints a `WriteAuthorization` (an architecture test pins callers to `AuthentikAdmin` and its `AuthentikTokens` delegate).
  - `execute()` is the single request loop: throttle, bearer header, 429/5xx retry, error mapping, logging.
  - `send()` is the test seam (`FixtureActionUtil`, `QbitReadContractIT.RecordingActionUtil`).
- `client/AuthentikTables` maps tables to the pinned schema (users, groups, sessions, events), plus the **virtual** `groupMember` table, which `AuthentikActionUtil.memberships()` serves from a group, a user, or a bounded sweep. `client/AuthentikApiSurface` lists every operation and parameter used. `SchemaDriftTest` and `SchemaDriftIT` check that surface.
- `client/AuthentikFilterMapper` maps a QQQ filter to Authentik params, or rejects it with a `QUserFacingException`. It never filters client-side.
- `security/AuthentikGuard` handles read permission checks, write authorization, the user scope, and protected-account detection. `security/IdentityPermission` is the `authentik.*` catalog (session form `<name>.hasAccess`).
- `admin/AuthentikAdmin` plans and performs every change (`AdminAction`, `AdminRequest`, `AdminPlan`): the guardrails of DESIGN.md 5.4 run against LIVE Authentik data and the operator's LIVE groups (never the session claim) at plan time and again at execute time; the audit row (`AdminActionAuditor`, table `authentik_admin_action`) is written BEFORE the call and the call is not made if that fails; then the change, then an Authentik `custom_qqq_admin_action` event. `AuthentikSafety` holds the pure rules (subset rule helpers, last-admin, fingerprints). Granting `authentik.*` queues an `authentik_approval_request` for a second person (`approve`/`reject`).
- `admin/AuthentikTokens` implements DESIGN section 13: personal calls use an action-scoped exchanged bearer; service-account calls use the qbit bearer. One-time keys never enter records, process values, audit or event context. `TokenKeyDelivery` refuses key-producing actions when core has no response-only secret channel.
- `processes/AuthentikProcesses`: every action is a standard streamed-ETL table or record action (details screen, Review = dry run, Result), never in the nav. The ETL defaults to full validation, so the Review screen already holds the dry-run lines. The preview step's record count is NOT carried to later steps (and a client count needs `setDistinctCount`), so steps count targets themselves.
- `app/`: `AuthentikHomeData`/`AuthentikHomeView` (the single home widget, HTML with no tables) and `AuthentikRelations` (joins, child-list widgets and sections so sub-tables appear on their parents, not in the nav).
- `permissions/GroupGraph` + `EffectivePermissionResolver` (pure) turn groups and their ancestors into QQQ permissions. The util caches the graph for `groupCacheTtlSeconds` and uses it for derived fields.
- `drift/AuthentikDriftReport` holds the drift checks, using only the service account's read permissions. It is rendered by `metadata/AuthentikDriftReportWidgetRenderer`, a standard TABLE widget gated by `authentik.admin`.

## Invariants (do not break)

- Every `AuthentikActionUtil` entry point calls the guard first (in addition to core action permission enforcement, retain Authentik-specific rules and protection for direct util calls).
- Never log query strings (search terms are PII), the token, successful GET bodies, or bodies of sensitive endpoints; run anything stored through `AuthentikRedactor`.
- Never filter client-side; reject what Authentik cannot evaluate.
- Multi-value params are repeated plain names (`type=a&type=b`). Authentik silently ignores `type[]=`.
- The user detail GET takes no `include_*` params. Groups have no `last_updated` in 2026.8.
- `check_access?for_user=` is useless for the service account: it is silently evaluated for the caller. Never use it for other users.
- Only `AuthentikAdmin` and its `AuthentikTokens` delegate may call `AuthentikActionUtil.write` / `writeAs`. Every write needs a reason, passes the guard, and is audited first.
- `recovery_email` needs the brand to have a recovery flow ("No recovery flow set." otherwise), the role's `add_user` (DRF maps POST to add) plus `reset_user_password`, and `view_emailstage` on the stage.
- The service account must never be a superuser and never hold `enable_group_superuser` or impersonate permissions; never token-key READ (view_token_key); add_token and set_token_key only for service-account creation and rotation (add_token cannot mint for others); `delete_user`/`delete_group` only when the host turns the `DELETE` feature on.

## Code Style

3-space indentation, braces on the next line, `return (x);`, flower-box Javadoc on every class and method, fluent `withX()` setters, wrapper types in config.

## Dependencies

Java 21. Parent `qbit-build-parent:2.0.0`. The default-active `qqq-snapshot` profile imports `qqq-bom-pom:4.1.0-RC.5` (ADR-0007, as in qbit-sql-workbench). The project uses `qqq-backend-core` and `qqq-backend-module-api`. Test dependencies: JUnit 5, AssertJ, Mockito, Testcontainers 1.21.4, and Jackson YAML (from qqq) for the schema tests.

## Release

CircleCI qqq-orb 0.6.8:
- `develop` publishes SNAPSHOTs
- `release/*` publishes RCs
- `v*` tags publish releases

Cut `release/0.1` only after phase 1 is green and reviewed.
