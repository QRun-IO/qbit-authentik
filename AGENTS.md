# AGENTS.md

This file provides guidance to Codex and other agents when working with code in this repository. It mirrors CLAUDE.md; keep them in sync.

## Project Overview

**QBit Authentik**: a QQQ QBit to manage Authentik users, groups, memberships and group-granted QQQ permissions from a QQQ app. Authentik's database is the source of truth; the qbit reads live and (from phase 2) writes through the Authentik API. Design: `docs/DESIGN.md` (approved spec, QRun-IO/qqq#1065). Current line: 0.1 = read-only (phases 0-1).

## Build Commands

```bash
./mvnw compile          # always use the wrapper: Maven 3.10 cannot read the parent POM
./mvnw test             # unit tests, offline, on recorded fixtures (src/test/resources/fixtures/2026.8.3)
./mvnw test -Dtest=ClassName
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
  - Writes go to the guard, which refuses them in 0.1.
  - `execute()` is the single request loop: throttle, bearer header, 429/5xx retry, error mapping, logging.
  - `send()` is the test seam (`FixtureActionUtil`, `QbitReadContractIT.RecordingActionUtil`).
- `client/AuthentikTables` maps tables to the pinned schema (users, groups). `client/AuthentikApiSurface` lists every operation and parameter used. `SchemaDriftTest` and `SchemaDriftIT` check that surface.
- `client/AuthentikFilterMapper` maps a QQQ filter to Authentik params, or rejects it with a `QUserFacingException`. It never filters client-side.
- `security/AuthentikGuard` handles read and write permission checks, the user scope, and protected-account detection. `security/IdentityPermission` is the `identity.*` catalog (session form `<name>.hasAccess`).

## Invariants (do not break)

- Every `AuthentikActionUtil` entry point calls the guard first (QQQ core does not enforce permissions for non-HTTP callers, qqq#1061).
- Never log query strings (search terms are PII), the token, successful GET bodies, or bodies of sensitive endpoints; run anything stored through `AuthentikRedactor`.
- Never filter client-side; reject what Authentik cannot evaluate.
- Multi-value params are repeated plain names (`type=a&type=b`). Authentik silently ignores `type[]=`.
- The user detail GET takes no `include_*` params. Groups have no `last_updated` in 2026.8.
- `check_access?for_user=` is useless for the service account: it is silently evaluated for the caller. Never use it for other users.
- The service account must never be a superuser and never hold `enable_group_superuser`, token-key, impersonate or delete permissions.

## Code Style

3-space indentation, braces on the next line, `return (x);`, flower-box Javadoc on every class and method, fluent `withX()` setters, wrapper types in config.

## Dependencies

Java 21. Parent `qbit-build-parent:2.0.0`. The default-active `qqq-snapshot` profile imports `qqq-bom-pom:4.1.0-RC.2` (ADR-0007, as in qbit-sql-workbench). The project uses `qqq-backend-core` and `qqq-backend-module-api`. Test dependencies: JUnit 5, AssertJ, Mockito, Testcontainers 1.21.4, and Jackson YAML (from qqq) for the schema tests.

## Release

CircleCI qqq-orb 0.6.8:
- `develop` publishes SNAPSHOTs
- `release/*` publishes RCs
- `v*` tags publish releases

Cut `release/0.1` only after phase 1 is green and reviewed.
