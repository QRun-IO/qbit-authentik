# QBit Authentik

A QQQ QBit for managing [Authentik](https://goauthentik.io) identities (users, groups, memberships, and the QQQ permissions a group grants) from a QQQ app. **Authentik stays the source of truth.** The qbit reads Authentik live and will write through the Authentik API. Changes made in the Authentik admin UI are equally valid.

Design: [`docs/DESIGN.md`](docs/DESIGN.md) (copy of the approved spec, QRun-IO/qqq#1065). Phase 0 owner steps: [`docs/PHASE0-OWNER-CHECKLIST.md`](docs/PHASE0-OWNER-CHECKLIST.md). Status and linked PRs: [`docs/STATUS.md`](docs/STATUS.md).

## Status

`0.1.0-SNAPSHOT`, the **read-only** release line (phases 0 and 1 of DESIGN.md section 11):

| Available | Not yet (refused by config validation) |
|---|---|
| `READ`: Authentik tables over the API | `MEMBERSHIP`, `GROUPS`, `USERS`, `CREDENTIALS`, `SESSIONS` writes (phases 2-3) |
| `MIRROR` (phase 1) | `RBAC` (phase 4), `WEBHOOK`, `SNAPSHOT_EXPORT` |

Every write is refused by `AuthentikGuard` in this release.

## Usage

```java
AuthentikQBitConfig config = new AuthentikQBitConfig()
   .withBaseUrl("https://auth.example.com")         // host root; /api/v3 is appended
   .withApiToken("${env.AUTHENTIK_API_TOKEN}")      // service-account token, resolved by the qbit
   .withAppKey("my-app-admin")                      // service account: qqq-my-app-admin-idadmin
   .withApplicationsInScope(List.of("my-app-prod"));

new AuthentikQBitProducer().withQBitConfig(config).produce(qInstance);
```

This produces:
- an API backend `authentikApi`
- read-only tables `authentik_user`, `authentik_group`, `authentik_group_member`, `authentik_session` and `authentik_event`
- the Identity Drift Report widget
- an app `authentikAdmin`, labelled "Identity", that hosts can nest, for example under Admin

Access is controlled by QQQ permissions:

| Permission (held as `<name>.hasAccess`) | Grants |
|---|---|
| `identity.users.read` | the Identity app and its tables |
| `identity.audit.read` | sensitive fields and tables |

The full `identity.*` set is in DESIGN.md section 5.2.

### Authentik side

The qbit's API token belongs to a dedicated Authentik service account whose role holds only the read permissions it needs. The bootstrap blueprint that creates it lives in the host's GitOps repo. One host's version, which the contract tests exercise, is [`src/test/resources/blueprints/kof22-identity-bootstrap.yaml`](src/test/resources/blueprints/kof22-identity-bootstrap.yaml); treat it as an example, not something to apply as is.

## Adopting in another app

See also the QQQ [adoption checklist](https://github.com/QRun-IO/qqq/blob/develop/docs/migration/adoption-checklist.adoc) (section 5 covers this QBit).

| Item | What to do |
|---|---|
| Coordinates | `com.kingsrook.qbits:qbit-authentik`. No release candidate or release is on Maven Central yet; CircleCI publishes snapshots from `develop`. Build from source or use a snapshot until `0.1.0` ships. |
| QQQ version | QQQ 4.1 (see `pom.xml` for the exact RC). Java 21. |
| Infrastructure | Authentik, contract-tested against 2026.8.3. The API must be reachable from the app at `baseUrl` (`/api/v3` is appended). |
| Authentik setup | A dedicated service account (default username `qqq-<appKey>-idadmin`) whose role holds only the read permissions the QBit needs, created by a bootstrap blueprint in the host's GitOps repository. `src/test/resources/blueprints/kof22-identity-bootstrap.yaml` is a worked example from one host, not something to apply as is. |
| Registration | `new AuthentikQBitProducer().withQBitConfig(config).produce(qInstance)`. Produces the `authentikApi` API backend, read-only tables (`authentik_user`, `authentik_group`, `authentik_group_member`, `authentik_session`, `authentik_event`), the drift report widget, and the `authentikAdmin` ("Identity") app, which the host may nest. |
| Required config | `baseUrl`, `apiToken`, `appKey` (lower-case letters, digits, dashes; chooses the service-account name), `applicationsInScope` (Authentik application slugs). Optional: `userScopePathStartsWith`, `groupScopeNamePrefix`, `mirrorBackendName` (phase 1 `MIRROR`), `throttleRequestsPerSecond` (default 10). |
| Secrets / env | `apiToken` as a `${env.X}` reference (the example uses `AUTHENTIK_API_TOKEN`); `bootstrapOperators` defaults to `${env.AUTHENTIK_QBIT_BOOTSTRAP_OPERATORS}` and `webhookSecret` to `${env.AUTHENTIK_WEBHOOK_SECRET}`. Keep them in the host's secret store, never in config files. |
| Permissions | `identity.users.read` (Identity app and tables), `identity.audit.read` (sensitive fields and tables); the full `identity.*` set is in DESIGN.md section 5.2. Granted through the Authentik group attribute `qqq.io/permissions`, read by `AuthentikGroupPermissionMapper`. |
| Storage | None for the read-only line, except the mirror tables when `MIRROR` is enabled on `mirrorBackendName`. |
| Known limitations | Read-only: every write is refused by `AuthentikGuard` until phases 2-3. `RBAC`, `WEBHOOK` and `SNAPSHOT_EXPORT` are refused by config validation. |
| Upgrading | First release line; nothing to migrate. |

## Build

```bash
./mvnw test                 # unit tests (recorded 2026.8.3 fixtures, no network)
CI=true ./mvnw verify       # + contract tests against Authentik 2026.8.3 in Docker (Testcontainers)
./mvnw verify -Dauthentik.test.image=ghcr.io/goauthentik/server:2026.10.0   # rehearse an upgrade
./mvnw verify -Dauthentik.fixtures.record=true                              # refresh unit fixtures
```

Contract tests start Authentik (server and worker), Postgres and Mailpit, and take about 10 minutes, mostly first boot and blueprint applies. Without Docker they are skipped locally. With `CI=true` they fail instead.

## License

Apache 2.0
