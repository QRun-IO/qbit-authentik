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
   .withAppKey("kof22-admin")                       // service account: qqq-kof22-admin-idadmin
   .withApplicationsInScope(List.of("kof22-website-prod"));

new AuthentikQBitProducer().withQBitConfig(config).produce(qInstance);
```

This produces:
- an API backend `authentikApi`
- read-only tables (`authentikUser`, `authentikGroup`, ...)
- an app `authentikAdmin`, labelled "Identity", that hosts can nest, for example under Admin

Access is controlled by QQQ permissions:

| Permission (held as `<name>.hasAccess`) | Grants |
|---|---|
| `identity.users.read` | the Identity app and its tables |
| `identity.audit.read` | sensitive fields and tables |

The full `identity.*` set is in DESIGN.md section 5.2.

### Authentik side

The qbit's API token belongs to a dedicated Authentik service account whose role holds only the read permissions it needs. The bootstrap blueprint that creates it lives in the host's GitOps repo. The kof22 version is [`src/test/resources/blueprints/kof22-identity-bootstrap.yaml`](src/test/resources/blueprints/kof22-identity-bootstrap.yaml), which the contract tests exercise.

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
