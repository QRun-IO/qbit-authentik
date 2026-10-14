# QBit Authentik

A QQQ QBit to manage [Authentik](https://goauthentik.io) identities from a QQQ app: **the full user lifecycle, and groups with the permissions they grant**. Authentik stays the source of truth. The qbit reads Authentik live and writes through the Authentik API, never its database. Changes made in the Authentik admin UI are equally valid, and the qbit never overwrites them blindly.

Design: [`docs/DESIGN.md`](docs/DESIGN.md) (the approved spec, QRun-IO/qqq#1065). Access tokens (PATs): [`docs/ACCESS-TOKENS.md`](docs/ACCESS-TOKENS.md). Status: [`docs/STATUS.md`](docs/STATUS.md). Phase 0 owner steps: [`docs/PHASE0-OWNER-CHECKLIST.md`](docs/PHASE0-OWNER-CHECKLIST.md). Table DDL: [`docs/schema.sql`](docs/schema.sql).

## What you get

| | |
|---|---|
| **People** | Create a user (Authentik emails them a link to set their own password; QQQ never sets or sees one), invite, edit, deactivate and reactivate, send a password reset email, reset MFA, revoke app passwords, revoke sessions, cancel invitations. Edit covers username, name, email, path and other attributes. Delete is a separate, explicit action behind the `DELETE` feature (off by default); deactivate stays the default. |
| **Groups and permissions** | Create, edit (parents, other attributes) and delete groups, add and remove members, and edit the QQQ permissions and app sign-in a group grants (`qqq.io/permissions`, `qqq.io/app-access` on the Authentik group). |
| **Policies** | IAM-style policy documents on groups (`qqq.io/policy`, format in [docs/POLICY-FORMAT.md](docs/POLICY-FORMAT.md)), edited with a matrix of the app's apps, tables, processes and reports and a live JSON preview (Next UI widget `AUTHENTIK_POLICY_EDITOR`). At sign-in they become QQQ permissions through `AuthentikGroupPermissionMapper`, or through the token claim with `AuthentikPolicyClaimMapper`. Parsing fails closed. |
| **Safety** | Operators can only grant permissions they hold themselves. No self-edits. Break-glass, the service account and superusers are untouchable, and superuser groups cannot be managed. The last administrator cannot be removed. Granting `authentik.*` needs a second person. Destructive actions need a reason and a typed confirmation. A change made in the Authentik UI after you opened a form is detected, not overwritten. |
| **Audit** | Every attempt is a row in `authentik_admin_action` (written before the call), and Authentik's own event log gets a `custom_qqq_admin_action` event naming the human operator. |
| **Screens** | A home dashboard (what needs attention, people, groups, recent changes, connection), standard tables with full record screens, and every action as a table or record action with the usual Review and Result steps. Nothing is in the nav except the main tables. |

Everything is a standard QQQ table, action and widget, so it works in any QQQ UI and over the QQQ API.

## Usage

```java
AuthentikQBitConfig config = new AuthentikQBitConfig()
   .withBaseUrl("https://auth.example.com")          // host root; /api/v3 is appended
   .withApiToken("${env.AUTHENTIK_API_TOKEN}")       // service-account token, resolved by the qbit
   .withAppKey("my-app-admin")                       // service account: qqq-my-app-admin-idadmin
   .withFeatures(EnumSet.of(READ, USERS, GROUPS, MEMBERSHIP, CREDENTIALS, SESSIONS, POLICIES))  // + DELETE for delete actions
   .withLocalBackendName("rdbms")                    // audit trail and approval requests (see docs/schema.sql)
   .withRecoveryEmailStage("my-recovery-email")      // Authentik email stage (name or uuid)
   .withInvitationFlow("my-enrollment");             // optional: enables invitations

new AuthentikQBitProducer().withQBitConfig(config).produce(qInstance);
```

Read-only is the default (`features` = `READ`). `readOnly=true` is a hard kill switch that refuses every write whatever the features say.

### What it produces

| | |
|---|---|
| API backend | `authentikApi` |
| Main tables (nav) | `authentik_user`, `authentik_invitation`, `authentik_group`, `authentik_policy` (with `POLICIES`), `authentik_application`, `authentik_approval_request`, `authentik_admin_action` |
| Child lists (on their parents, not in the nav) | `authentik_group_member`, `authentik_session`, `authentik_token` (metadata only, never a key), `authentik_event`, `authentik_policy_binding`, `authentik_role`, `authentik_blueprint` |
| App and home | `authentikAdmin` (label "Identity", hosts may nest it) with the `authentikHome` widget and the drift report |
| Actions | Create User, Invite User, Edit User, Deactivate User, Reactivate User, Add To Group, Remove From Group, Send Password Reset Email, Reset MFA, Revoke App Passwords, Revoke Sessions, Create Group, Edit Group, Edit Permissions And App Access, Add Members, Remove Members, Cancel Invitation, Approve And Apply, Reject; with `POLICIES`: Edit Policy (on groups and policies); with `DELETE`: Delete User, Delete Group |

### Permissions

QQQ permissions, held as `<name>.hasAccess`, granted through the group attribute `qqq.io/permissions` and read by `AuthentikGroupPermissionMapper`:

| Permission | Grants |
|---|---|
| `authentik.users.read` | the Identity app, home, users, groups, applications, bindings, roles, blueprints |
| `authentik.users.manage` | create, invite, edit, deactivate, reactivate users; cancel invitations |
| `authentik.groups.manage` | create and edit groups |
| `authentik.memberships.manage` | add and remove members (subset rule) |
| `authentik.permissions.manage` | edit a group's permissions and app access (subset rule) |
| `authentik.policies.manage` | edit a group's policy (subset rule) |
| `authentik.credentials.reset` | password reset email, reset MFA, revoke app passwords |
| `authentik.sessions.revoke` | revoke sessions |
| `authentik.audit.read` | sessions, tokens, events, the audit trail, sensitive fields |
| `authentik.approve` | approve or reject a second person's request |
| `authentik.admin` | the drift report |
| `authentik.roles.manage` | reserved (role management is phase 4) |

`authentik.*` grants all of them.

Policies also grant table feature permissions registered through core `TableFeaturePermissionsMetaData`: `analyze` (qbit-data-analysis) and `comment`, `attach`, `tag`, `share`, `task`, `assign` (qbit-collaboration), or any future registered feature. For example, `{"Effect":"Allow","Action":["analyze","comment"],"Resource":["person"]}` grants `person.analyze` and `person.comment`. The resource is the table's effective permission base name. Features must be granted explicitly: policy action `"*"` still means only `hasAccess`, `read`, `insert`, `edit`, `delete`.

The editor discovers features and labels through `PermissionsHelper.getAllAvailablePermissions`; they appear when the host's core version exposes them. The pinned RC.5 release does not include `TableFeaturePermissionsMetaData`; its later core implementation is a follow-up for the next baseline upgrade. See [the policy format](docs/POLICY-FORMAT.md) for validation and host customizer usage.

### Authentik side

The qbit's API token belongs to a dedicated Authentik service account whose role holds only the permissions it needs (DESIGN.md section 5.1), created by a bootstrap blueprint in the host's GitOps repository. It is never a superuser and never holds `enable_group_superuser`, token-key or impersonate permissions, and holds delete permissions only when the `DELETE` feature is on. [`src/test/resources/blueprints/kof22-identity-bootstrap.yaml`](src/test/resources/blueprints/kof22-identity-bootstrap.yaml) is one host's worked example.

Write features need these in the role, on top of the read set: `add_user`, `change_user`, `reset_user_password`, `add_group`, `change_group`, `add_user_to_group`, `remove_user_from_group`, `view_token`, `delete_token`, `delete_authenticatedsession`, invitation `view`/`add`/`delete` (if you use invitations), `authentik_flows.view_flow` (to find the invitation flow by slug), and `view_emailstage` on the recovery stage. Saving a policy uses `change_group`. The `DELETE` feature also needs `delete_user` and `delete_group`. The contract tests grant exactly this list.

## Adopting in another app

See also the QQQ [adoption checklist](https://github.com/QRun-IO/qqq/blob/develop/docs/migration/adoption-checklist.adoc) (section 5 covers this QBit).

| Item | What to do |
|---|---|
| Coordinates | `com.kingsrook.qbits:qbit-authentik`. No release is on Maven Central yet; CircleCI publishes snapshots from `develop`. |
| QQQ version | QQQ 4.1.0-RC.5 (released BOM, no core SNAPSHOT). Java 21. |
| Infrastructure | Authentik, contract-tested against 2026.8.3. The API must be reachable from the app at `baseUrl`. |
| Tables | Create `authentik_admin_action` and `authentik_approval_request` on your local RDBMS backend (`docs/schema.sql`) before turning write features on. |
| Registration | `new AuthentikQBitProducer().withQBitConfig(config).produce(qInstance)`. |
| Required config | `baseUrl`, `apiToken`, `appKey`. For writes: `features`, `localBackendName`, `recoveryEmailStage` (users and credentials). Optional: `invitationFlow`, `twoPersonApproval` (default on), `userScopePathStartsWith`, `protectedUsernames`, `applicationsInScope`, `linkPrefix` (default `/app`), `throttleRequestsPerSecond` (default 10), `bulkPacingMillis`. |
| Secrets / env | `apiToken` as a `${env.X}` reference; `bootstrapOperatorSubjects` (the lockout escape hatch) defaults to `${env.AUTHENTIK_QBIT_BOOTSTRAP_SUBJECTS}`: immutable ids only (the Authentik user pk or uuid, or the token `sub`), never emails, because users can change their own email. Empty it once real group grants exist. Keep secrets in the host's secret store. |
| Optional host wiring | ESB: publish the local tables with `EsbTableMetaData.ofOrWithNew(table).withPublication(...)`. Quick Search: register `authentik_user` and `authentik_group` with the Quick Search qbit. Alerts: see Known limitations. |
| Known limitations | Not in this release: the Authentik webhook, the local mirror tables and reconcile, the access-matrix widget, snapshot export, RBAC role management (phase 4), Alerts producer integration. Invitations add people but not their groups (add them to groups after they sign up). Group and user lists are read live (cached 30 s). |
| Upgrading | See `UPGRADE.md`. |

## Build

```bash
./mvnw test                 # unit tests (recorded 2026.8.3 fixtures and an in-memory Authentik, no network)
CI=true ./mvnw verify       # + contract tests against Authentik 2026.8.3 in Docker (Testcontainers)
./mvnw verify -Dauthentik.test.image=ghcr.io/goauthentik/server:2026.10.0   # rehearse an upgrade
./mvnw verify -Dauthentik.fixtures.record=true                              # refresh unit fixtures
```

Contract tests start Authentik (server and worker), Postgres and Mailpit, and take about 10 minutes, mostly first boot and blueprint applies. Without Docker they are skipped locally. With `CI=true` they fail instead.

## License

Apache 2.0
