# Upgrading qbit-authentik

## QQQ 4.1.0-RC.5 baseline (#20 / F19)

Hosts should align their QQQ dependencies with the released `qqq-bom-pom:4.1.0-RC.5`
and use Java 21. The historical `qqq-snapshot` profile and `qqq.snapshot.version`
property names remain, but the imported core version is a release, not a SNAPSHOT.
Core actions now enforce permissions and field security locks for non-HTTP callers
(QRun-IO/qqq#1061, #1062); callers must supply an appropriately authorized session.
The qbit keeps its guards, scope checks and sensitive-field stripping because they
also protect direct backend calls and implement Authentik-specific rules.
No qbit configuration, stored policy format or schema changes are introduced.

Stand-in audit against core tag `v4.1.0-RC.5`:

- `PolicyFeaturePermissionsTest` supplies a synthetic available-permission catalog:
  `STAND-IN(core=QRun-IO/qqq#1136, removeBy=4.1.0-RC.6)`. RC.6 is the removal target,
  subject to verifying that release contains the metadata hook. Retain malformed
  and duplicate catalog test cases when adding real metadata registration coverage.
- The requested stand-in/RC grep found only the old baseline references; the broader
  audit found the test catalog above and stale core-enforcement explanations.
  No production bridge can safely be removed by this baseline bump.
- `TableFeaturePermissionsMetaData` (core commit `9a302136d`, #1136) and client
  channels (core commit `741bb4974`, PR #1141) exist after RC.5, but neither commit
  is an ancestor of the RC.5 tag and neither API is present in that release.
  Follow up on a released baseline containing them: verify the policy editor's
  catalog with real feature metadata and adopt client-channel attribution and
  identity/credential channel restrictions. These features are not added here.

## Permissions renamed `identity.*` → `authentik.*` (unreleased → first release)

The qbit's permissions follow the same owner naming rule (2026-10-12) and now
carry the qbit's name. The suffixes are unchanged:

| Before | After |
|---|---|
| `identity.*` | `authentik.*` |
| `identity.users.read` | `authentik.users.read` |
| `identity.users.manage` | `authentik.users.manage` |
| `identity.groups.manage` | `authentik.groups.manage` |
| `identity.memberships.manage` | `authentik.memberships.manage` |
| `identity.permissions.manage` | `authentik.permissions.manage` |
| `identity.roles.manage` | `authentik.roles.manage` |
| `identity.credentials.reset` | `authentik.credentials.reset` |
| `identity.sessions.revoke` | `authentik.sessions.revoke` |
| `identity.audit.read` | `authentik.audit.read` |
| `identity.approve` | `authentik.approve` |
| `identity.admin` | `authentik.admin` |

The QQQ session form is the new name plus `.hasAccess`
(`authentik.users.read.hasAccess`).

**Legacy names are not granted.** The resolver lists an old `identity.*` name
among a group's *unknown* permissions, so it grants nothing and fails closed.
Update every stored grant **before** you deploy, or the admins lose the
Identity app until you do:

- **Authentik group attributes:** edit `qqq.io/permissions` on each group, for
  example `identity-admins`, in the Authentik UI (Directory → Groups →
  Attributes) or in its blueprint. Replace `identity.` with `authentik.`:

  ```yaml
  attributes:
    qqq.io/permissions:
      - authentik.*            # was identity.*
  ```

  To find the groups that still carry old names, run the drift report. Its
  "group attributes" check warns about each `identity.*` entry ("grants
  nothing in this app").
- **QQQ-side grants:** these are static fallbacks in
  `AuthentikGroupPermissionMapper`, host permission lists and role tables. If
  a host stores permission names in a table:

  ```sql
  -- example only: use your host's table and column names
  UPDATE role_permission
     SET permission_name = REPLACE(permission_name, 'identity.', 'authentik.')
   WHERE permission_name LIKE 'identity.%';
  ```

  The qbit itself stores no grants in a database. `qqq_user_session` rows hold
  resolved permissions, so sign users out (or let their sessions expire)
  after the change.
- **Code** that names `identity.*` strings. Use `IdentityPermission`
  instead. `IdentityPermission.LEGACY_PREFIX`, `LEGACY_WILDCARD` and
  `getLegacyShortName()` (all deprecated) give the old names for upgrade
  scripts.

The `identity-admins` group name and the "Identity" app label are unchanged.

## Snake_case table names (unreleased → first release)

Table names now follow the owner naming rule (2026-10-12): lowercase snake_case,
prefixed with the qbit's name and `_`.

| Before | After |
|---|---|
| `authentikUser` | `authentik_user` |
| `authentikGroup` | `authentik_group` |
| `authentikGroupMember` | `authentik_group_member` |
| `authentikSession` | `authentik_session` |
| `authentikEvent` | `authentik_event` |

With a custom `tableNamePrefix` the prefix is snake-cased too: `myAuth` gives
`my_auth_user`. App, widget, backend and process names keep camelCase
(`authentikAdmin`, `authentikDriftReport`, `authentikApi`).

The tables are API-backed, so there is no database DDL. Hosts that ran a
pre-release snapshot should update anything that stores a table name:

- **Permissions:** grants or role definitions that name a table (for example
  table-level permission names derived from the table name) and any host code
  calling `qInstance.getTable("authentikUser")`.
- **Saved views and reports:** rows whose table name is an old name, for
  example `UPDATE saved_view SET table_name = 'authentik_user' WHERE table_name = 'authentikUser';`
  (and the same for saved reports and any shared/favorite records).
- **Audit:** `audit_table.name` rows for the old names, if the host audits
  these tables (rename them, or leave history under the old name).
- **Frontend links and bookmarks** of the form `/…/authentikUser/…`.

`AuthentikTables.LEGACY_*_TABLE_NAME` hold the old names (deprecated) so
upgrade scripts can find them.
