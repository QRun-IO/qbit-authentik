# Upgrading qbit-authentik

## Table help bundle (unreleased)

Nothing to do. The qbit now applies `help/qbit-authentik.yaml` to the Identity app and its tables at the end of `produce()`, filling only help slots the host has not set. There is no schema change and nothing to seed or include in a Liquibase changelog: the API-backed tables are live Authentik data, and the four local tables fill as people use the actions.

## QQQ 4.1.0-RC.6 baseline (#20 / F19)

Hosts should align their QQQ dependencies with the released `qqq-bom-pom:4.1.0-RC.6`
and use Java 21. The historical `qqq-snapshot` profile and `qqq.snapshot.version`
property names remain, but the imported core version is a release, not a SNAPSHOT.
Core actions now enforce permissions and field security locks for non-HTTP callers
(QRun-IO/qqq#1061, #1062); callers must supply an appropriately authorized session.
The qbit keeps its guards, scope checks and sensitive-field stripping because they
also protect direct backend calls and implement Authentik-specific rules.
No qbit configuration, stored policy format or schema changes are introduced.

The build adopts `qbit-build-parent:2.1.0` with `qbit.guardrails.enforce=true`.
The expired #1136 test stand-in is removed: tests now register features through
`TableFeaturePermissionsMetaData` and discover them through the real
`PermissionsHelper.getAllAvailablePermissions`, as production hosts do. The
unused explicit permission-source overload in `PolicyCatalog` is removed.
Duplicate shared-base entries, replacement registrations and malformed suffixes
remain covered. Hosts should register feature suffixes, labels and table
applicability through the core metadata API; no synthetic catalog is needed.
Client-channel attribution and identity/credential channel restrictions remain
separate follow-up work.

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
