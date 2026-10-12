# Upgrading qbit-authentik

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
(`authentikAdmin`, `authentikDriftReport`, `authentikApi`). Permission names
(`identity.*`) are unchanged.

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
