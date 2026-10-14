# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- `AuthentikMaintenance.applyPolicy` lets reviewed host run-once jobs apply a policy to an exact group name through the existing audited Save Policy path. Dedicated maintenance identities, full-access expansion, canonical no-ops, context restoration, stale checks and optional two-person approval are covered; system-session writes remain forbidden. No HTTP route or process is registered.

- Explicit full-access policy statement (`Action: ["*"], Resource: ["*"]`) resolves against all current core and qbit permissions, including features, READ_WRITE `write`, identity names and future resources. Added canonical round trips, complete-set save authorization, last-admin removal protection and the editor `fullAccess` payload contract; named-resource wildcards retain their five-action meaning.

- Edit Policy supplies per-member preview data for up to 200 active, in-scope direct and descendant members, with relevant direct group names, base permissions excluding only the edited policy, a truncation flag, and the configured mapper-enabled flag. The Next UI can compute effective permissions and additions/removals locally while preserving inherited, named, static and bootstrap grants.
- Service-account lifetime caps use the user attribute (`serviceAccountTokenLifetime`, default `days=365`), preserving other attributes and requiring no special group.
- `TokenContractIT` on Authentik 2026.8.3 (9 tests) with the production token blueprint: token exchange as the user, the broker deny policy, the `qqq_token` claim, PATCH defaults, the expiry cap, service-account create/set_key/extend, the detective alarm, and the qbit lifecycle with the one-time key absent from audit rows and events.

### Added (access tokens 6c)
- Read-only and app/table scopes, validated at Review and execution and enforced after claims permissions; revoked credentials fail closed. Optional core credential-scope bridge for #1153.
- Last-used login activity (90-day window, five-minute cache), creation time and scope summaries; API tokens are explicitly not tracked.
- Daily expiry reminders with persistent per-window deduplication and optional Alerts delivery; high-severity guard-bypass alerts.
- A standard Access tokens TABLE widget with owner counts, age buckets and cleanup links, plus the existing record/list bulk revoke action.

### Added (access tokens, DESIGN.md section 13)
- Default-on `TOKENS` with personal create/rotate/revoke/extend, service-account creation and rotation, protected-owner guardrails and optional two-person approval.
- Action-scoped OAuth2 token exchange, response-only one-time key delivery (fail closed on older QQQ), generated usage instructions and non-secret token scope records.
- Token-manager read access, expanded token metadata, secret redaction and in-memory process/persistence tests.

### Changed (core baseline, #20 / F19)
- Build against the released QQQ BOM `4.1.0-RC.6` through the existing `qqq.snapshot.version` property; no core SNAPSHOT is used. Adopt `qbit-build-parent:2.1.0` with `qbit.guardrails.enforce=true`.
- Core actions now enforce permissions for non-HTTP callers. Authentik-specific guards remain for direct util calls and domain rules. See [UPGRADE.md](UPGRADE.md) for host impact and feature registration requirements.
- Replace the expired feature-catalog stand-in with real `TableFeaturePermissionsMetaData` registrations and remove the test-only `PolicyCatalog` permission-source overload. Feature discovery uses the core catalog without static mocking.

### Added (automated sessions)
- `AuthentikGroupPermissionMapper` resolves tokenless automated sessions by a unique active Authentik email match, applying direct and inherited group permissions, static fallbacks and the sign-in cut-over guard while preserving existing session permissions.

### Added (table feature permissions)
- Policies can grant table feature permissions (e.g. analyze, comment) registered through core TableFeaturePermissionsMetaData

### Added (policy cut-over, DESIGN.md section 12.8)
- `AuthentikHostPermissionSource` SPI (today's access) and config `mapperEnabled`, `cutoverGuardGroups`, `mapperOverride`, `staticGroupPermissions`.
- **Enforcement status**: banner widget `authentikPolicyEnforcement` (first on group and policy records and on the Edit Policy step) and a "Policies at sign-in" row in the home's Connection card: OFF, ACTIVE, OVERRIDDEN or BLOCKED.
- **Compare Access** widget `authentikCompareAccess` on the app home (`authentik.admin`, read only): per active person, today vs the mapper, with added, removed and unchanged, and the guard result.
- **Cut-over guard**: while a member of a guarded group would lose a permission (and no override), the mapper grants today's access plus the static fallback and bootstrap subjects instead of the policies.
- **Generate Policy From Current Access** group action: the expressible part of today's access (joined with the current policy) becomes the policy, named permissions go to `qqq.io/permissions`, the rest is listed; Review shows the document and diff.

### Added (full user and group CRUD, phase 5c: DESIGN.md section 12.5)
- **Edit User** also changes the username (validated, unique) and the other attributes (a JSON object; reserved `qqq.io/` and `goauthentik.io/` keys are kept and cannot be set; blank leaves them as they are; editing attributes needs `authentik.audit.read`, which is also what shows them on the form). **Edit Group** edits other attributes the same way.
- **Delete User** and **Delete Group** record actions behind the new `DELETE` feature (off by default; needs Authentik's `delete_user` / `delete_group`). Typed confirmation; never yourself, a protected account, a superuser group or the last identity administrator; a group must have no members and no child groups first; the group's `authentik_policy` row goes with it. Deactivate stays the default for people.

### Added (policy editor, phase 5b: DESIGN.md section 12.4)
- **Edit Policy** record action on groups and on policies (feature `POLICIES`, permission `authentik.policies.manage`): a standard streamed-ETL action whose step shows the `AUTHENTIK_POLICY_EDITOR` widget (Next UI). Review parses the submitted document (fail closed), regenerates it in canonical form with the round-trip check, refuses new resources this app does not define, applies the subset rule to the permissions it adds, and lists what is added and removed. Result merge-patches `qqq.io/policy` into the group's current attributes (removed when empty). Optional second-person approval (`policyTwoPersonApproval`).
- **`PolicyCatalog`**: every app, table, process (hidden record actions included), report and protected widget a policy can grant, with the actions QQQ checks, grouped by app. Its permission names join the permission catalog.
- **`authentik_policy`** local table (one row per group; field-level audit is the change history; DDL in `docs/schema.sql`), in the nav under Access and as a child list on the group.
- Widget `authentikPolicyEditor` (type `AUTHENTIK_POLICY_EDITOR`): the catalog and the group's live document, with a flag when it was changed in Authentik since the last save in QQQ.

### Added (policies, phase 5a: DESIGN.md section 12, docs/POLICY-FORMAT.md)
- **Policy documents** (IAM-style statements) on Authentik groups: `PolicyParser` (fails closed: unknown spec or version, non-Allow effect, unknown action, bad resource or malformed JSON grant nothing), `PolicyGenerator` (canonical form with a round-trip check), `PolicyFormat` and the config `policySpec`, `policyVersion`, `policyAttribute`, `policyClaim`, `policyTwoPersonApproval`.
- **Runtime**: `AuthentikPolicyClaimMapper` (reads the `qqq_policy` claim from the ID token or access token; `applySecurityKeys` hook for record locks) and `PolicyPermissions.fromClaims` for a host's own customizer. `AuthentikGroupPermissionMapper` also adds the claim, and the group graph and `EffectivePermissionResolver` read each group's `qqq.io/policy`, so effective permissions, the subset rule and the last-admin check see policy grants. An invalid policy on a group is listed as malformed.
- **Blueprint example** for the scope mapping that puts the merged policies into the token, pinned by `PolicyClaimMappingIT` on Authentik 2026.8.3.

### Added (v1: full user lifecycle and group/permission management, phases 2-3)
- **Writes through the Authentik API**, behind the features `USERS`, `GROUPS`, `MEMBERSHIP`, `CREDENTIALS` and `SESSIONS` (read-only stays the default; `readOnly` is a hard kill switch). Every change goes through `AuthentikAdmin`: it plans against live Authentik data (the guardrails of DESIGN.md 5.4), audits first, calls Authentik, posts a `custom_qqq_admin_action` event naming the operator, and finishes the audit row. `AuthentikActionUtil.write` needs a `WriteAuthorization`, which only `AuthentikGuard.authorize` can mint.
- **Actions** (table and record actions with Review and Result steps; none in the nav): Create User, Invite User, Edit User, Deactivate User, Reactivate User, Add To Group, Remove From Group, Send Password Reset Email, Reset MFA, Revoke App Passwords, Revoke Sessions, Create Group, Edit Group, Edit Permissions And App Access, Add Members, Remove Members, Cancel Invitation, Approve And Apply, Reject.
- **Safety**: the subset (no escalation) rule evaluated from the operator's live groups; protected accounts and superuser groups; no self-edits; last-administrator protection; reasons; typed confirmations (and a typed count above 25 targets); a 100-target cap; stale checks by fingerprint (groups have no `last_updated`); attribute edits merge only the `qqq.io/*` keys into the current attributes; two-person approval for granting `authentik.*`.
- **Local tables** `authentik_admin_action` (append-only audit) and `authentik_approval_request` (DDL in `docs/schema.sql`), on the new `localBackendName`.
- **Read tables** `authentik_application`, `authentik_policy_binding`, `authentik_blueprint`, `authentik_role`, `authentik_token` (metadata only, never a key) and `authentik_invitation`. Sub-tables appear as child lists on their parents; the nav lists only the main tables.
- **Home**: the `authentikHome` widget (needs attention, people, groups and permissions, recent changes, connection).
- Config: `localBackendName` (replaces `mirrorBackendName`), `twoPersonApproval`, `schedulerName`, `linkPrefix`.
- Tests: an in-memory Authentik for the rules, process tests through `RunProcessAction`, and write contract tests on Authentik 2026.8.3 (`QbitWriteContractIT`, including the recovery email arriving in Mailpit).

### Security
- `bootstrapOperators` (emails) is replaced by `bootstrapOperatorSubjects` (env `AUTHENTIK_QBIT_BOOTSTRAP_SUBJECTS`): users can change their own email in Authentik, so an email must never confer identity permissions. A bootstrap operator is now matched on the token `sub` (email-looking subs ignored) or, with a verified email, on the single active Authentik user with that email whose pk or uuid is configured. Spoofed, duplicate or unverified emails are denied; entries containing `@` fail validation. The admin service uses the same rule.

### Fixed
- Count reported no distinct count, so a process Review showed no total; group lists now include member pks (member counts were 0).
- Spec: multi-value filters are repeated plain names (`type=a&type=b`), never `type[]=a` (which Authentik silently ignores); stale role-state, `check_access`, re-parenting-risk, private-repo and backend-name wording corrected (spec revision 4).

### Not in this release
- The Authentik webhook, the local mirror tables and reconcile, the access-matrix widget, snapshot export, RBAC role management (phase 4) and the Alerts producer integration. `MIRROR`, `WEBHOOK`, `ACCESS_MATRIX`, `SNAPSHOT_EXPORT` and `RBAC` are refused by config validation.


### Changed
- **Permissions renamed `identity.*` â†’ `authentik.*`** (same suffixes; owner naming rule, 2026-10-12; spec #1065 amended). Legacy names are reported as unknown and never granted. The old names are kept as `@Deprecated` `IdentityPermission.LEGACY_PREFIX`/`LEGACY_WILDCARD`/`getLegacyShortName()`. Update the `qqq.io/permissions` group attributes before deploying; see [UPGRADE.md](UPGRADE.md).
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
