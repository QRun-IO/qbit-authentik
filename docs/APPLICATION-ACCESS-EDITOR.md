# Application access editor implementation plan

Updated: 2026-11-04. User-approved scope: QQQ application roles only; Authentik administrative RBAC is excluded.

## Acceptance

From a user, group or application role, an operator can view effective QQQ access, identify each grant's source, edit direct grants using a checkbox matrix, and assign/remove users, groups and roles with searchable controls. Every save has Review and Result, live authorization and an audit record. Inherited grants cannot be removed by unchecking a direct grant. Permission removal must be verified after fresh sign-in.

## Model

- Authentik remains authoritative; all mutations go through the existing guarded admin API path.
- Application roles are reusable QQQ permission-bearing Authentik groups, distinguished by a reserved qqq.io attribute. User-role assignment is membership; group-role assignment is parent inheritance. This reuses the existing mapper, policy claims and subset/last-admin rules.
- Explicitly label Authentik administrative roles separately and do not expose them as editable QQQ application roles.
- Direct user grants use a dedicated group tagged with app key and immutable user ID. The group has exactly one member, no parents/children or Authentik administrative roles. The user action enforces protection, self-edit, stale-state, subset, last-admin and approval checks; generic group edits, membership changes and parent assignments cannot repurpose it. Existing group-based sign-in mapping remains compatible.
- Preserve grants from other sources; unknown existing permission names remain visible and are never silently dropped.

## Work sequence

1. Backend role classification, server-side role queries, named permission catalog and grant provenance; regression tests.
2. Reusable checkbox permission editor for groups/roles and searchable membership/parent-role selectors; remove the normal workflow's raw name/JSON fields.
3. User permissions and assignments, with direct/inherited sources and explicit save semantics; mapper and safety tests.
4. Review host with two operators and representative application resources. Verify role creation, direct and inherited grants, assignment/removal, protected targets, approval, fresh-sign-in enforcement and persistence behavior.
5. Finish unit/coverage/frontend and real-Authentik contract gates; resolve the previously observed bootstrap reapplication issue instead of counting an assisted run as clean.

## Working locations

- Backend: R:/Git.Local/QRunIO/qbit-authentik, review/local-latest (preserve existing local-review work).
- Frontend: C:/Users/james/.cache/qqq-authentik-access-ui, feature/authentik-access-ui, based on refreshed origin/main d04cfa4b.
- Existing review UI remains at http://localhost:18300/app/authentikAdmin while implementation proceeds.

No commit, push, merge or deployment is authorized by this plan.

## Implementation checkpoint

Implemented the backend and the frontend controls, including single-field server searches compatible with Authentik filters. Backend verification: 330 tests and JaCoCo gate passed; frontend access/process widgets: 46 tests passed, typecheck and changed-file lint passed. Live API checks found and drove the picker-search fix. Final real-Authentik write smoke and frontend proxy checks passed; the uniquely owned review instance is running. This is not a 1.0 release acceptance claim.

The manual review stack has unique qbit-authentik-review instance names and ownership labels. It uses explicit recorded-ID cleanup because an idle Testcontainers reaper connection removed earlier manual stacks while their JVMs were still running. Automated contract tests retain the ordinary reaper lifecycle.

## Large-catalog follow-up (2026-11-04)

Direct permission editing now requests 25-resource pages from the guarded widget endpoint. Search and application/resource-type filters run against QQQ metadata on the server. The UI renders action columns, preserves the complete direct-grant selection separately from catalog pages, and exposes bulk select/clear only for the displayed page with an explicit permission count. Named grants cover existing resources; bulk selection never creates wildcard/future grants.

Selected direct grants and inherited/policy grant sources have separate searchable, paged views. Unknown direct grants remain selected and removable. Directory assignments retain stable IDs and server-backed searches; their visible choices are bounded to 25.

Scale verification: a generated 1,000-table catalog is walked across all 40 pages, checking completeness, uniqueness, metadata filters, label search and out-of-range pages. Frontend tests exercise bulk page changes, off-page/unknown preservation and request failures. This is functional scale coverage, not a production latency or concurrency benchmark. Initial selected/inherited grant data still transfers as a complete baseline; the separate Edit Policy screen retains its existing catalog implementation.
