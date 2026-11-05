# Status

The Authentik qbit's progress through DESIGN.md section 11, with links. Updated with each PR.

## Local review update — 2026-11-04

- Refreshed from Gitea `develop` (`fe6f716`) on `review/local-latest`.
- Updated the QQQ BOM to 4.1.0-RC.21 and added a local Next UI 1.0.0-RC.37 host.
- `mvnw.cmd verify -DskipITs`: 321 tests passed, zero failures/errors/skips;
  JaCoCo coverage gate passed.
- Real browser check: Identity dashboard, users, user details, Edit User Review
  and Result all worked against disposable Authentik 2026.8.3; a synthetic user's
  display name was successfully changed through the qbit.
- A clean full contract gate is still required: the separate test stack hit
  first-boot blueprint errors. Manual reapplication is diagnostic assistance,
  not evidence of an unattended green bootstrap.
- This is review-ready, not a 1.0 release sign-off. OAuth, personal token
  exchange, two-operator approval and production rollout still need acceptance
  in a fully configured host. Earlier owner checklist items below have not been
  revalidated against production during this session.

Start/stop instructions and review limitations: [LOCAL-REVIEW.md](LOCAL-REVIEW.md).

## v1 = phases 0-3 (the full user lifecycle and group/permission management)

| Phase | State |
|---|---|
| 0. Foundations and migration | agent items done; **owner items open** (checklist items 6-8, 10, then 12) |
| 1. Read-only plus the permissions model | done, except the mirror tables, reconcile and the access-matrix widget (see "Not built yet") |
| 2. Memberships and permission editing | done, except the webhook route, ESB trigger, inbox and session re-evaluation marking |
| 3. Full user lifecycle | done, except the optional snapshot export |
| 4. RBAC role management | post-v1, not started |
| 5. Policies and full CRUD (DESIGN.md section 12) | 5a policy model (#14), 5b policy editor (#15), 5c user and group CRUD additions; the Next UI widget is a separate qqq-frontend-next PR |

### Built in this line (0.1)

| Area | What |
|---|---|
| People | Create, invite, edit (username, name, email, path, other attributes), deactivate, reactivate, delete (feature `DELETE`), password reset email, reset MFA, revoke app passwords, revoke sessions, cancel invitations |
| Groups | Create, edit (parents, other attributes), delete (feature `DELETE`), add and remove members (bulk), edit permissions and app access, edit the group policy (feature `POLICIES`) |
| Safety | Subset rule on live groups, protected accounts and superuser groups, no self-edits, last-admin protection, reasons, typed confirmations, bulk caps, stale checks, two-person approval for `authentik.*` |
| Audit | `authentik_admin_action` (before the call), Authentik `custom_qqq_admin_action` events, approval requests |
| Screens | Home dashboard, main tables in the nav, child lists on parents, every action as a table or record action |
| Tests | Unit tests on an in-memory Authentik (rules, processes, app, home), contract tests on Authentik 2026.8.3 |

### Not built yet (and why)

| Item | Note |
|---|---|
| Authentik webhook, ESB trigger, inbox, session re-evaluation marking | Needs the notification transport in cluster-gitops (inert today); reads are live (30 s cache) so screens are correct without it |
| Mirror tables and reconcile | For Web Users joins and widget counts; the home reads live |
| Access matrix widget, group tree widget | Needs Next UI custom widgets (separate frontend PRs) |
| Snapshot export | Optional in the spec |
| RBAC role management | Phase 4 |
| Alerts producer integration | Optional until the Alerts qbit SPI (QRun-IO/qqq#1090) lands |
| Quick Search for users and groups | They are API-backed (read-through), so they are searched with the table's own search box, which Authentik evaluates live |
| Invitations add groups | Groups for invited people are added after they sign up (needs the webhook) |

## Phase 0: foundations (agent items done; owner items open)

| # | Item | State | Where |
|---|---|---|---|
| 1 | Repo, DESIGN.md, CI, README, CLAUDE.md | done | this repo (`develop`); public |
| 2 | Config, producer, `AuthentikActionUtil`, pinned schema + drift test | done | phase 0 PR |
| 3 | Testcontainers harness, fixture recorder, contract tests (b), (c), (d), (h) | done | `src/test/java/.../contract` |
| 4 | Open points (i)-(iv) resolved | done | DESIGN.md section 0.2 |
| 5 | cluster-gitops PR (bootstrap, removals, sign-in policy, webhook, lint) | draft | KofTwentyTwo/cluster-gitops#72 |
| 6 | Staging rehearsal | **owner** | `docs/PHASE0-OWNER-CHECKLIST.md`, `docs/cluster-gitops-phase0/rehearse-phase0.sh` |
| 7 | Production apply | **owner** | checklist |
| 8 | Service-account token, Infisical, webhook secret | **owner** | checklist |
| 9 | Website-Backend wiring (ExternalSecret + env, qbit behind a disabled flag) | draft | KofTwentyTwo/cluster-gitops#73, Website-Backend#94 |
| 10 | Seed attributes, break-glass password | **owner** | checklist |
| 11 | Read-only on staging | after 6-10 | flip `AUTHENTIK_QBIT_ENABLED` |
| 12 | Turn on the full lifecycle (role permissions, brand recovery flow, tables, flags) | after 11 | checklist item 12 |

## Contract and unit tests (Authentik 2026.8.3)

`CI=true ./mvnw verify`. The numbers are filled in at the end of each PR; see the PR description.

The diagnostic full run was stopped during BlueprintReapplyIT after the assisted bootstrap (5 tests) and schema drift (1 test) passed. It is incomplete and is not a passing contract gate. The review JVM remains running independently.

## Application access editor — 2026-11-04

Implemented QQQ application roles (tagged Authentik groups), checkbox named-permission/sign-in access editing, server-searched assignment selectors, direct user grants isolated in single-member groups, and inherited grant provenance. Generic group operations cannot repurpose direct-user access groups. All writes retain the live guard, audit, stale-state and approval paths.

Validation: 330 offline backend tests passed with the JaCoCo gate; 46 frontend access/process widget tests passed; typecheck and changed-file lint passed. Real-Authentik smoke testing caught and fixed the default picker OR-filter incompatibility and reopening after the last direct grant is removed. This is review-ready development work, not a 1.0 release acceptance claim: the complete contract suite and fresh OAuth sign-in acceptance remain outstanding.

Review instructions and scoped start/stop commands: `docs/LOCAL-REVIEW.md`. The new UI source is in `C:/Users/james/.cache/qqq-authentik-access-ui`; it is not in the published frontend JAR yet. No changes have been committed or published.

Final live result: `target/access-smoke.log` passes role creation, group inheritance, searchable selections, membership add/remove, direct grant save/revoke/reopen/restore and inherited access retention. The frontend proxy and group permission/sign-in checkbox payload were verified, and the review UI returns HTTP 200. `review.sam` is seeded with both direct and inherited application grants for manual review.

### Catalog scaling verification (2026-11-04)

Direct grants now use guarded 25-resource catalog pages with application/type/search filters and page-scoped bulk editing. Complete direct selections remain independent of page requests; unknown and off-page grants are retained. Generated 1,000-table functional coverage passes. Backend verify: 331 tests and coverage gate; frontend: 47 tests, typecheck and lint. Live frontend proxy serves the new catalog. This is not a production concurrency benchmark or 1.0 release acceptance.
