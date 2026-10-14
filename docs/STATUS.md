# Status

The Authentik qbit's progress through DESIGN.md section 11, with links. Updated with each PR.

## v1 = phases 0-3 (the full user lifecycle and group/permission management)

| Phase | State |
|---|---|
| 0. Foundations and migration | agent items done; **owner items open** (checklist items 6-8, 10, then 12) |
| 1. Read-only plus the permissions model | done, except the mirror tables, reconcile and the access-matrix widget (see "Not built yet") |
| 2. Memberships and permission editing | done, except the webhook route, ESB trigger, inbox and session re-evaluation marking |
| 3. Full user lifecycle | done, except the optional snapshot export |
| 4. RBAC role management | post-v1, not started |
| 5. Policies and full CRUD (DESIGN.md section 12) | 5a policy model (#14), 5b policy editor (#15), 5c user and group CRUD additions; the Next UI widget is a separate qqq-frontend-next PR |
| 6d. Personal access token Preferences | implemented on `feature/token-preferences`; draft until a QQQ RC contains QRun-IO/qqq#1162 |

### Phase 6d: Access tokens Preferences

The `TOKENS` feature registers the `access-tokens` section and user-menu shortcut without an app or permission gate. The provider resolves the current Authentik operator and reads only their app passwords, with read-only metadata and optional scope inputs. Create, rotate, extend and revoke use `AuthentikAdmin`, including live protection/ownership checks, broker exchange and audit. Preferences uses core's one-time secret response independently of process delivery; keys never enter section values or local storage.

This branch builds against the locally installed `4.1.0-PREFS-SNAPSHOT`. Keep any PR draft until the RC shipping #1162 is available, then replace the marked POM stand-in. Last-used tracking is not implemented in this branch, so the section omits it. Next UI renders the section and user-menu entry through the core Preferences contract.

`AccessTokenPreferencesTest` exercises the core dispatcher with FakeAuthentik and an in-memory QInstance, including lifecycle, scoped rotation, ownership, protected-user/broker refusals, read-only validation, and searches of local tables, audit, reloaded section values, events and captured logs for leaked keys.

Validation (2026-10-13): `./mvnw.cmd -q -o verify -DskipITs` passed on Windows: 253 tests, no failures/errors/skips; JaCoCo 91.48% instruction and 100% class coverage. Contract ITs were intentionally excluded.

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
