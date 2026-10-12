# Status

The Authentik qbit's progress through DESIGN.md section 11, with links. Updated with each PR.

## Phase 0: foundations (agent items done; owner items open)

| # | Item | State | Where |
|---|---|---|---|
| 1 | Repo, DESIGN.md, CI, README, CLAUDE.md | done | this repo (`develop`); private for now, see owner checklist D1 |
| 2 | Config, producer, `AuthentikActionUtil`, pinned schema + drift test | done | phase 0 PR |
| 3 | Testcontainers harness, fixture recorder, contract tests (b), (c), (d), (h) | done | phase 0 PR, `src/test/java/.../contract` |
| 4 | Open points (i)-(iv) resolved | done | DESIGN.md section 0.2; QRun-IO/qqq#1065 revision 3 |
| 5 | cluster-gitops PR (bootstrap, removals, sign-in policy, webhook, lint) | draft | KofTwentyTwo/cluster-gitops#72 |
| 6 | Staging rehearsal | **owner** | `docs/PHASE0-OWNER-CHECKLIST.md`, `docs/cluster-gitops-phase0/rehearse-phase0.sh` |
| 7 | Production apply | **owner** | checklist |
| 8 | Service-account token, Infisical, webhook secret | **owner** | checklist |
| 9 | Website-Backend wiring (ExternalSecret + env, qbit behind a disabled flag) | draft | KofTwentyTwo/cluster-gitops#73, Website-Backend draft PR |
| 10 | Seed attributes, break-glass password | **owner** | checklist |
| 11 | Read-only on staging | after 6-10 | flip `AUTHENTIK_QBIT_ENABLED` |

## Contract test results (Authentik 2026.8.3)

`CI=true ./mvnw verify`: 48 unit tests and 27 contract tests, all green; JaCoCo gate met.
