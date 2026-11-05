# Remaining release acceptance

- [x] Add server-owned invitation correlation policy and prove native prompt forgery cannot replace or fabricate the reference (426 units +2 real Authentik contracts/coverage, release-invitation-policy-live-04.log).
- [x] Implement uncached guarded invitation-flow validation in the enrollment-evidence path; verify native service-account reads and rejection after policy disablement (429 units +2 real Authentik contracts/coverage, release-invitation-flow-live-04.log).
- [x] Connect the existing group/QQQ-role picker and public invitation action to validated flow and durable intent-before-email; cancel pending intent after consumption/expiry.438units +44selected integrations/coverage pass (release-invitation-create-integration.log).
- [ ] Connect durable event pairing and deferred audited assignments under the original immutable operator's current authority; validate again before grants. Complete actual public invitation/email/signup/membership and rendered UI acceptance, then deploy and verify host role/policy configuration.
- [ ] Verify and close the legacy no-group invitation path's behavior when a configured flow slug cannot resolve: current flowUuid can return null and the body omits flow. Do not permit an unintentionally unbound invitation.

- [x] Implement guarded authoritative invitation event verification and test malformed/mismatched/native-vs-custom/edited/impersonated cases.423units +real native enrollment/service-account verification and coverage pass (release-invitation-evidence-live.log).
- [x] Persist invitation operator/group intent, one-time enrollment binding and serialized grant attempts; verify expiry completion and scope-bound settled retention on H2/PostgreSQL (426 units +42 PostgreSQL integrations and coverage, release-invitation-retention-postgres.log).
- [ ] Connect persisted invitation intent and event verification to UI and audited assignments; prevent copied references and replay from granting access through full native enrollment acceptance.

- [x] Verify native invitation/enrollment ordering and event correlation: real2026.8.3 consumes/deletes invite before creating user; later user_write carries created-user pk and fixed data.419units +provider contract/coverage pass (release-invitation-enrollment-live-03.log).
- [ ] Implement and verify automatic invitation group/QQQ-role assignments per INVITATION-ASSIGNMENTS.md; correlation proof alone must not authorize writes.

- [x] Verify refreshing OAuth mapper's bounded directory API outage fallback on H2/PostgreSQL: failed scan preserves watermark; no API calls for fresh mirror resumes; revocations/inactive users/stale snapshots deny.419units +39PG/coverage pass (release-mirror-outage-postgres.log). Legacy mapper migration, widget fallback and deployed-provider acceptance remain separate.

- [x] Reproduce and resolve sync cadence/freshness collision: five-minute schedule retains fifteen-minute permission freshness. SQL regression covers a four-minute scan, one skipped tick, and stale rejection; 414 units +37 PostgreSQL contracts/coverage pass (release-sync-freshness-postgres.log). Actual API throughput, jitter and prolonged contention remain scale gates.

- [x] Run complete Authentik contracts on unchanged current source: release-full-contracts-03.log passes 376 units, 76 integration tests, zero skips and coverage. Repeat for final release source after remaining implementations.
- [ ] Verify grant and revoke behavior through a fresh OAuth sign-in with the production host mapper configuration (the local review host logs in its operator automatically).
- [ ] User review of the new permissions/assignment UI.
- [ ] Package the frontend change and complete the coordinated backend/frontend release when authorized.

Implementation is recorded in SESSION-STATE.md. The user authorized the full production release goal; do not call it complete without the acceptance evidence in RELEASE-1.0.md. Deployment destination remains to be confirmed.

- [x] Add direct-grant resource matrix, server-side catalog paging/search, scoped bulk controls and 1,000-table functional coverage.
- [ ] Benchmark production-like group depth, membership counts, latency and concurrent permission edits; the 1,000-table test does not cover these.
- [x] Verify 1,000-level hierarchy with 1,000 users and concurrent snapshot readers, cycle safety and refreshed revocations.
- [x] Add sync storage schema and authenticated, bounded webhook envelope; verify SQL constraints and exclusion of arbitrary context.
- [x] Implement durable inbox deduplication, leased claims, retries, retention and atomic fenced local writes; verify the same seven race/recovery scenarios on H2 and PostgreSQL.
- [ ] Connect durable inbox, retries, reconcile scheduling, mirror projection/fallback and session invalidation; then enable MIRROR/WEBHOOK with real PostgreSQL and Authentik acceptance.
- [x] Add uncached complete sync reads, reject incomplete/changing pagination, and verify watermark filtering and membership projection against live Authentik.
- [x] Add allowlisted mirror projection and QQQ-action writer with RECORD audit, stable IDs and idempotent replay tests.
- [x] Verify mirror/audit commit and rollback through QQQ's H2 and PostgreSQL backends; handle unique username/email swaps without changing IDs or exposing intermediate values.
- [x] Recheck candidate deletions against live Authentik before committing a full sweep, then connect the mirror writer to the lease-protected full-refresh worker; H2 and PostgreSQL acceptance pass.

- [x] Add and unit-test uncached deletion/scope-exit preflight; existing users are checked with a server-scoped immutable UUID query.
- [x] Add incremental reconciliation with retained profiles, group-member discovery, scope-change full baselines and fresh source-superuser checks; verify on H2/PostgreSQL.
- [ ] Add metrics, scheduling/ingress and persistent session reevaluation before feature enablement; complete mirror fallback and end-to-end acceptance.
- [x] Verify nonzero MFA and rolling failed-login metrics against live Authentik, including unconfirmed devices, old events and other users.
- [x] Add uncached, immutable-ID mirror authorization reads with freshness/scope checks and transaction isolation; verify on H2 and non-UTC PostgreSQL.
- [ ] Bind authenticated sessions persistently to immutable Authentik identities and connect request-time reevaluation without restoring old token or session grants. The mirror reader alone does not implement this.
- [x] Implement durable write-once session binding storage, cross-node lookup, revocation tombstones, expiry and retention; verify concurrent creators on H2 and PostgreSQL. Authentication wiring remains pending.
- [x] Add and verify signed immutable-user identity claim against real Authentik tokens, including username/email changes and omission without profile scope. Production mapping deployment and adapter remain pending.
- [x] Rebuild the corrected frontend artifact and smoke-test it through QQQ's actual static JAR serving path.
- [x] Renew directory and webhook leases around each sync HTTP request; verify cancellation discards partial results and old workers cannot publish (373 units and 18 PostgreSQL contracts plus coverage).
- [x] Verify current-grant replacement mapper with same-session revocation, host fallback, immutable-identity rejection and credential narrowing (389-unit/coverage gate). OAuth request-path wiring remains open.
- [x] Implement opt-in OAuth binding/refresh adapter and seven protocol tests (396-unit/coverage gate). Real OAuth plus SQL cross-node revocation and callback/refresh acceptance remain open.
- [x] Exercise actual native JWT verification, same-token revocation across separate module instances, service identity and logout through H2/PostgreSQL (397 units +19 PostgreSQL contracts). Real Authentik issuance and separate deployed-node/interactive acceptance remain open.
- [x] Verify actual Authentik-issued token, provider discovery/signature, live group revocation and production reconciliation with SQL session binding (397units + focused live contract/coverage). Interactive cookie/refresh and independently deployed nodes remain open.
- [x] Verify native authorization-code exchange, cookie resume, encrypted refresh-token HTTP exchange and logout through H2/PostgreSQL (398units +20PG contracts). Actual Authentik browser flow remains open.
- [x] Implement bounded authenticated HTTP inbox adapter using host connection provider; real H2/PostgreSQL HTTP contracts pass (399units +28PG/coverage). Registration remains disabled pending handler/ESB/scheduler integration.
- [ ] Resolve/stability-verify intermittent PostgreSQL renewal SQLException from release-webhook-http-postgres.log; isolated and full reruns pass but original root cause unknown. Safe SQL-state diagnostics added.

- [x] Connect targeted live-state event handler to host inbox/worker; verify stale-delete safety, group grant/revoke, idempotent replay, bounded metric reads and preserved baseline watermark (402 units +30 PostgreSQL contracts/coverage).
- [ ] Diagnose intermittent PostgreSQL connection reset during identity-swap test setup in release-targeted-events-postgres.log; unchanged-source rerun passes, cause unknown.

- [x] Define native guarded sync processes for2s inbox/15min reconcile/nightly full/retention and verify execution through QQQ on H2/PostgreSQL; registration and actual scheduler runtime acceptance pending.
- [x] Defer directory-lease contention without exhausting event failure attempts; repeated contention then recovery passes on H2/PostgreSQL (404units +32PG/coverage).
- [ ] Investigate shared-host socket allocation exhaustion observed in release-sync-process-postgres.log; no global settings changed. Do not conflate with earlier reset/renewal exceptions without evidence.

- [x] Connect post-commit HTTP delivery to inline processing or optional ESB; verify real embedded broker/native asynchronous trigger, real Quartz recovery, idempotence and resulting grant/revoke on H2/PostgreSQL (406units +34PG full gate; strengthened2+2focused checks).
- [x] Register opt-in sync metadata/processes/routes with host database, scheduler/destination and namespace validation. Native route loader, isolated HTTP secrets and producer-to-SQL/inbox/grant publication verified;418units +38PG/coverage pass (release-sync-registration-postgres.log).
- [ ] Verify minimal host classpath combinations without optional RDBMS/Javalin/ESB dependencies, full application server startup and staging migration/rollback before production enablement.

- [x] Anchor bearer deadlines to signed iat and cap session lifetime at30days; verify invalid age, tombstone-purge replay rejection, cookie refresh and actual Authentik tokens (409units +35PG +1live contract/coverage).
- [ ] Align verified OAuth issuer with the configured Authentik directory/public URL before production enablement; retain public/internal URL support.
- [x] Verify durable invitation event pairing in either order, restart, conflicting identity/rollback and completed replay on H2/PostgreSQL (441 units +37 PG/coverage).
- [ ] Connect invitation evidence transitions to inbox ownership transaction and execute original-operator-authorized audited grants; verify lease loss, concurrent delivery and native full workflow.
- [x] Connect authoritative invitation evidence to inbox transaction; verify concurrent events, rollback, lost lease during API reads and both delivery orders on H2/PostgreSQL (445 units +41 PG/coverage).
- [ ] Execute READY invitation grants through AuthentikAdmin with immutable original-operator identity/current rights and durable attempts, then verify full native/signup/UI workflow.
- [x] Connect READY invitation grants to AuthentikAdmin with current immutable actor/target checks, normal guardrails, audit-before-write and durable no-replay attempts (460 units +41 PG/coverage).
- [ ] Verify public invitation/email/native signup/inbox/audited membership on SQL host; add partial multi-group failures and native authority changes, then rendered UI acceptance.
- [x] Verify native public invitation, Mailpit delivery, protected username signup, reversed native-event delivery, actual membership and SQL administrative audit (460 units +2 native/coverage).
- [x] Preserve/resume READY work across read-only and membership-feature pauses without spending failure retries (462 units +41 PG/coverage).
- [ ] Update local review to SQL/protected enrollment/event delivery, then render and exercise assignment UI; native webhook transport and remaining failure cases still open.
- [x] SQL-backed review host, protected enrollment configuration, strict QQQ startup, rendered permission draft smoke and actual native notification-to-inbox-to-mirror delivery verified (2026-11-05). Final launcher clean-start and saved assignment/invitation browser acceptance remain pending.
- [x] Move machine-to-machine webhook to /qqq/hooks/{prefix}/webhook per QQQ contract; namespace/authentication/strict-auditor regression and462-unit coverage gate pass. Changed blueprint contract/full IT rerun still required.
- [x] Rendered direct-permission and role membership add/remove, actual Authentik state and SQL audits verified; repeatable Verify-Access-Writes.cjs added.
- [x] Rendered Invite User with selected Review Viewer, local email, browser username signup, native webhook processing, COMPLETE SQL intent, provider membership and exactly one successful deferred audit verified; Verify-Invitation-UI.cjs added.
- [ ] Complete rendered group/role permission editing, parent-role inheritance and two-person approval acceptance; review handling of consumed but abandoned invitation intents.
- [x] Rendered role permission edit/removal, group parent-role inheritance/removal and inherited user source labels, actual provider state and SQL audits verified (Verify-Group-Inheritance.cjs).
- [x] Two distinct synthetic review operators: pending leaves provider unchanged, self-approval refused, second approval applies, audit identifies approver, role restored; rejection also verified (Verify-Approval-UI.cjs).
- [x] Final native-gateway launcher clean startup and fresh full invitation-browser/native-webhook assignment passed (review-clean-launch-invitation-03.log). Real OAuth login remains separate.
- [ ] Collect full unchanged-Java-source verify gate target/release-full-after-ui.log, exec1568;462units passed, contracts running. Never rebuild Java until terminal.

- [x] Fix local review token widget SQL mappings; preserve explicitly named reminder columns. Regression reproduces missing-column error; 9 focused tests pass.
- [ ] Resolve final full-suite failures: SchemaDriftIT placeholder regex and PostgreSQL connection errors in mirror/inbox tests (release-full-after-ui.log, 108 integrations / 3 errors).

- [x] Verify repaired Tokens and app passwords in real browser with an actual synthetic password-reset token and rendered scope. Review instance restored on port 18300.
