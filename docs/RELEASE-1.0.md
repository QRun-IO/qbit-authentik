# 1.0 production release acceptance

## RC checkpoint approved 2026-11-05

The user approved committing, pushing and merging the current backend and companion
UI as an RC candidate. This does not close the full 1.0 acceptance gates below.
The local UI passes permission editing, membership/role assignment, inheritance,
two-person approval, native invitation enrollment and the token-widget regression.
The latest full gate passed 462 unit tests but had three errors among 108 integration
tests: SchemaDriftIT's literal-placeholder regex, a PostgreSQL mirror connection
closure and a PostgreSQL webhook-inbox I/O error. The subsequent token-widget fix
passed nine focused tests and real-browser acceptance. Blueprint startup also
exhibited a PostgreSQL deadlock before recovering. These remain documented RC
limitations; required remote checks and branch protections still apply.

Objective authorized 2026-11-04: take the QBit and its coordinated UI to a full 1.0 production release. Earlier local-review-only scope is superseded. The goal remains active until the delivered release is verified; a version bump or local test run is not completion.

## Requirements and evidence

| Requirement | Evidence required | Current state |
|---|---|---|
| Full lifecycle, assignments, QQQ roles, direct grants and policies | Guard matrix, real Authentik contract tests, UI workflows | Implemented; final unchanged-source gate and UI acceptance pending |
| Read-only defaults, scoped reads, protected/self/last-admin safeguards, subset rules, audit-before-write, two-person approval | Unit/architecture tests plus two-operator live acceptance | Unit coverage exists; live acceptance pending |
| Fresh OAuth sign-in and revoke behavior | Real token/claims flow through production mapper, fresh sign-in after edits | Actual Authentik-issued same-token revocation passes through native verifier, reconciliation and SQL bindings; interactive browser acceptance pending |
| Webhook authentication, durable inbox, ESB handling, session invalidation | DESIGN 7.1 and 9.5 contract/security tests, retry/idempotency and latency evidence | Producer registration, HTTP ingress, inline processing, native ESB runtime and timer recovery verified on SQL hosts; scale and deployed-host acceptance pending |
| Mirror tables and reconciliation | DESIGN 7.2 metadata, persistence, reconciliation and stale-data tests | Full/incremental workers, metrics, scheduling and producer registration verified; fallback and host rollout pending |
| Group tree, user access matrix and health | DESIGN 8 workflows, guarded bounded widget data and UI acceptance | Partial; remaining views unimplemented |
| Large systems | 1,000-resource functional tests, bounded policy editor, realistic hierarchy/membership and concurrent-edit checks | Both editors paged; 1,000-level concurrent-reader check passes; API/concurrent-edit gates pending |
| Production frontend artifact | Full tests, lint/typecheck, static export/JAR, served artifact smoke and UI acceptance | Corrected static export/JAR built and served directly by QQQ; real-browser catalog/search/draft selection/source/cancel smoke passes. Full workflow and user acceptance remain pending |
| Clean Authentik contracts and schema compatibility | CI=true wrapper verify, no manual bootstrap repair | Full baseline gate passes: 376 units, 76 integration tests, zero skips and coverage; repeat after subsequent session/mirror implementation |
| Host integration and migration | DESIGN 4.4 / PHASE0-OWNER-CHECKLIST staging rehearsal and actual host configuration | Must verify current external state |
| Release supply chain | Coordinated reviewed changes, green remote CI, versioned artifacts and immutable release tag on primary Gitea | Pending |
| Operations | Upgrade/rollback instructions, defaults/flags, secret handling, retention and monitoring checks | Existing docs require final audit |

Authentik administrative RBAC remains explicitly post-v1 per the approved design and user clarification. Snapshot export and Alerts integration are optional in the approved spec. Required functionality will not be reclassified as optional to obtain a green release.

## Execution order

1. Run full suites and diagnose bootstrap/test failures without weakening assertions.
2. Close lifecycle/authentication/security and large-catalog gaps.
3. Implement outstanding approved v1 integrations and views with targeted tests.
4. Build production artifacts and exercise end-to-end workflows and host rollout in staging.
5. Audit requirements against evidence, then coordinate primary-forge release/CI and verify published artifacts and rollout.

All Docker/process operations must stay scoped to unique ownership identifiers; preserve other agents' work. Keep the independent local review instance available whenever possible.

## Evidence collected during release work

- Invitation event verifier implemented and proven through non-superuser service-account API reads of real native enrollment events.423units +live provider contract/coverage pass (target/release-invitation-evidence-live.log). Guarded uncached detail reads, identity/action/flow/time/reference checks, strict new-user validation and sanitized minimal facts are covered. Persisted intent, one-time binding/replay protection, UI and audited writes remain; no automatic membership assignment is enabled.

- Native invitation ordering verified against real2026.8.3:419units +InvitationEnrollmentContractIT and coverage pass (target/release-invitation-enrollment-live-03.log). Invitation consumption/deletion precedes account creation; user_write supplies the created account pk and fixed-data correlation. DESIGN corrected to require both stages, not immediate grant on invitation_used. Automatic assignments remain unimplemented; INVITATION-ASSIGNMENTS.md captures required persistence, identity/authority/replay checks and UI/end-to-end gates.

- Directory API outage acceptance passes419units +39PostgreSQL contracts/coverage (target/release-mirror-outage-postgres.log). Existing refreshing adapter uses fresh committed mirror grants without additional identity API reads; failed reconciliation cannot advance freshness, and revoked/inactive/stale identities cannot regain access. Native OAuth verifier remains active against the loopback issuer; this is not an actual provider shutdown or interactive outage test. See SESSION-IDENTITY.md for the required adapter migration and cut-over guard limits. Widget fallback remains outstanding.

- Public producer integration passes418units +38PostgreSQL contracts and coverage (target/release-sync-registration-postgres.log). MIRROR/WEBHOOK now explicitly opt-in, with six tables/jobs/native bound route registration and preflight host/name validation. Real HTTP tests verify namespace/secret separation; H2/PostgreSQL producer test verifies baseline, audit, accepted inbox event and resulting grants. Shared status dropdown registration corrected for multiple QBits. Native class-and-properties loading replaces unsupported lambda route references. See SYNCHRONIZATION.md; review runtime unchanged. Optional-classpath matrix, full host startup and staging/scale/fallback/invitation/UI acceptance remain.

- Cadence collision reproduced and fixed: five-minute incremental scheduling retains the fifteen-minute authorization ceiling. SQL regression covers scan duration of four minutes, one skipped tick, and fail-closed expiry; 414 units +37 PostgreSQL contracts and coverage pass (target/release-sync-freshness-postgres.log). Earlier fifteen-minute design cadence superseded with rationale in DESIGN 7.2. More frequent scans increase API demand; production-scale throughput/jitter remain unproven and feature registration remains disabled.

- 2026-11-05 issuer/source alignment gate passes 413 units, 37 selected integration tests (PostgreSQL and actual Authentik), zero failures/skips and coverage: target/release-issuer-live.log. Production registration and final complete contracts remain pending. Source inspection additionally identified a possible freshness-denial gap between the 900-second reconcile cadence and 15-minute scan-start-based freshness; deterministic reproduction and resolution are required before enablement. This remains a no-go for 1.0.

- First full frontend run: 12 failures under default unbounded worker concurrency. A four-worker run passed 339 files / 3,656 tests, with one existing skip (target/release-frontend-tests-02.log). Worker cap now configured; timeout assertions were not weakened.
- Static frontend build and isolated resource JAR packaging succeeded (target/release-frontend-build-01.log, release-frontend-jar-01.log). Review JAR is unpublished and must be rebuilt after subsequent source edits.
- Policy editor now uses server-paged catalog data (25 resources), with explicit page bulk scope and a passing 1,000-resource selection regression. Both editor suites pass 32 tests; typecheck, changed-file lint and the second static build pass.
- Fixed caller-supplied approval and stale preview execution: all public request execution removes approved; external plans are revalidated; only approve(stored-id) reaches trusted approval execution. 59 related security/admin tests passed (target/release-approval-tests.log).
- Contract run 01 bootstrapped cleanly, then lost its disposable containers. Run 02 passed 55 contracts with unique names and explicit JVM cleanup (local Ryuk disabled); bootstrap succeeded unattended after 424 seconds. This run is diagnostic because source changes occurred while it was active; a final immutable full run remains required.
- Fresh credential-OAuth grant/revoke regression passed with 332 units and coverage (target/release-oauth-grants-02.log). Interactive browser sign-in remains a separate acceptance gate.
- In-process scale check passes for 1,000 users, 1,000 hierarchy levels, four concurrent readers, cycles, and a refreshed revoked-grant snapshot (roughly 0.9–1.0 seconds locally). This does not establish API latency or concurrent-write safety.
- Sync storage foundation added: read-only mirror/inbox/checkpoint metadata and additive docs/schema-sync.sql. H2 PostgreSQL-mode tests execute the DDL, match every metadata column and verify event/membership/identity uniqueness. Authenticated bounded webhook envelope strips arbitrary context before persistence. Five targeted scale/schema/envelope tests pass. No route, reconciler or fallback is enabled yet; actual PostgreSQL acceptance and end-to-end sync remain required.
- Durable inbox implementation now commits before acknowledgment, deduplicates by canonical event UUID, leases batches of at most 50, retries at most five times with persisted backoff, fences stale workers and expires terminal rows after 30 days. Pending work is retained. Local mirror/session-marker writes can run inside the ownership-checked transaction; network reads must happen outside it. Seven identical tests pass on H2 and actual PostgreSQL, including concurrent delivery/claims, restarts, expired leases, rollback and retention (target/release-inbox-postgres-02.log). Full unit/coverage gate passes 344 tests (target/release-inbox-unit-verify.log). No inbox test containers remain. Ingress, host database adapter, actual live-state handler, mirror audit/reconciliation, ESB/scheduling and session refresh remain unconnected and the features remain disabled.
- Strict uncached synchronization reads now reject missing/contradictory pagination, size ceilings, duplicate IDs, changing counts and scope violations. Mirror projection checks both membership representations, normalizes email identities, excludes unrelated attributes, resolves inheritance, and clears inactive-user grants. The QQQ-action writer retains RECORD audit and stable IDs (memory action semantics tested). Live Authentik directory/projection/watermark contract plus all 353 units and coverage pass (target/release-mirror-read-contract.log). Host-RDBMS writer/audit atomicity, rename swaps, and live deletion rechecks remain gates; API pagination is not an atomic directory snapshot.
- Repackaged the latest static frontend into the unpublished review JAR (target/release-frontend-jar-02.log). Both review HTTP endpoints return 200 when checked with required localhost access. Full frontend rerun 03 encountered local-server failures under sandbox restrictions; the same four wrapper tests pass with localhost access (target/release-frontend-network-diagnostic.log). Do not treat the frontend full rerun as passed until its final results and remaining failures are resolved.
- Frontend run 03 was explicitly stopped after confirmed localhost-fixture restrictions (not an observation timeout). Run 04 with required localhost access passed all 339 files / 3,658 tests, one existing skip (target/release-frontend-tests-04.log). No frontend assertions were weakened.
- Mirror writer transaction tests now pass through QQQ's H2 and PostgreSQL backend modules: outside connections cannot see uncommitted mirrors/audits; rollback removes both; committed rename swaps preserve IDs and hide temporary unique-name reservations. PostgreSQL run 01 exposed an incorrect test JDBC schema separator; run 02 corrected it and passed both scenarios (target/release-mirror-postgres-02.log). Worker/connection integration and live deletion rechecks are still required before enabling MIRROR.
- Guarded deletion/scope-exit preflight now passes eight focused sync tests, three schema tests, and a live Authentik contract together with all 359 units and coverage (target/release-deletion-live.log). Fresh detail 404s confirm deletions; existing users require an empty complete server-scoped immutable-UUID query. Failures abort rather than remove rows. Worker integration remains pending; this does not establish end-to-end reconciliation.
- Full-refresh integration passes all 364 units plus 14 PostgreSQL contracts and coverage (target/release-worker-postgres.log). One directory lease serializes publishers; the worker uses the host connection provider, live deletion preflight, inbox fencing and one QQQ transaction for mirror/audit/checkpoint plus the required session-publication hook. Callback rollback/commit behavior is tested. The actual session marker adapter, incremental sync, metrics, scheduling/ingress and fallback are still pending; feature flags remain unavailable.
- Incremental reconciliation now preserves the complete local baseline, applies changed profiles and complete group graphs, discovers previously unseen scoped members, and recomputes inherited access. Scope/configuration changes force full baselines. Previously true API superuser status is refreshed so demotion does not remain sticky. Latest gate: 370 units, ten PostgreSQL worker contracts and coverage (target/release-incremental-final.log); preceding live Authentik scoped-identity contract passes (target/release-incremental-contract.log). Metrics/scheduling/session integration/fallback and full end-to-end release acceptance remain pending.
- Long-scan renewal passes 373 units, 18 PostgreSQL worker/inbox contracts and coverage (target/release-sync-renewal-final.log). Explicit per-request checkpoints renew both leases and stop scans after ownership loss; no shared callback state or background thread. This is functional safety evidence, not the outstanding production-scale latency benchmark.
- Fresh replacement mapper gate passes all 389 units and coverage (release-refresh-unit-verify.log), including five new refresh/security regressions. This is not end-to-end OAuth revocation acceptance; native OAuth adapter and durable binding integration remain pending.
- OAuth adapter now connects native authentication to durable bindings and fresh grants; seven isolated protocol tests plus all396units/coverage pass (release-oauth-adapter-unit-verify.log). No feature enablement. Actual provider/database cross-node and interactive acceptance remain required.
- Native verifier + real host SQL acceptance passes on H2/PostgreSQL: same signed token across separate module instances follows committed revocations, unchanged deadline, forged signature rejection, service username check and durable logout. All397units +19PostgreSQL contracts/coverage pass (release-signed-session-postgres.log). OIDC issuer is a local protocol fixture, not actual Authentik; provider/callback/deployed-node gates remain.
- Actual Authentik-issued same-token revocation now passes through native verifier, production full reconciliation and H2 mirror/binding storage; second module and original-session refresh lose removed real group grant; logout rejects reuse. All397units + focused TokenContract/coverage pass (release-authentik-session-live.log). Bootstrap recovered without repair. Interactive login/refresh and deployed-node acceptance remain.
- Native cookie/code/refresh protocol passes on H2/PostgreSQL with encrypted refresh storage, unchanged binding deadline, current permissions, missing-binding denial and credential cleanup;398units +20PG contracts/coverage pass (release-cookie-refresh-postgres.log). Loopback OAuth fixture does not replace actual Authentik browser acceptance.
- HTTP webhook ingress now tested on H2/PostgreSQL for auth-before-parse, committed dedupe, redaction, bounded chunked bodies and failure responses;399units +28PG/coverage pass on rerun (release-webhook-http-postgres-02.log). Initial run had an unexplained incremental-sync renewal SQLException; isolated/full reruns pass, SQL-state diagnostic added, cause not proven fixed. Route registration stays disabled pending processing/scheduling.

- Targeted event processing passes 402 units +30 PostgreSQL contracts/coverage (release-targeted-events-postgres-02.log). Events re-read current identities/group graph, retain untouched metrics and preserve baseline freshness; stale deletion/replay checks pass. First run had a connection reset during unrelated identity-swap test setup; stability remains an open gate. Scheduler/ESB/inline integration and actual event-latency acceptance remain pending.

- Native sync-process metadata/execution and contention deferral pass404units +32PostgreSQL contracts/coverage (release-sync-process-postgres-02.log). Automatic registration, actual scheduler timing, ESB/inline delivery and production enablement remain pending. Initial run encountered Windows socket allocation exhaustion in an existing mirror-access test; host stability acceptance remains open.

- Post-commit inline/ESB delivery now passes406units +34PostgreSQL contracts/coverage (release-event-delivery-postgres.log). Real embedded Artemis/native asynchronous consumption and real Quartz polling recover pending events; strengthened grant/revoke assertions pass on H2/PostgreSQL (release-event-permissions-postgres.log). These are bounded small-fixture checks, not scale, broker-outage or deployed-host acceptance. Automatic production registration remains disabled.

- Bearer lifetime/retention gap closed: min(exp, signed iat + configured lifetime), max30days, invalid/missing/future/old issue times rejected. Purged logout cannot revive an old token even when core's optional lifetime cap is disabled. release-bearer-age-live.log passes409units +35PostgreSQL +1actual Authentik token contract/coverage, zero skips. Issuer-source alignment and production enablement remain pending.

- Invitation intent persistence gate passed: 425 units +41 selected PostgreSQL integrations, zero failures/errors/skips, coverage met (target/release-invitation-intent-postgres.log). This does not complete invitation assignment: UI, event integration, guarded audited grants and end-to-end acceptance remain pending. Release readiness remains NO-GO.


- Invitation lifecycle follow-up passes426units +42PostgreSQL integrations and coverage (release-invitation-retention-postgres.log). Matching existing attempts can record outcomes after expiry without permitting new attempts; daily settled-intent retention is wired and preserves unresolved rows. Automatic assignments remain unconnected; this is storage/lifecycle evidence, not end-to-end release acceptance.


- Server-owned invitation correlation artifact verified:426units +2native Authentik prompt/enrollment contracts and coverage pass (release-invitation-policy-live-04.log). Saved reference overrides forged form input; absent saved reference cannot be fabricated. Host flow validation and audited assignment integration remain pending; this does not establish end-to-end automatic memberships.


- Live invitation-flow validation now gates enrollment evidence.429units +2real Authentik contracts/coverage pass (release-invitation-flow-live-04.log): non-superuser configuration reads and same-event rejection after protection disablement. Bounded uncached pagination, stage/target identities and exact protected policy checks covered. Host role/policy rollout plus invitation UI/admin/event/assignment integration remain pending.


- Invitation creation/cancellation integration verified:438units +44selected integrations (42PostgreSQL+2native Authentik) and coverage pass (release-invitation-create-integration.log). Existing picker feeds persisted audited intent before remote creation/email; pending intent cancellation survives consumption/expiry. Actual deferred event-to-membership worker and native public-action/email/renderedUI acceptance remain incomplete. No production rollout or review restart.

- Invitation pairing gate: 441 units +37 PostgreSQL integrations and coverage pass (target/release-invitation-pairing-postgres.log). Either-order durable evidence, immutable identity, rollback and completed replay covered; missing-flow creation refused. Inbox worker/automatic audited grants and full native workflow remain incomplete.
- Invitation event evidence worker connected to production inbox processing; atomic claim/evidence persistence verified on H2/PostgreSQL, including concurrent claims, rollback and expired ownership. 445 units +41 PostgreSQL integrations and coverage pass (release-invitation-worker-postgres.log). Automatic audited membership execution and full native/UI acceptance remain incomplete.
- Deferred membership execution connected through AuthentikAdmin with immutable original actor/current rights, audit-before-write, fenced durable attempts and no replay after ambiguous/completed outcomes. Public invitation-to-event-to-grant SQL integration uses simulated provider HTTP. 460 units +41 PostgreSQL integrations and coverage pass (release-invitation-grants-postgres.log). Full native email/signup/membership and rendered UI acceptance remain required.
- Native invitation/email/signup/deferred-membership flow and SQL administrative audit passed:460 units +2 native contracts/coverage (release-invitation-native-grants-03.log). Subsequent pause/resume correction passed462 units +41 PostgreSQL contracts/coverage (release-invitation-pause-postgres.log). Native webhook notification transport and rendered UI acceptance remain open; final whole-suite gate must cover the eventual release source.

## Rendered saved-workflow acceptance (2026-11-05)

The SQL-backed local review passed direct-permission checkbox save/removal and
QQQ role membership add/removal through Review/Submit, with independent actual
Authentik reads and successful SQL administrative audits. It also passed UI
Invite User with Review Viewer selected, local Mailpit delivery, real browser
username enrollment, native notification-to-inbox handling, COMPLETE assignment
intent, actual provider membership and exactly one successful deferred ADD_MEMBER
audit. Scripts: Verify-Access-Writes.cjs and Verify-Invitation-UI.cjs. Evidence:
target/review-access-writes.log and target/review-invitation-ui.log.

These are synthetic local acceptance checks, not production OAuth or scale
proof. Group/role permission editing and inheritance, two-operator approval,
clean final launcher startup, full unchanged-source contracts, deployed-node
and staging rollout/rollback acceptance and release supply-chain remain open.

- RC checkpoint validation: 463 unit tests and JaCoCo passed via wrapper verify -DskipITs; companion UI 33 focused tests and typecheck passed. Full integration errors above remain open. UI PR205 is submitted on primary Gitea; authenticated merge and RC publication are pending.
