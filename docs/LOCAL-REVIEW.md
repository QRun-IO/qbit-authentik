# Local review

This host runs the local backend with QQQ 4.1.0-RC.21 and either its frontend
dependency or an explicitly supplied frontend JAR. It is a local manual-review
environment, not a release or a production deployment. The running packaged
review is at **http://127.0.0.1:18300/app/authentikAdmin**; its artifact path and
SHA-256 are recorded in `target/review-process.json`.

## Start and stop (Windows)

Requirements: Java 21, PowerShell 7, Docker Desktop with Linux containers.

```powershell
./scripts/Start-Review.ps1
# Optional alternate UI port:
./scripts/Start-Review.ps1 -Port 18301
# Serve an unpublished production build directly through QQQ:
./scripts/Start-Review.ps1 -FrontendJar C:/Users/james/.cache/qqq-authentik-access-ui/target/qqq-frontend-next-1.0.0-production-review.jar
./scripts/Stop-Review.ps1
```

The launcher builds with the Maven wrapper and starts a hidden JVM. First boot
can take several minutes. `target/review-server.log` prints `REVIEW UI`,
`REVIEW AUTHENTIK` and `REVIEW MAIL` once ready. Build failures are in
`target/review-build.log`; JVM stderr is in `target/review-server-error.log`.

Open <http://localhost:18300/app/authentikAdmin>. No password is required for
the QQQ host: it automatically signs in as the synthetic review operator.
The application and Authentik stack ports are bound to 127.0.0.1. Never expose or deploy
this test host. Existing local Authentik stacks are not reused or changed.

A new Authentik 2026.8.3 server/worker, PostgreSQL and Mailpit stack is created
per launch. Four synthetic people and two review groups are added to the
contract-test blueprints. Writes use the dedicated non-superuser service
account and retain the qbit's live authorization, audit and safety checks.
QQQ audit/approval/policy and synchronization records use a private H2 SQL
database initialized from the published migrations. Stopping the host discards
review data; restart to reset. Use Stop-Review to remove the owned containers.
Native Authentik notifications reach the loopback app through Docker Desktop's
`host.docker.internal` gateway. The generated webhook secret stays in runtime
configuration and is not written to the ownership receipts. This launcher
requires Docker Desktop on Windows; other Docker host networking is unverified.

## Review checklist

- Open Identity, People and Groups; inspect parent/child record screens.
- Edit `review.sam` or `review.alex`; verify the updated record.
- Create a user; inspect the captured recovery email in the printed Mailpit URL.
- Create a group, add/remove a review user, edit its permissions/policy.
- Deactivate/reactivate a review user and inspect the audit trail.
- Try editing yourself or a protected account and verify the guard refuses it.
- Requests granting identity administration should queue for second approval.

## Limits

Automatic local login does not test OAuth, real claims mapping or personal
token exchange. The default session is one operator, so completing a
second-person approval uses a fixed second synthetic review identity in the
browser acceptance test described below. This does not verify real login. Personal token
creation/rotation requires a real OAuth host with the broker configured.
Enrollment now includes an invitation stage, username prompt and protected
user-write correlation policy. Password setup uses recovery. The host enables
the SQL mirror, webhook ingress and Quartz synchronization jobs. Full rendered
enrollment with selected application-role assignment is verified through the
rendered browser, local email, native notifications, SQL intent completion and
actual Authentik membership/audit. Audit and policy persistence across restarts, production rollout and all
contract tests remain separate release gates.

## Application access editor (2026-11-04)

Live browser smoke: `node scripts/Smoke-Access-UI.cjs` uses the running frontend
and backend, checks catalog/search/draft selections and inherited grant sources,
then cancels without executing changes. It requires the frontend worktree's
installed Playwright and Chromium. `QBIT_REVIEW_FRONTEND` and `QBIT_REVIEW_UI_URL`
override the defaults. Screenshots and the run log belong in `target/`.

The 2026-11-04 refreshed review stack passes this smoke check. The frontend now
accepts QQQ's omission of empty application IDs in catalog JSON; without that
fix the matrix displayed a catalog-loading error despite a successful HTTP response.
The same smoke also passes against the packaged JAR served by QQQ: set
`QBIT_REVIEW_UI_URL=http://127.0.0.1:18300` before running it. Real OAuth,
two-operator execution and full workflow acceptance remain separate requirements.

The new controls are in the isolated frontend worktree `C:/Users/james/.cache/qqq-authentik-access-ui`, branch `feature/authentik-access-ui`. The published frontend JAR does not yet include them. Start the backend using `scripts/Start-Review.ps1`, then run `scripts/Start-Access-UI.ps1`. Open **http://127.0.0.1:18301/app/authentikAdmin**. Both servers bind to loopback.

- **Users → select a user → Actions → Edit User Permissions:** select direct grants, enter a reason, Review, then execute. Expand inherited access to see its source. Direct user grants use an isolated Authentik group which cannot be shared through these screens.
- **Users → Add To Group Or Role / Remove From Group Or Role:** choose the group or reusable role.
- **Groups and Application Roles → Create Application Role:** name it and select permissions. Review Viewer and Review Editor are seeded examples for Review Documents.
- **Group or role → Edit Permissions And App Access:** checkbox selections for named grants and application sign-in access. **Edit Policy** retains the existing resource/action matrix.
- **Group or role → Edit Group:** select the parent groups or roles whose permissions it inherits. Clearing the selection removes all parent assignments.
- **Group or role → Add Members / Remove Members:** search and select users. Selections survive changes to the search.

Unchecking a direct grant does not revoke access supplied by another group, role or policy. Changes take effect on session refresh; this automatically logged-in review host is not an OAuth/fresh-sign-in acceptance test. Protected accounts, self-edits, subset checks, last-administrator protection and approval requirements remain enforced.

Use `scripts/Stop-Access-UI.ps1` and `scripts/Stop-Review.ps1` to stop these processes. Review data is disposable. Source changes have not been committed or published.

Manual review containers are named `qbit-authentik-review-<unique-id>-<component>` and carry `io.qrun.qbit.project` / `io.qrun.qbit.review` labels. Only this manual launcher disables Ryuk; `Stop-Review.ps1` validates the saved JVM identity and each recorded container’s ownership before cleanup. Use that script when finished.

## Permission catalog at scale

In Edit Permissions or Edit User Permissions, use Application and Resource type to narrow the matrix, then search by resource name or label. Each page shows at most 25 resources. Select/Clear on this page changes only its named permissions; other pages remain selected. Use Show → Selected direct grants to inspect/remove existing or legacy grants, or Show → Why access is granted to inspect inherited sources. These views also paginate. Review still validates the final change before saving. This does not automatically grant access to future resources.


## Saved workflow acceptance (2026-11-05)

Run `node scripts/Verify-Access-Writes.cjs` against the default review host on
18300. It changes only `review.sam` through rendered UI controls, checks the
provider independently, restores the initial direct read grant, adds/removes
Review Viewer, and verifies SQL administrative audit success. It refuses to
start if that user is already a Review Viewer member. An interrupted run can
leave a synthetic change; inspect the user before rerunning.

Run `node scripts/Verify-Invitation-UI.cjs` to create one unique synthetic
invitation with Review Viewer selected, receive it in local Mailpit and finish
username signup in a browser. It verifies native callback processing, COMPLETE
SQL intent, actual provider membership and one successful deferred ADD_MEMBER
audit. The resulting synthetic enrollee is retained for inspection. One-time
invitation links and credentials are never printed. Consuming an invitation
then closing the browser before signup abandons that enrollment session; use a
fresh invitation for another attempt.

Both workflows passed on the SQL-backed review host. Evidence is in
`target/review-access-writes.log` and `target/review-invitation-ui.log`.
These checks do not prove real OAuth sign-in, production scale, or the complete
release contract suite.

`node scripts/Verify-Group-Inheritance.cjs` verifies role permission addition and
removal, parent-role assignment and removal, inherited user access/source labels,
actual Authentik parent/attribute values and SQL audits. It restores the synthetic
Review Editor/Review Readers groups and refuses a nonbaseline starting state.

`node scripts/Verify-Approval-UI.cjs` verifies pending changes leave Authentik
unchanged, self-approval is refused, a distinct synthetic operator approves,
and the provider grant and SQL approver audit agree. It removes the granted
permission afterward. The test-only ReviewAuthentication recognizes the fixed
`qbit-authentik-review-second` session selector for review.second; every other
session uses review.operator. The anonymous frontend creates a session during
boot, so the test selects the second identity after boot, before the action.
This selector exists only in test sources and is not an authentication mechanism.

Both group inheritance and two-person approval checks passed. Evidence is in
`target/review-group-inheritance.log` and `target/review-approval-ui.log`.
