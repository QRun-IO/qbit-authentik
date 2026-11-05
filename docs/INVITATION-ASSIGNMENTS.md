# Invitation assignment implementation

Automatic group assignment after enrollment remains a 1.0 requirement. The
invitation form and admin action now save group/QQQ-role selections when MIRROR,
WEBHOOK and MEMBERSHIP are configured. The deferred event-to-membership worker
is connected through AuthentikAdmin with live original-operator authorization,
audit-before-write and durable attempts. The native email/signup/membership
workflow now passes on a SQL host. Rendered UI acceptance and the remaining
failure/recovery scenarios are still required before release.

## Pinned Authentik behavior

Inspection of the owned Authentik 2026.8.3 image establishes that the invitation
stage emits `invitation_used` and deletes a single-use invitation before the user
write stage creates the account. The event records `context.invitation_uuid`;
its user is not necessarily the future enrollee. The later native `user_write`
event records the created user's pk and a server-set `context.created` flag.
Fixed invitation data is merged into the pending enrollment data before this
write. The contract `InvitationEnrollmentContractIT` exercises this through the
real flow executor, including its same-endpoint stage redirects.

Verified 2026-11-05: `target/release-invitation-enrollment-live-03.log` passes
419 unit tests, this real-provider contract and coverage. The contract observes
the consumed invitation returning 404 while no user exists, then verifies the
new account and matching `user_write` event. Earlier setup failures corrected
the stage endpoint (`/stages/invitation/stages/`) and client redirect handling;
no provider repair was needed.

Neither the invitation-used event's user nor an email lookup is sufficient to
identify the account that should receive a deferred grant. A correlation value
is only a lookup key for pending intent; it is not authorization by itself.

## Implemented event verification

`AuthentikInvitationEvidence` now fetches native events by UUID through the
uncached, audit-read-guarded `AuthentikActionUtil.syncEvent` method. It checks
event ID, native action, exact flow executor path, the saved invitation/reference
and the supplied intent time window. User creation requires a strict boolean
`created=true` and a positive integral user pk; impersonation/agent markers fail
closed. It returns only minimal immutable facts, never grants or raw context.
API errors, missing events and malformed data produce sanitized failures.

The verifier is connected to the SQL inbox and deferred admin writer. Expected
values and time bounds come from persisted intent. Immutable paired evidence,
protected flow validation and one-time group attempts provide the additional
binding and replay protections described below.

Verified: `target/release-invitation-evidence-live.log` passes 423 unit tests,
the real enrollment contract using the QBit's non-superuser service account for
event verification, and coverage. Focused rejection and schema checks also pass
in `target/release-invitation-evidence-unit.log`.

## Remaining implementation and verification

### Server-owned correlation boundary

Native prompt stages merge validated form fields into `prompt_data`. A configured
editable field named `qqq_invitation_reference` can therefore overwrite the value
copied from invitation fixed data. Matching that value in `user_write` alone is
not proof that the account consumed the intended invitation.

The packaged `authentik/invitation-reference-policy.py` expression restores the
reference from the invitation object retained in the server's flow plan. Bind it
to the user-write stage binding with `evaluate_on_plan=false`,
`re_evaluate_policies=true` and `policy_engine_mode=all`, after all prompts and
immediately before user-write. Set the mode explicitly: Authentik defaults to `any`.
Authentik's re-evaluation marker disables policy caching. The expression first
removes submitted correlation and only restores a canonical UUID from that
server-held invitation; it does not assign any memberships. It contains no
credentials and must not log flow data.

Verified by `target/release-invitation-policy-live-04.log`: 426 unit tests, two
real Authentik enrollment cases and coverage pass with no failures or skips.
The cases submit an editable forged reference after consuming an invitation:
the saved reference is restored when present, and a fabricated reference is
removed when no reference was saved. Both use native prompt submission and
service-account event verification. Earlier runs stopped in test-client setup
because they incorrectly required a CSRF cookie for anonymous enrollment; the
corrected client sends the anonymous POST through the native executor.

`AuthentikInvitationFlow` now validates live configuration before the enrollment
evidence helper returns a created-user fact. It requires an enrollment flow with
one invitation stage before one user-write stage, unambiguous stage ordering,
stage-time re-evaluation and exactly one policy on the write binding. The policy
must be enabled, non-negated, non-expiring, fail closed on execution errors, have
execution logging disabled and match the packaged source (allowing platform
newlines and surrounding whitespace only). Additional write-binding policies are
rejected because policy evaluation can be concurrent. Place other enrollment
validation before this protected write stage.

Configuration reads are audit-read guarded, uncached, bounded and server-filtered;
incomplete pagination and mismatched target/stage IDs fail closed. Required
service-account reads add `authentik_flows.view_flow`,
`authentik_flows.view_flowstagebinding` and
`authentik_policies_expression.view_expressionpolicy` to the existing
`authentik_policies.view_policybinding`. No provider configuration writes are
granted. The test bootstrap contains these read permissions; host deployment must
apply the corresponding role update. `target/release-invitation-flow-live-04.log`
passes 429 unit tests, both native enrollment cases and coverage with no failures
or skips. It verifies configuration through the non-superuser service account
and rejects the same enrollment event after the policy binding is disabled.

The provider uses different IDs for policy lookup and serialization: filter
policy bindings by `policybindingmodel_ptr_id`, but compare their returned
`target` with the concrete flow-stage binding `pk`. The regression fixtures keep
these IDs distinct. Also, Authentik 2026.8.3's policy-binding serializer requires
`target` and `policy` in an `enabled` PATCH; the native test supplies those fields.

The invitation action uses this validation before saving selected assignment
intent; the deferred worker also uses it before applying grants.
An event field or host declaration alone is not sufficient. Unprotected flows
remain unsupported for automatic assignments.

The SQL intent store now saves immutable operator/group intent, binds a single
enrollment identity and serializes per-group attempts across workers. A started
attempt is never automatically reset after a crash or lost response. Expiry
prevents new work; a matching existing attempt can still record its result after
expiry. Daily retention removes only COMPLETE/CANCELLED intent more than thirty
days after expiry in the current scope. Unresolved intent remains for review.
The invitation action starts its normal audit before saving intent, creates the
provider invitation with the generated reference and matching expiry, attaches
the provider ID durably, and only then sends email. Storage failure stops further
provider actions. Failure to attach after creation reports that an invitation
exists but email was not sent, for operator review before retrying. SQL access
temporarily uses the internal session and restores the original operator before
every provider write. Submitted operator identity fields are ignored.

The existing paged group/QQQ-role picker is registered when MIRROR, WEBHOOK and
MEMBERSHIP are enabled. Planning and execution require current user/membership
management authority, the existing subset/protected-group rules, an active scoped
operator with a canonical immutable UUID, at most 100 selected groups/roles and
a reason of at most 2048 characters. Configured flow UUIDs resolve server-side to
the actual slug and must match exactly.

Cancellation stops pending intent even if the provider invitation was already
consumed or expired. An in-flight attempt cannot be promised cancelled and is
refused for review; completed membership changes are not undone. The connected
event worker persists authoritative facts under inbox ownership, then reserves
each automatic grant before calling the normal audited admin path. Focused
creation/cancellation tests use actual H2 SQL and fixture provider HTTP.

Verified by `target/release-invitation-create-integration.log`: 438 unit tests,
44 integration tests (42 PostgreSQL and two native Authentik enrollment cases)
and coverage pass with no failures or skips. The public admin action tests cover
intent-before-creation, attachment-before-email, cancellation after consumption
and expiry, changed flow after preview, audit/storage/attachment failures,
session restoration and revoked live membership authority. Native contracts also
verify configured UUID-to-slug resolution. The later native gate below extends
this evidence to actual email delivery and deferred membership.

Native workflow verified by `target/release-invitation-native-grants-03.log`:
460 unit tests, two Authentik enrollment contracts and coverage pass without
failures or skips. The saved-reference case invokes the public invitation
action with the non-superuser service bearer, verifies Mailpit delivery, submits
a username plus forged correlation through the native flow, then delivers the
real enrollment event before consumption to the production host inbox processor.
It asserts the actual provider membership and a SUCCEEDED administrative audit
stored in SQL. The second case still proves that a fabricated reference is
removed when none was saved. Temporary provider permissions are restored.
This is HTTP flow-executor acceptance, not rendered browser/UI acceptance or a
test of provider notification delivery to the webhook endpoint.

1. Complete rendered UI acceptance and native invitation/email acceptance for the
   new group/QQQ-role selection and persisted intent path.
2. Verify native event details through the Authentik API using the event UUID.
   Associate consumption and successful new-user creation with the stored
   invitation and configured enrollment flow. Handle either delivery order,
   duplicate hints, missing events, expired/cancelled invitations and account
   identity changes. Never take grant values or user identity from a webhook
   payload alone. Correlation replay/copying between enrollments needs explicit
   adversarial coverage before this can authorize writes.
3. Route each assignment through `AuthentikAdmin`, retaining audit-before-write,
   current operator authority, protected-account checks, subset rules and any
   required approval. Persist progress so retries do not re-add a membership
   after a later intentional removal. Ambiguous remote write outcomes must be
   visible for review rather than silently replayed.
4. Verify the full operator invitation → native signup → durable event handling
   → audited membership flow on the SQL host and real Authentik. Include lost,
   reordered and duplicate delivery, partial completion, cancellation, revoked
   operator permissions, changed groups and spoofed correlation/event data.

The native enrollment contract establishes provider behavior only. It does not
prove the authorization, persistence, UI or assignment requirements above.

## Invitation event pairing verified
Consumption and enrollment can now be persisted independently in either delivery order. First verified facts are immutable; the combined bind API uses the same transitions and cannot bypass a saved identity. Rejected pairs roll back both mutations, invalid chronology becomes REVIEW, and duplicate completed events cannot reset APPLIED progress. H2/PostgreSQL regressions cover both orders, restart, conflicting identity, rollback and replay. Missing configured invitation flow now refuses creation, including execute-time drift.
Gate target/release-invitation-pairing-postgres.log passed 441 units +37 AuthentikMirrorPostgresIT tests, zero failures/errors/skips and coverage; session78862 terminal0. Initial restricted run had nine localhost fixture errors (no assertion failures); rerun used approved localhost/Docker access. No source changes during final gate. No review restart, commit or release.
NEXT: add connection-aware event fact persistence inside inbox.withClaim (same SQL transaction, no nested independent commit); connect authoritative event lookup/verification to saved intent; implement audited membership execution under original immutable operator identity and CURRENT authority. Keep system-session write prohibition. Add simultaneous event delivery/lease-loss/cancellation/expiry coverage and native full signup-to-membership acceptance. Overall 1.0 goal remains active.

## Invitation inbox evidence worker connected
AuthentikInvitationEvents now handles invitation_used/user_write from the production AuthentikApplyChangeEvents.forHost path. It re-fetches authoritative event details, checks event ID/action, looks up only saved intent, uses the existing flow/time/reference verifier, and binds enrollment only to a live active scoped immutable user UUID. Envelope username/timestamp are not assignment authority. Consumption skips mirror refresh because it precedes account creation; enrollment retains existing mirror processing.
Store connection-aware transitions join inbox.withClaim's SQL transaction; no independent nested commit, no network work under lock. Tests prove rollback invisibility, reclaimed lease rejection, lease loss during HTTP reads, mismatched event identity/action/flow rejection, concurrent independent claims preserving both facts, and public batch pairing in either order without provider writes.
Final target/release-invitation-worker-postgres.log passes445units +41AuthentikMirrorPostgresIT tests, zero failures/errors/skips and coverage; session70988 terminal0. Focused02 passes2 tests; first focused run exposed a fixture returning a user for a different username, fixed to return an empty server-filtered result. Production scope validation retained. No Java edits during finalgate, no review restart/commit/release.
NEXT: implement AuthentikAdmin-controlled deferred grant execution from saved READY intent. Each group needs original operator pk+UUID and CURRENT live permission validation, active scoped target UUID check, flow protection, normal guard/protected/self/subset/audit-before-write, durable begin/finish and no replay after ambiguous outcomes. Do not weaken system-session write prohibition or expose generic impersonation. operator() currently resolves ordinary sessions by email; deferred path must be pinned to stored immutable identity, not reuse a later email owner. Add current-authority revocation, target/operator replacement, cancellation/expiry/lease loss and provider-write failure tests; then full native signup/email/membership and rendered UI acceptance. Automatic memberships are still not executed by this worker. Full1.0 remains active.

## Deferred invitation membership execution connected
AuthentikAdmin.applyInvitationAssignments accepts only the internal worker plus saved reference/claim. READY intent reserves each group attempt in the inbox ownership transaction. A private delegated admin pins original operator pk+UUID, reads active scoped identities uncached, derives current group/static/host permissions, requires both USERS_MANAGE and MEMBERSHIPS_MANAGE, verifies protected enrollment flow, and creates a short-lived human QSession only for normal ADD_MEMBER execution. No caller-supplied identity/action/grants enter this path. Original worker context is always restored; guard's system-session write prohibition remains unchanged. Revalidation immediately before provider write retains protected/self/subset checks and original current authority. No-change counts as settled. Errors mark REVIEW; failed outcome storage leaves IN_FLIGHT. Tickets cannot be replayed after completion/ambiguity/manual removal. Read-only or disabled infrastructure suspends new attempts without writing provider.
AuthentikInvitationEvents now calls that writer after successful fenced evidence commit. FakeAuthentik now respects server-side UUID filters (needed for production syncUser reads).
New SQL/admin tests cover audit RUNNING and IN_FLIGHT before HTTP, human attribution/context restoration, original/target UUID replacement or inactivity, revoked rights before and after preparing delegation, disabled flow, protected target/superuser/escalated group, internal-caller requirement, missing audit, read-only/cancel/lost ownership, ambiguous remote side effect and no replay after manual removal. A public invitation -> SQL inbox -> authoritative event/flow verification -> admin grant test passes with only provider HTTP simulated. Existing native enrollment tests remain separate.
Final target/release-invitation-grants-postgres.log:460units +41AuthentikMirrorPostgresIT tests, zero failures/errors/skips and coverage; session85250 terminal0. Focused56 tests passed earlier. No Java changes during finalgate. No review restart/commit/release.
NEXT: full native SQL-host invitation/email/signup/inbox/audited membership acceptance and rendered UI. Reuse or extend InvitationEnrollmentContractIT protected flow; public INVITE_USER fixed_data has email/name/reference but no username, so native flow must prompt for username. SessionSqlHost provides H2 sync tables and QQQ RECORD audit; admin action tables need configured backend as in QbitWriteContractIT. Grant only needed temporary provider permissions through stack.grantTemporaryPermissions and restore them. Add partial multi-group failure, expiry/cancellation races and native changed/revoked original authority cases. Current live review still predates changes. Broader mirror views, browser/deployed-node auth, scale, staging/rollback and release supply-chain gates remain open. Full1.0 goal active.
- Pause recovery: READY assignments in read-only mode or with MEMBERSHIP disabled retain their inbox trigger through deferral; re-enabling resumes with current authorization. Verified by both pause-mode SQL tests and release-invitation-pause-postgres.log (462 units +41 PG/coverage). MIRROR/WEBHOOK must remain enabled for the worker to be registered.
