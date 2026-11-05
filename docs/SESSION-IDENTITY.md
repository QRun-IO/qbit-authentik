# Immutable identity for session reevaluation

The request-time authentication adapter remains opt-in and is not yet ready for
production enablement. `AuthentikRefreshingOAuth2Module` connects core OAuth
authentication to durable bindings and the refreshing mapper. H2/PostgreSQL
tests exercise native signature verification, cookie/refresh exchange, logout
and old-token rejection after retention cleanup. A real Authentik-issued-token
contract verifies current-grant revocation through the adapter. Separate module
instances share SQL state; independently deployed nodes and interactive browser
acceptance remain release gates.

Mirror authorization expires fifteen minutes after the last published scan's
start time. Incremental reconciliation is scheduled every five minutes so the
next scan can finish before that expiry. Busy ticks do not extend freshness;
targeted webhook updates also do not make an old directory baseline fresh.
If synchronization stalls beyond the limit, authentication fails closed. Size
the host and API budget so scans finish within this window; realistic load
verification remains required before production enablement.

## Directory API outages

The refreshing adapter reads committed mirror permissions on every request;
it does not retry the directory API in the request path. This provides the
mapper's bounded outage fallback without merging old token groups, policies or
session permissions. H2 and PostgreSQL acceptance tests use native signed OAuth
verification, force reconciliation API reads to fail, and verify that the failed
scan cannot advance the watermark. Fresh mirrored access remains usable; committed
revocations, inactive identities and snapshots older than fifteen minutes do not.

This applies to `AuthentikRefreshingOAuth2Module` with
`AuthentikRefreshingPermissionMapper`, after immutable identity mapping and durable
binding setup. The legacy `AuthentikGroupPermissionMapper` is the compatibility
sign-in customizer and does not provide request-time session reevaluation. Hosts
must migrate to the refreshing pair to obtain these guarantees. OAuth signature,
issuer, audience, lifetime and binding checks still run: directory API fallback
does not bypass an unavailable OAuth login or refresh endpoint. Configured cut-over
guards retain their existing fail-safe host-permission behavior if their live API
comparison cannot run; the outage acceptance test covers an already enforced
mapper without cut-over guard groups. Widget outage behavior and deployed-host
acceptance are separate release gates.

The live `TokenContractIT.existingOAuthTokenReflectsReconciledPermissionRevocation`
now also passes with an Authentik-issued token and real provider discovery/keys.
It removes a real group permission, publishes the directory through the production
worker into H2, and proves that the same token loses access through a second
module instance. Durable logout prevents reuse. Interactive login/token refresh
and independently deployed application nodes remain separate acceptance gates.

The native authorization-code exchange, stored-cookie resume and refresh-token
HTTP exchange now also pass against the loopback OAuth fixture on H2 and
PostgreSQL. The tests use core session/refresh-token metadata and encrypted
refresh-token storage. Refresh replaces the stored access token without extending
the identity binding deadline; current grants apply, missing bindings reject,
and logout removes both core credential rows. This is protocol acceptance,
not a browser login against the actual Authentik authorization flow.

The kof22 provider uses `sub_mode: user_email`. Email and username can change
or be reused, so neither is sufficient to bind an existing QQQ session to an
Authentik user. Keep the existing subject mode for host compatibility and add
the managed **QQQ - immutable user identity** profile scope mapping from
[the tested infrastructure blueprint](../src/test/resources/blueprints/kof22-oauth2-apps.yaml).
Attach it to the application's OAuth provider alongside its existing property
mappings; do not replace the provider's other mappings.

The mapping returns:

```python
if not request.user.is_authenticated:
    return {}
return {"qqq_identity": {"pk": request.user.pk, "uuid": str(request.user.uuid)}}
```

The app must request `profile`. A token without that scope has no identity
claim and cannot be used by the forthcoming reevaluation adapter. This is an
additional signed claim, not a change to the OAuth subject or an authorization
grant. Existing authentication behavior remains unchanged until the adapter is
explicitly configured.

`AuthentikSessionIdentity.fromVerifiedClaims` accepts only a positive integral
pk within the API's integer range and a canonical UUID. It does not verify JWT
signatures, issuer, audience or lifetime. It must receive claims from the
authenticated OAuth path, never from request parameters or a decoded but
unverified token. Missing or malformed claims have no email/username fallback.

The adapter must bind a newly verified login to that pk and UUID using
`AuthentikSessionBindings`. Cookie-session resumption must load the existing
binding; it must never recreate a missing, expired or revoked binding from old
claims. The original login deadline is fixed. An existing core user-reference
change must not reassign the binding to a different identity.

On reevaluation, `AuthentikMirrorAccess` supplies only fresh, committed directory
grants for the bound identity. Its result must replace stale directory/token
grants while preserving separately established host contributions and credential
restrictions. A denied or unavailable read cannot justify restoring old claims.
This replacement and the cross-node request path remain release acceptance gates.

Evidence: `TokenContractIT.clientCredentialsClaimsRequireProfile` mints real
Authentik tokens, compares the claim with the API user record, checks its absence
without `profile`, then changes both username and email and verifies that the
claim is unchanged while `sub` changes. Interactive authorization-code/session
refresh acceptance remains separate. The production provider mapping has not
been deployed; coordinate it with the host adapter before feature enablement.

## Adapter configuration and behavior

The opt-in host module code reference is `AuthentikRefreshingOAuth2Module`,
with `AuthentikRefreshingPermissionMapper` (or a host subclass) as the OAuth
customizer. Configure `sessionStoreEnabled=false` and a positive
`maxSessionLifetimeSeconds` no greater than 2,592,000 (thirty days). The adapter rejects missing prerequisites rather
than changing shared metadata during requests. Core bearer cache hits bypass
the customizer, so leaving that cache enabled would defeat reevaluation.

The host must install the local sync/binding schema and publish a fresh mirror
before enabling this module. Verified authorization-code logins bind immutable
identity and original core user reference; cookie resumption only looks up an
existing binding. Missing, expired, revoked or reassigned bindings reject.

Set `authentikPublicUrl` to the public root of the same Authentik installation
used by `baseUrl` for API reads. It defaults to `baseUrl`; set it explicitly when
the API uses an internal service address. On login and every permission refresh,
the mapper checks the verified `iss` origin (scheme, host and effective port)
and deployment-path boundary against that public root before reading the mirror.
Native OAuth still verifies the signature and exact provider/audience allowlist;
this additional check prevents an independently trusted issuer from borrowing
matching local user IDs. Both global and per-provider issuer paths within the
installation are supported. Userinfo, query strings, fragments, escaped paths
and dot-segment/duplicate-slash ambiguity fail closed. Use canonical HTTP(S) URLs.

Verified bearer and service credentials use the same durable binding. Their
absolute deadline is the earlier of token `exp` and signed `iat` plus the
configured session lifetime. The adapter requires an integral, positive `iat`
that is not in the future; keep the provider and host clocks synchronized.
It enforces this deadline on every bind and resume, even if core's optional
bearer-token lifetime limit is disabled. Cookie login deadlines remain fixed
at the verified callback, and cookie resumption never recreates missing bindings.

Repeated binding cannot extend the original deadline. Retention keeps logout
records for thirty days after binding expiry; the lifetime cap and signed-age
check prevent a still-signed old bearer from creating a new binding after those
records are purged. Logout records durable revocation before core
credential cleanup. Every successful resume and validity check refreshes
permissions, applying credential restrictions after current grants.

Host permissions must be supplied by current static-group configuration or the
host permission source during blocked cut-over. Do not restore an old session's
permission set in a host customizer. Interactive OAuth, token refresh, real
same-token revocation across nodes and provider rollout remain acceptance gates.
