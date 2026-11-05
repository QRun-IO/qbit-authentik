# Host synchronization integration

`MIRROR` and `WEBHOOK` are opt-in features. The QBit producer now registers their
metadata, jobs and routes. The updated local review host enables both with SQL
storage; see [local review](LOCAL-REVIEW.md) for its acceptance limitations.
Production rollout still requires the staging, scale, browser-session and
rollback checks in [the release checklist](RELEASE-1.0.md).

Before producing the QBit, the host must register its local RDBMS backend and a
cron-capable scheduler. Set `localBackendName` and, when more than one scheduler
exists, `schedulerName`. Enable `READ` and `MIRROR`; add `WEBHOOK` and resolve
`webhookSecret` from the host secret environment to accept events. Missing
dependencies or conflicting mirror table/process names fail production of the
metadata. These features do not require enabling upstream administrative writes.

The host owns migrations: apply [schema-sync.sql](schema-sync.sql), adapting table
names for the configured prefix, and the existing [local schema](schema.sql).
Register standard QQQ audit tables and possible-value sources. Enrich local
tables with the host backend's physical table details before validating the
instance. Mirror field metadata already supplies explicit column names. The
producer makes no database or Authentik calls and does not create SQL tables.
H2 and PostgreSQL have executable integration coverage; other database vendors
have not been verified for synchronization.

The producer adds all seven synchronization tables: users, groups, memberships,
inbox, checkpoint/lease state, durable session bindings and invitation assignment
intent. Generic writes remain
disabled. It registers incremental reconciliation every five minutes, full
reconciliation at 02:00 UTC, daily retention and, with `WEBHOOK`, inbox polling
every two seconds. The host starts its normal QQQ scheduler. Jobs require the
internal system session and use database ownership to serialize publishers.

`WEBHOOK` also adds a native QJavalin route-provider reference. The host's normal
QJavalin server loads it. Configure Authentik to POST with the
`X-QQQ-Webhook-Secret` header to:

| Table/component prefix | Webhook path |
|---|---|
| `authentik` (default) | `/qqq/hooks/authentik/webhook` |
| `workforce` | `/qqq/hooks/workforce/webhook` |
| Empty | `/qqq/hooks/webhook` |

These are machine-to-machine routes, outside the versioned UI API as required
by QQQ's UI API extension contract. Earlier development configuration used
`/qqq/v1/.../webhook`; update notification transports to the paths above. No
legacy alias is registered: it would fail QQQ's strict UI route audit.

Each provider is bound to its QBit API backend; credentials and feature state are
resolved for every request. Multiple QBits also need distinct producer namespaces
and component prefixes. Existing host route definitions are preserved. Do not
register another handler on a QBit webhook path. Requests authenticate before
body parsing and acknowledge only committed inbox receipts. Polling recovers
failed delivery notifications.

Without `esbDestinationName`, committed events are processed inline. With it,
register the destination and provider in the host's ESB metadata before producing
the QBit, include the optional ESB dependency, and start the normal host ESB
runtime. Notifications contain no event payload; SQL inbox processing remains
authoritative and polling stays enabled.

Registration does not change the host's authentication module. Configure the
[refreshing OAuth adapter and immutable identity mapping](SESSION-IDENTITY.md)
separately after a successful baseline. Its fifteen-minute freshness ceiling is
unchanged: prolonged synchronization failure denies access rather than restoring
old token grants. The refreshing mapper's bounded directory-outage fallback is
verified on H2 and PostgreSQL. Widget outage behavior, invitation-used assignments,
operational views and production-scale acceptance remain release work.
