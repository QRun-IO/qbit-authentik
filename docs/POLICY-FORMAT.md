# QQQ policy format

Version 1.0.0 of the policy documents that `qbit-authentik` reads and writes. The design is in [DESIGN.md §12](DESIGN.md#12-policies-iam-style-permission-statements-revision-5).

A **policy** grants QQQ permissions to the members of an Authentik group. It is stored on the group as an attribute. At sign-in, the policies of all the user's groups, including inherited parent groups, become QQQ session permissions.

## Document

```json
{
  "PolicySpec": "qqq-iam",
  "PolicyVersion": "1.0.0",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["hasAccess"],
      "Resource": ["contentApp", "publishPage"]
    },
    {
      "Effect": "Allow",
      "Action": ["read", "insert", "edit"],
      "Resource": ["cms_page", "cms_media"]
    }
  ]
}
```

| Field | Type | Rule |
|---|---|---|
| `PolicySpec` | string | Must equal the app's configured spec name (`policySpec`, default `qqq-iam`) |
| `PolicyVersion` | string, semver | Must equal the supported version (`policyVersion`, default `1.0.0`) |
| `Statement` | array of statements | May be empty (grants nothing) |
| `Statement[].Effect` | string | `Allow` (the only effect in 1.0.0) |
| `Statement[].Action` | array of strings | Each one of `hasAccess`, `read`, `insert`, `edit`, `delete`, `*`, or a table feature name registered for every listed resource |
| `Statement[].Resource` | array of strings | Either `*` with exactly `Action: ["*"]`, or a QQQ permission base name matching `[A-Za-z0-9_]+`: a table, process, app, report or widget name (or its custom `permissionBaseName`) |

## Meaning

Each statement grants `{resource}.{action}` for every resource and action it lists. `Action: ["*"]` on a named resource stands for the five standard actions only; it never includes table features. The full-access statement below is the explicit exception. The result is the union over all statements, and over all of the user's groups.

| Action | QQQ permission | Applies to |
|---|---|---|
| `hasAccess` | `{name}.hasAccess` | apps, processes, reports, widgets, and tables with `HAS_ACCESS` permissions |
| `read` | `{name}.read` | tables (query, get) |
| `insert` | `{name}.insert` | tables |
| `edit` | `{name}.edit` | tables |
| `delete` | `{name}.delete` | tables |
| registered feature (e.g. `analyze`, `comment`) | `{name}.{feature}` | tables that register that feature, including `HAS_ACCESS` and `READ_WRITE` tables |

Examples:
- `{"Action": ["read"], "Resource": ["cms_page"]}` grants `cms_page.read`.
- `{"Action": ["*"], "Resource": ["cms_page"]}` grants `cms_page.hasAccess`, `cms_page.read`, `cms_page.insert`, `cms_page.edit` and `cms_page.delete`.
- `{"Action": ["analyze", "comment"], "Resource": ["person"]}` grants `person.analyze` and `person.comment` when both features are registered for `person`.

Features are generic strings, discovered by matching `PermissionsHelper.getAllAvailablePermissions(qInstance)` entries to the table's effective permission base name. Examples include `analyze` from qbit-data-analysis and `comment`, `attach`, `tag`, `share`, `task`, `assign` from qbit-collaboration. The feature label comes from `AvailablePermission.permissionType`. For named resources every feature grant is explicit, so registering a new feature never broadens an existing `Action: ["*"]` statement on a named resource. This matching rule also exposes the available `write` permission of `READ_WRITE` tables as an explicit named action; it is not part of `*`.

A grant that QQQ never checks (for example `hasAccess` on a table with insert/edit/delete permissions) is harmless.

**Not in 1.0.0:** `Deny`, prefix resources, wildcard resources other than the full-access form below, conditions, and field-level rules. Named permissions such as `authentik.users.manage` cannot be written as a resource, because they contain dots. Explicit named grants stay in the group attribute `qqq.io/permissions`; full access includes them in session form.

## Full access

The exact full-access statement is:

```json
{"Effect":"Allow","Action":["*"],"Resource":["*"]}
```

It grants **Full access (all current and future resources)**. A complete document is:

```json
{
  "PolicySpec": "qqq-iam",
  "PolicyVersion": "1.0.0",
  "Statement": [
    {"Effect":"Allow","Action":["*"],"Resource":["*"]}
  ]
}
```

Full access expands when permissions are computed (sign-in, effective-permission resolution, access comparison and member preview), using the current QQQ instance. The document and cached group graph retain a symbolic marker; no expanded permission list is stored in the document or cached for full access. Adding a table, process, app, report, widget or table feature therefore requires no policy edit. Existing signed-in sessions receive the new set when their permissions are computed again.

The expansion is the union of:

- **Every `AvailablePermission.name` returned by `PermissionsHelper.getAllAvailablePermissions(qInstance)`**, without limiting names to the editor's resource syntax. Core uses effective permission base names and permission levels: table `hasAccess`, `read`, `insert`, `edit`, `delete`, READ_WRITE `write`, registered table feature names, and process/app/report/protected-widget `hasAccess`. Names supplied by custom permission checkers are included when those checkers expose them through this API; arbitrary permissions that core does not enumerate are not inferred.
- **The qbit permission catalog**, including policy-catalog permissions for hidden tables and processes (core skips hidden tables/processes), plus any additional catalog names supplied to the resolver.
- **Every `IdentityPermission` session name**, such as `authentik.users.manage.hasAccess`, `authentik.permissions.manage.hasAccess` and `authentik.policies.manage.hasAccess`. This covers the entire qbit identity catalog, even when a particular feature is not enabled.

This grants QQQ permissions, not Authentik superuser status. Existing scope, protected-account, audit, approval, last-admin and cut-over checks still apply.

Examples and boundaries:

- `{"Effect":"Allow","Action":["*"],"Resource":["*"]}` includes table features, READ_WRITE `write`, named identity permissions and future resources.
- `{"Effect":"Allow","Action":["*"],"Resource":["cms_page"]}` still grants only the five standard actions for `cms_page`; it does not grant features or `write`.
- `{"Effect":"Allow","Action":["read"],"Resource":["*"]}` is invalid. So is `Action: ["*", "read"]` with `Resource: ["*"]`. The error says that `Resource "*" requires Action ["*"]`.
- A full-access statement may coexist with other valid statements (or named resources in the same statement). Canonicalization drops the redundant grants. Every statement and resource is validated first: an invalid statement anywhere still rejects the entire document, even beside full access.

Saving a full-access document requires the operator to hold **every permission in its current expansion**, even when the target already has full access. An operator whose own effective policy is full access meets that check. Review and audit summaries use **Full access (all current and future resources)**. Removing full access cannot remove the last qualifying identity administrator.

## Parsing fails closed

A document grants **nothing**, and the parser logs a warning, when any of these is true:
- it is missing, blank, not JSON, or not a JSON object
- `PolicySpec` is missing or is not the configured name
- `PolicyVersion` is missing or is not the supported version
- `Statement` is present but not an array, or a statement is not an object
- a statement's `Effect` is not `Allow` (including `Deny`, which is not supported yet)
- `Action` or `Resource` is missing or not an array of strings
- an action is neither a standard action, `*`, nor a feature registered for every listed resource
- a resource does not match `[A-Za-z0-9_]+`, except `*` with exactly `Action: ["*"]`

There is no partial credit: one bad statement voids the whole document. When the qbit reads policies from the group graph, each group's document is parsed on its own, so one bad group voids only that group. In the merged token claim, one bad statement voids the claim.

## Canonical form

A document containing full access canonicalizes to exactly one full-access statement. A generated permission set produces full access only when it explicitly contains the internal full-access marker; enumerating all current permissions never creates future grants.

For other documents the qbit writes the existing canonical form:
- one statement per action that is granted, in the order `hasAccess`, `read`, `insert`, `edit`, `delete`, then feature names sorted alphabetically (existing documents retain their byte-for-byte canonical form)
- each statement lists its resources sorted
- no `*`
- stored on the group as a compact JSON **string**

Before every save, the qbit checks the round trip: parsing the generated document must give back exactly the permissions it was generated from. A document that fails this check is never written.

## Where it lives

| What | Default | Config |
|---|---|---|
| Group attribute holding a group's document | `qqq.io/policy` | `policyAttribute` |
| Token claim holding the merged document | `qqq_policy` | `policyClaim` |
| Spec name | `qqq-iam` | `policySpec` |
| Version | `1.0.0` | `policyVersion` |

An app that already stores documents of this shape under its own spec name, attribute and claim sets those four values and keeps its data unchanged. The parser accepts the attribute or claim as a JSON string or as a JSON object.

## Getting policies into the token

Authentik puts the merged document into the token through a scope mapping. Steps:

1. Apply the example blueprint, [`src/test/resources/blueprints/qqq-policy-claim.yaml`](../src/test/resources/blueprints/qqq-policy-claim.yaml). Edit its spec, version, attribute and claim name to match your config.
2. Add the mapping to the OAuth2 provider's `property_mappings`. It uses the scope `profile`, which every QQQ sign-in requests.
3. Keep `include_claims_in_id_token: true` on the provider (the default).
4. Register the customizer in your app:
   - `AuthentikPolicyClaimMapper` on its own, or
   - `AuthentikGroupPermissionMapper`, which also reads the claim and the group graph, or
   - your own customizer, calling `PolicyPermissions.fromClaims(claims, config.getPolicyFormat(), PolicyCatalog.of(qInstance))`.

The catalog-aware overloads of `PolicyParser`, `PolicyGenerator`, `PolicyPermissions`, `PolicyStore.fingerprint` and `GroupGraph.fromGroups` support features. The older overloads without a catalog accept standard actions and full access; `PolicyPermissions.fromClaims` uses the current `QContext` instance for full-access expansion when no catalog is supplied. Raw `PolicyParser` results are symbolic and must be resolved before entering a session. Both bundled mappers and the editor pass the catalog, as do group-policy resolution and access comparison. This qbit consumes the available-permission API from the pinned RC.6 core; registered `TableFeaturePermissionsMetaData` features appear in that API.

The mapping merges the statements of every group in `request.user.all_groups()` (direct groups and their ancestors) whose document has the right spec and version. It always emits a document, with an empty `Statement` array when the user has no policies.

The contract test `PolicyClaimMappingIT` runs this blueprint on Authentik 2026.8.3. It puts generated policies on a parent and a child group (one as a string, one as a JSON object), then runs the mapping through Authentik's property-mapping test endpoint for a member of the child group. It checks that the parser turns the claim into the union of the groups' permissions, that a document with another spec is skipped, and that a user without policies gets a valid empty document.

### Freshness

The claim is computed when the token is issued, so a policy change reaches a signed-in user at their next token refresh. In kof22 that is within 1 hour. To apply a change at once, revoke the user's sessions (*Revoke Sessions*).

## Record locks (not yet)

Row-level security keys are not part of the format. `AuthentikPolicyClaimMapper.applySecurityKeys(QSession, JSONObject)` is the extension point. A host overrides it to set security key values from its own explicit claims, and must never infer them from group names.
