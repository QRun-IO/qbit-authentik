# Phase 0 owner checklist (kof22)

These are the steps only James can take: items 6, 7, 8 and 10 of DESIGN.md section 11.0, plus a few decisions the phase 0 work surfaced. Agents prepared everything else. Nothing below has been run against production.

Links:
- cluster-gitops draft PR: KofTwentyTwo/cluster-gitops#72 (the identity bootstrap blueprint, the removal of the `present` entries, the attribute-driven sign-in policy, inert webhook plumbing, and the blueprint lint)
- Website-Backend and cluster-gitops wiring draft PRs: see `docs/STATUS.md`
- Spec: QRun-IO/qqq#1065 (revision 3 records the phase 0 findings)

## 0. Decisions surfaced by phase 0 (read first)

| # | Decision | Recommendation |
|---|---|---|
| D1 | **Repo visibility.** `QRun-IO/qbit-authentik` was created **private**, because creating a public repo was blocked for the agent. Other generic qbits (quick-search, sql-workbench) are public, and the spec is already public in qqq#1065. CI publishes `develop` snapshots and `release/*` RCs to Maven Central / Sonatype (with sources jars), which would make the code public anyway. | Make it public before the first publish: *Settings → General → Change visibility*. Then check that CircleCI follows the repo (it must, for PR CI). |
| D2 | **Lockout risk.** Authentik stops the service account from *escalating*, but not from *locking out*. With the phase 2/3 permissions it can do all of the following (contract test `SuperuserFloorIT`): remove members from `authentik Admins`, deactivate `kof22-breakglass`, strip `qqq.io/protected`, and rename the superuser group. The qbit guard refuses all of these; Authentik does not. | Accept, with the mitigations in the spec (§5.1, revision 3). The real break-glass for a compromised QQQ is cluster access: `kubectl exec` into the Authentik worker and run `ak shell` to reactivate or re-add. Optionally, phase 2 grants `remove_user_from_group` per group (object permissions) instead of globally. |
| D3 | **Self-minted tokens.** Any authenticated user, including the service account, can create API tokens **for itself** without `add_token`, and read their keys. A compromised QQQ could therefore keep a second token alive after you rotate the first. | Accept. The phase 1 drift report flags service-account tokens beyond the expected one. Check that list after every rotation (item 8). |
| D4 | **Access matrix.** `check_access?for_user=` only works for superusers. For the service account it silently answers *for itself*. The policy-test endpoint returns HTTP 500 for non-superusers on 2026.8.3. | Accepted in the spec: the qbit computes app access itself from `qqq.io/app-access` and the app's bindings, and shows other expression policies as "not evaluated". |

## Item 6: staging rehearsal (needs your go-ahead)

The agent cannot read production data. The rehearsal runs entirely in local Docker, on a dump you take.

1. **Take a dump** of the Authentik database. This is a read-only `pg_dump` of the CNPG cluster that hosts it:
   ```bash
   # CNPG cluster kof22-website-pg (namespace kof22-website-prod) hosts the database "authentik"
   P=$(kubectl --context=k8s-galaxy -n kof22-website-prod get pod -l cnpg.io/cluster=kof22-website-pg,cnpg.io/instanceRole=primary -o name)
   kubectl --context=k8s-galaxy -n kof22-website-prod exec "$P" -c postgres -- \
     pg_dump -Fc -d authentik > authentik-$(date +%F).dump
   ```
   Keep the dump on an encrypted disk. It contains every identity and password hash. Delete it after the rehearsal.
2. **Get both blueprint versions**:
   ```bash
   git -C cluster-gitops show origin/main:tenants/kof22/website-authentik/blueprint-configmap.yaml > before.yaml
   git -C cluster-gitops show origin/feat/kof22-identity-bootstrap:tenants/kof22/website-authentik/blueprint-configmap.yaml > after.yaml
   ```
3. **Run** `docs/cluster-gitops-phase0/rehearse-phase0.sh authentik-<date>.dump before.yaml after.yaml`.
   - The script restores the dump into a throwaway Postgres and starts Authentik 2026.8.3 on the current blueprints. It then records every user's groups, switches to the phase 0 blueprints, re-applies both twice, and checks:
     - nobody's memberships changed
     - `james.maes` keeps `authentik Admins` and `kof22-admins`
     - the service account, break-glass and seed groups exist
   - It prints `REHEARSAL PASSED` or the differences.
   - Containers and the work directory are removed on exit. The script mints a rehearsal-only API token **inside the throwaway copy**, which is deleted with the container.
4. Reply "rehearsal passed" (or paste the output) on cluster-gitops#72.

## Item 7: production apply

Do these in order, in one sitting.

1. **Freeze.** Record the current memberships: *Authentik admin → Directory → Users*, or export each admin group's member list. Note who is in `authentik Admins`, `kof22-admins` and `kof-website-publishers`.
2. **Merge** cluster-gitops#72 (convert it from draft first). ArgoCD syncs the ConfigMap, and the worker sees the file change and applies both blueprints within about a minute.
3. **Verify** in *Authentik admin → Customization → Blueprints*:
   - [ ] `kof22-oauth2-apps` and `kof22-identity-bootstrap` both show **successful**
   - [ ] `james.maes` still has `authentik Admins` and `kof22-admins`
   - [ ] user `qqq-kof22-admin-idadmin` exists: type *Service account*, no groups, role `qqq-kof22-admin-idadmin`
   - [ ] user `kof22-breakglass` exists and is a superuser
   - [ ] groups `identity-admins`, `kof22-admins`, `kof-website-publishers`, `kof-website-drafters` exist; only `identity-admins` has attributes
   - [ ] you can still sign in to `https://admin.kof22.com` (the name fallback in the sign-in policy keeps today's access)
   - [ ] *Events → Notification rules*: `qqq-kof22-admin-sync` has **no destination** (inert)
4. **Prove it** (optional, recommended): add a test user to `kof-website-publishers` in the UI. Then *Blueprints → kof22-oauth2-apps → Apply* and the same for `kof22-identity-bootstrap`. Wait a minute and confirm the member is still there. Remove the test user afterwards.
5. **Rollback** if anything is wrong: revert the PR. This re-adds the old `present` entries, which re-pin James's groups. Logins keep working throughout because of the fallback.

## Item 8: service-account token and secrets

1. **Mint the API token**:
   - In Authentik admin, go to *Directory → Tokens and App passwords → Create*.
   - Identifier: `qqq-kof22-admin-idadmin-api`. User: `qqq-kof22-admin-idadmin`. Intent: **API**. Expiring: **on**, with an expiry **90 days** out.
   - Copy the key once.
2. **Store it** in Infisical at `/kof22-website-authentik-api/token`. Paste it straight from the Authentik dialog into Infisical; it must never go in chat, git or a ticket.
3. **Webhook secret** (used in phase 2; create it now so the phase 2 PR can be merged directly): `openssl rand -base64 48` into Infisical at `/kof22-website-authentik/qqq-webhook-secret`.
4. **Check** that *Directory → Tokens* shows **exactly one** token for `qqq-kof22-admin-idadmin` (see D3).
5. **Calendar** a rotation reminder for day 76. The health widget will also warn 14 days before expiry.

## Item 10: seed data (Authentik UI)

1. Add **yourself** (`james.maes`) to **`identity-admins`**.
2. On group **`kof22-admins`** → *Attributes*, set the following. This is today's `ADMIN_PERMISSIONS` from Website-Backend `AuthentikAuthenticationCustomizer`, resolved to literal strings on 2026-10-11 against `origin/main` f936cbd. Re-check if that list changed before you seed, because the phase 1 mapper will grant exactly this:
   ```yaml
   qqq.io/app-access: ["kof22-website-prod"]
   qqq.io/permissions:
     - esbView.hasAccess
     - esbOperate.hasAccess
     - esbDelete.hasAccess
     - analytics.hasAccess
     - quickSearchAdmin.hasAccess
     - quickSearchIndex.read
     - quickSearchIndex.write
     - quickSearchIndexRun.read
     - quickSearchIndexRun.write
     - quickSearchFailedEvent.read
     - quickSearchFailedEvent.write
     - dataHealth.hasAccess
   ```
   Keep the existing attributes of the group. Add only these two keys.
3. On group **`kof-website-publishers`** → *Attributes*: `qqq.io/app-access: ["kof22-website-prod"]`. This keeps the `kof-publisher-prod` service account's client-credentials tokens working once the name fallback is removed.
4. **`kof-website-drafters`**: leave it without `qqq.io/app-access` until you decide that drafters should sign in to the admin. Granting it later is that one attribute.
5. **Break-glass password**:
   - Set a long random password on `kof22-breakglass` (*Directory → Users → kof22-breakglass → Set password*) and store it in 1Password.
   - Sign in with it once in a private window to prove it works, then sign out.
   - Its recovery path is `ak create_recovery_key 10 kof22-breakglass` on the worker pod.

## After items 6-10

Tell the agent "phase 0 owner steps done". Next come item 11 (the qbit in read-only mode on staging, behind `AUTHENTIK_QBIT_ENABLED`), then the phase 1 mapper cut-over, then removal of the sign-in name fallback.
