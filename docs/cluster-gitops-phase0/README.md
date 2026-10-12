# cluster-gitops phase 0 support files

The cluster-gitops changes themselves are in **KofTwentyTwo/cluster-gitops#72** (draft). That PR adds:
- the identity bootstrap blueprint
- the removal of the `present` `james.maes` and `kof22-admins` entries
- the attribute-driven sign-in policy
- the inert webhook plumbing
- the lint

The blueprint YAML in that PR is generated from this repo's tested fixtures, `src/test/resources/blueprints/*.yaml`. That way, what goes to cluster-gitops is what the contract tests applied to Authentik 2026.8.3.

| File | Purpose |
|---|---|
| `scripts/lint-authentik-blueprints.py` | The blueprint lint (also in cluster-gitops#72 under `scripts/`). It forbids `present` user/group entries, member lists, roles beyond `permissions`, tokens and literal secrets. `--self-test` runs the built-in cases. |
| `rehearse-phase0.sh` | Owner checklist item 6: replays the migration on a **local, disposable** Authentik restored from a dump you take, and checks that no membership moves. |

To re-check the fixtures with the lint:

```bash
python3 docs/cluster-gitops-phase0/scripts/lint-authentik-blueprints.py src/test/resources/blueprints
```
