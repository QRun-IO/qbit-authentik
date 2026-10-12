#!/usr/bin/env bash
# Rehearse the phase 0 blueprint migration (DESIGN.md section 4.4, owner
# checklist item 6) on a DISPOSABLE local Authentik restored from a dump of the
# production Authentik database. Nothing here talks to production: you supply
# the dump file; everything runs in local Docker and is removed at the end.
#
# Usage:
#   rehearse-phase0.sh <authentik-db.dump> <configmap-before.yaml> <configmap-after.yaml>
#
#   authentik-db.dump      pg_dump -Fc of the production Authentik database
#   configmap-before.yaml  tenants/kof22/website-authentik/blueprint-configmap.yaml at main
#   configmap-after.yaml   the same file on branch feat/kof22-identity-bootstrap
#
# Needs: docker, jq, python3 with PyYAML. Takes ~5 minutes.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash on Windows: keep container paths as-is

DUMP=${1:?dump file}; BEFORE=${2:?configmap before}; AFTER=${3:?configmap after}
IMAGE=${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server:2026.8.3}
NET=ak-rehearsal; PORT=${PORT:-19900}
WORK=$(mktemp -d); BP="$WORK/blueprints"; mkdir -p "$BP"
BP_MOUNT="$BP"; command -v cygpath >/dev/null 2>&1 && BP_MOUNT=$(cygpath -w "$BP")
ADMIN_TOKEN="rehearsal-$(openssl rand -hex 16)"
API="http://localhost:$PORT/api/v3"

cleanup() { docker rm -f akr-server akr-worker akr-pg >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

extract() {  # write every blueprint key of a ConfigMap into $BP
  rm -f "$BP"/*.yaml
  python3 - "$1" "$BP_MOUNT" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
for key, value in doc["data"].items():
    open(f"{sys.argv[2]}/{key}", "w", encoding="utf-8").write(value)
    print("  blueprint file:", key)
PY
}

api() { curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" "$API$1"; }
snapshot() {  # users -> sorted groups, as TSV
  api "/core/users/?page_size=100&include_groups=true&type=internal&type=external&type=service_account" \
    | jq -r '.results[] | [.username, ([.groups_obj[].name] | sort | join(","))] | @tsv' | tr -d '\r' | sort
}
wait_blueprints() {  # $1 = how many kof22* blueprint instances must exist
  local want=${1:-1}
  for _ in $(seq 1 90); do
    states=$(api "/managed/blueprints/?page_size=100" | jq -r '[.results[] | select(.name|startswith("kof22")) | .status] | join(" ")' || true)
    count=$(wc -w <<<"$states")
    if [ "$count" -ge "$want" ] && ! grep -qv successful <<<"$(tr ' ' '\n' <<<"$states")"; then echo "  kof22 blueprints: $states"; return 0; fi
    sleep 5
  done
  echo "  blueprints did not all reach successful: $states"; api "/managed/blueprints/?page_size=100" | jq -r '.results[] | "\(.name) \(.status)"'; return 1
}

echo "== 1. restore the dump into a disposable Postgres"
docker network create $NET >/dev/null
docker run -d --name akr-pg --network $NET -e POSTGRES_USER=authentik -e POSTGRES_PASSWORD=rehearsal -e POSTGRES_DB=authentik postgres:16-alpine >/dev/null
until docker exec akr-pg pg_isready -U authentik >/dev/null 2>&1; do sleep 1; done
docker cp "$DUMP" akr-pg:/tmp/authentik.dump
docker exec akr-pg pg_restore -U authentik -d authentik --no-owner --no-privileges /tmp/authentik.dump || echo "  (pg_restore reported warnings; usually role/ownership notices)"
docker exec akr-pg psql -U authentik -d authentik -tAc "select count(*) from authentik_core_user" | sed 's/^/  users restored: /' 

echo "== 2. start Authentik with the CURRENT (main) blueprints"
extract "$BEFORE"
ENV=(-e AUTHENTIK_SECRET_KEY="$(openssl rand -hex 32)" -e AUTHENTIK_POSTGRESQL__HOST=akr-pg -e AUTHENTIK_POSTGRESQL__USER=authentik
     -e AUTHENTIK_POSTGRESQL__PASSWORD=rehearsal -e AUTHENTIK_POSTGRESQL__NAME=authentik -e AUTHENTIK_BOOTSTRAP_TOKEN="$ADMIN_TOKEN"
     -e KOF22_OAUTH2_CLIENT_SECRET=rehearsal-not-the-real-secret -e AUTHENTIK_ERROR_REPORTING__ENABLED=false
     -e AUTHENTIK_DISABLE_UPDATE_CHECK=true -e AUTHENTIK_EMAIL__HOST=localhost -e AUTHENTIK_EMAIL__PORT=1)
docker run -d --name akr-worker --network $NET "${ENV[@]}" -v "$BP_MOUNT:/blueprints/custom" "$IMAGE" worker >/dev/null
docker run -d --name akr-server --network $NET -p "$PORT:9000" "${ENV[@]}" -v "$BP_MOUNT:/blueprints/custom" "$IMAGE" server >/dev/null
until curl -sf "http://localhost:$PORT/-/health/ready/" >/dev/null; do sleep 3; done
# The bootstrap token only applies to an EMPTY instance; on a restored database
# create a rehearsal token for akadmin-equivalent access through the shell.
docker exec akr-worker ak shell -c "
from authentik.core.models import Token, TokenIntents, User
u = next(x for x in User.objects.filter(is_active=True).exclude(username__startswith='ak-').order_by('pk') if x.is_superuser)  # is_superuser is derived from groups
Token.objects.update_or_create(identifier='phase0-rehearsal', defaults={'user': u, 'intent': TokenIntents.INTENT_API, 'key': '$ADMIN_TOKEN', 'expiring': False})
print('rehearsal token for', u.username)" 2>&1 | grep -E 'rehearsal token|Error|error' | tail -3 | grep 'rehearsal token'  || { echo "could not create the rehearsal API token in the restored copy"; exit 1; }
wait_blueprints 1
snapshot > "$WORK/before.tsv"; echo "  $(wc -l < "$WORK/before.tsv") users recorded (step 1, freeze)"

echo "== 3. switch to the phase 0 blueprints (as an ArgoCD sync would)"
extract "$AFTER"
docker restart akr-worker >/dev/null   # a restart triggers discovery like a ConfigMap change
wait_blueprints 2
for name in kof22-oauth2-apps kof22-identity-bootstrap; do
  pk=$(api "/managed/blueprints/?name=$name" | jq -r '.results[0].pk')
  curl -sf -X POST -H "Authorization: Bearer $ADMIN_TOKEN" "$API/managed/blueprints/$pk/apply/" >/dev/null
done
sleep 30; wait_blueprints 2

echo "== 4. checks"
snapshot > "$WORK/after.tsv"
fail=0
if ! diff <(awk -F'\t' '$1 != "qqq-kof22-admin-idadmin" && $1 != "kof22-breakglass"' "$WORK/after.tsv") "$WORK/before.tsv" >/dev/null; then
  echo "  FAIL memberships changed:"; diff "$WORK/before.tsv" "$WORK/after.tsv" || true; fail=1
else echo "  ok   existing users' memberships unchanged"; fi
grep -q $'^james.maes\t.*authentik Admins.*kof22-admins' "$WORK/after.tsv" && echo "  ok   james.maes keeps authentik Admins + kof22-admins" || { echo "  FAIL james.maes groups"; fail=1; }
api "/core/users/?username=qqq-kof22-admin-idadmin&include_roles=true" | jq -e '.results[0] | .type=="service_account" and (.groups|length)==0 and ([.roles_obj[].name]==["qqq-kof22-admin-idadmin"])' >/dev/null \
  && echo "  ok   service account: type, no groups, role" || { echo "  FAIL service account"; fail=1; }
api "/core/users/?username=kof22-breakglass" | jq -e '.results[0].is_superuser' >/dev/null && echo "  ok   break-glass superuser" || { echo "  FAIL break-glass"; fail=1; }
for g in identity-admins kof22-admins kof-website-publishers kof-website-drafters; do
  api "/core/groups/?name=$g" | jq -e '.pagination.count==1' >/dev/null && echo "  ok   group $g" || { echo "  FAIL group $g"; fail=1; }
done
echo "== 5. re-apply both again (an hourly run): memberships must not move"
for name in kof22-oauth2-apps kof22-identity-bootstrap; do
  pk=$(api "/managed/blueprints/?name=$name" | jq -r '.results[0].pk')
  curl -sf -X POST -H "Authorization: Bearer $ADMIN_TOKEN" "$API/managed/blueprints/$pk/apply/" >/dev/null
done
sleep 30; wait_blueprints 2
snapshot | diff - "$WORK/after.tsv" >/dev/null && echo "  ok   stable across re-apply" || { echo "  FAIL changed on re-apply"; fail=1; }
[ $fail = 0 ] && echo "REHEARSAL PASSED" || { echo "REHEARSAL FAILED"; exit 1; }
