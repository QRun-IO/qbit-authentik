/*
 * Copyright 2026 Kingsrook, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kingsrook.qbits.authentik.sync;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.client.AuthentikJson;
import com.kingsrook.qbits.authentik.client.AuthentikRedactor;
import com.kingsrook.qbits.authentik.permissions.ApplicationRole;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.policy.PolicyCatalog;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import org.json.JSONArray;
import org.json.JSONObject;

/*******************************************************************************
 ** Allowlisted directory projection for one complete refresh. Authentik remains
 ** authoritative. No raw user attributes, event context, IPs, or user agents
 ** enter the mirror. Build succeeds fully before any local writes are attempted.
 *******************************************************************************/
public record AuthentikMirrorSnapshot(List<QRecord> users, List<QRecord> groups, List<QRecord> memberships, Instant refreshedAt)
{
   /*******************************************************************************
    ** Optional separately fetched metrics. Null means unavailable, never zero.
    *******************************************************************************/
   public record Metrics(Integer mfaDeviceCount, Integer failedLogins24h)
   {
   }

   /*******************************************************************************
    ** Resolve permissions from the complete group graph. User scope and both
    ** sides of memberships are checked; disagreement aborts for a fresh retry.
    ** Email is normalized for case-insensitive identity lookup and uniqueness.
    *******************************************************************************/
   public static AuthentikMirrorSnapshot build(AuthentikQBitConfig config, QInstance instance,
      List<JSONObject> rawUsers, List<JSONObject> rawGroups, Map<Integer, Metrics> metrics, Instant refreshedAt)
   {
      AuthentikGuard guard = new AuthentikGuard(config);
      PolicyCatalog catalog = PolicyCatalog.of(instance);
      GroupGraph graph = GroupGraph.fromGroups(rawGroups, config.getPolicyFormat(), catalog);
      Set<String> permissionNames = new TreeSet<>(catalog.permissionNames());
      permissionNames.addAll(com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper.getAllAvailablePermissionNames(instance));
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph, permissionNames, instance);
      List<QRecord> users = new ArrayList<>();
      List<QRecord> groups = new ArrayList<>();
      List<QRecord> memberships = new ArrayList<>();
      Set<Integer> userKeys = new HashSet<>();
      Set<String> usernames = new HashSet<>();
      Set<String> emails = new HashSet<>();
      Set<String> groupKeys = new HashSet<>();
      for(JSONObject group : rawGroups)
      {
         String pk = group.getString("pk");
         if(!groupKeys.add(pk) || group.optJSONArray("users") == null)
         {
            throw (new IllegalArgumentException("Group snapshot has duplicate keys or missing membership data"));
         }
         GroupGraph.Node node = graph.byPk(pk);
         if(node.parentPks().stream().anyMatch(parent -> graph.byPk(parent) == null))
         {
            throw (new IllegalArgumentException("Group snapshot contains an unresolved parent"));
         }
         JSONObject attributes = new JSONObject();
         JSONObject raw = group.optJSONObject("attributes");
         // Persist only attributes understood by this QBit, including the
         // configured policy document. Unknown host attributes are not mirrored.
         for(String key : Set.of(AuthentikJson.ATTR_PERMISSIONS, AuthentikJson.ATTR_APP_ACCESS, AuthentikJson.ATTR_PROTECTED,
            ApplicationRole.ATTRIBUTE, GroupGraph.USER_ACCESS_ATTRIBUTE, config.getPolicyFormat().attribute()))
         {
            if(raw != null && raw.has(key))
            {
               attributes.put(key, raw.get(key));
            }
         }
         groups.add(new QRecord().withValue("pk", pk).withValue("name", node.name())
            .withValue("parentPks", json(new TreeSet<>(node.parentPks())))
            .withValue("attributes", AuthentikRedactor.redactText(attributes.toString(), null))
            .withValue("memberCount", node.memberPks().size()).withValue("isSuperuser", graph.isSuperuserInherited(pk))
            .withValue("refreshedAt", refreshedAt));
      }
      for(JSONObject user : rawUsers)
      {
         int pk = user.getInt("pk");
         String username = user.getString("username");
         String email = user.optString("email", "").trim().toLowerCase(Locale.ROOT);
         if(!guard.isUserInScope(user) || !userKeys.add(pk) || username.isBlank() || !usernames.add(username)
            || (!email.isEmpty() && !emails.add(email)))
         {
            throw (new IllegalArgumentException("User snapshot contains an out-of-scope or ambiguous identity"));
         }
         JSONArray direct = user.optJSONArray("groups");
         if(direct == null)
         {
            throw (new IllegalArgumentException("User snapshot is missing membership data"));
         }
         Set<String> directPks = new TreeSet<>();
         for(int i = 0; i < direct.length(); i++)
         {
            directPks.add(direct.getString(i));
         }
         if(!directPks.equals(new TreeSet<>(graph.groupsOfUser(pk))))
         {
            throw (new IllegalArgumentException("Directory membership changed during refresh; retry the snapshot"));
         }
         Set<String> groupNames = new TreeSet<>();
         for(String groupPk : directPks)
         {
            String name = graph.byPk(groupPk).name();
            groupNames.add(name);
            memberships.add(new QRecord().withValue("userPk", pk).withValue("groupPk", groupPk).withValue("groupName", name)
               .withValue("refreshedAt", refreshedAt));
         }
         boolean active = user.optBoolean("is_active", false);
         Metrics userMetrics = metrics == null ? null : metrics.get(pk);
         users.add(new QRecord().withValue("pk", pk).withValue("uuid", user.optString("uuid", null))
            .withValue("username", username).withValue("email", email.isEmpty() ? null : email)
            .withValue("name", user.optString("name", "")).withValue("type", user.getString("type"))
            .withValue("path", user.optString("path", ""))
            .withValue("sourceIsSuperuser", user.optBoolean("is_superuser", false))
            .withValue("sourceIsProtected", AuthentikGuard.isMarkedProtected(user))
            .withValue("isActive", active).withValue("lastLogin", AuthentikJson.instant("last_login").apply(user))
            .withValue("isSuperuser", user.optBoolean("is_superuser", false) || directPks.stream().anyMatch(graph::isSuperuserInherited))
            .withValue("isProtected", guard.protection(user).isProtected() || directPks.stream().anyMatch(graph::isSuperuserInherited))
            .withValue("groupNames", json(groupNames))
            .withValue("effectivePermissions", json(active ? resolver.resolveUser(pk).sessionPermissions() : Set.of()))
            .withValue("mfaDeviceCount", userMetrics == null ? null : userMetrics.mfaDeviceCount())
            .withValue("failedLogins24h", userMetrics == null ? null : userMetrics.failedLogins24h())
            .withValue("refreshedAt", refreshedAt));
      }
      return (new AuthentikMirrorSnapshot(List.copyOf(users), List.copyOf(groups), List.copyOf(memberships), refreshedAt));
   }

   /*******************************************************************************
    ** Stable JSON arrays avoid audit churn caused only by set iteration order.
    *******************************************************************************/
   private static String json(Set<String> values)
   {
      return (AuthentikRedactor.redactText(new JSONArray(new TreeSet<>(values)).toString(), null));
   }

   /*******************************************************************************
    ** Merge changed API users with the last complete local directory. Rebuild
    ** retained users' membership from the newly fetched group graph, so role,
    ** parent and membership edits recompute grants even without a user timestamp
    ** change. Scope exits from local rows require the worker's live preflight.
    ** Never use derived protection/superuser values as source attributes: doing
    ** so would make a removed inherited privilege permanent in the mirror.
    ** The worker separately refreshes profiles whose API is_superuser was true,
    ** because Authentik can include inherited status in that source value too.
    *******************************************************************************/
   public static List<JSONObject> incrementalUsers(AuthentikQBitConfig config, List<QRecord> existing,
      List<JSONObject> changed, List<JSONObject> groups)
   {
      GroupGraph graph = GroupGraph.fromGroups(groups, config.getPolicyFormat());
      Map<Integer, JSONObject> merged = new java.util.LinkedHashMap<>();
      AuthentikGuard guard = new AuthentikGuard(config);
      for(QRecord row : existing)
      {
         int pk = row.getValueInteger("pk");
         if(row.getValue("path") == null || row.getValue("sourceIsSuperuser") == null || row.getValue("sourceIsProtected") == null)
         {
            throw (new IllegalArgumentException("Mirror requires a full refresh before incremental reconciliation."));
         }
         List<String> memberships = graph.groupsOfUser(pk);
         JSONArray groupObjects = new JSONArray();
         memberships.forEach(group -> groupObjects.put(new JSONObject().put("pk", group).put("name", graph.byPk(group).name())));
         JSONObject user = new JSONObject().put("pk", pk).put("uuid", row.getValueString("uuid"))
            .put("username", row.getValueString("username")).put("email", row.getValueString("email"))
            .put("name", row.getValueString("name")).put("type", row.getValueString("type"))
            .put("path", row.getValueString("path")).put("is_active", row.getValue("isActive"))
            .put("is_superuser", row.getValue("sourceIsSuperuser"))
            .put("attributes", new JSONObject().put(AuthentikJson.ATTR_PROTECTED, row.getValue("sourceIsProtected")))
            .put("groups", new JSONArray(memberships)).put("groups_obj", groupObjects);
         if(row.getValue("lastLogin") != null)
         {
            user.put("last_login", row.getValue("lastLogin").toString());
         }
         if(guard.isUserInScope(user))
         {
            if(merged.put(pk, user) != null)
            {
               throw (new IllegalArgumentException("Mirror contains duplicate source identities."));
            }
         }
      }
      Set<Integer> changedKeys = new HashSet<>();
      for(JSONObject user : changed)
      {
         int pk = user.getInt("pk");
         if(!changedKeys.add(pk) || !guard.isUserInScope(user))
         {
            throw (new IllegalArgumentException("Incremental API users contain duplicate or out-of-scope identities."));
         }
         merged.put(pk, user);
      }
      return (List.copyOf(merged.values()));
   }
}
