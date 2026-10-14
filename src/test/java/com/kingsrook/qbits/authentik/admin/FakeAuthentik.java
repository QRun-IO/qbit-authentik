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

package com.kingsrook.qbits.authentik.admin;


import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qqq.backend.module.api.actions.QHttpResponse;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** A small in-memory Authentik for unit tests: users, groups (with parents,
 ** attributes and members), tokens, sessions, MFA devices, invitations and the
 ** write endpoints the qbit uses, with the same superuser inheritance the real
 ** server has. Every write request is recorded so tests can assert what was
 ** (and was not) sent. Plug it in with {@link #install()}.
 *******************************************************************************/
public class FakeAuthentik
{
   public final JSONObject brandAttributes = new JSONObject();
   public final Map<Integer, JSONObject>        users    = new LinkedHashMap<>();
   public final Map<String, JSONObject>         groups   = new LinkedHashMap<>();
   public final Map<String, List<JSONObject>>   tokens   = new LinkedHashMap<>();
   public final Map<String, Integer>            sessions = new LinkedHashMap<>();
   public final Map<Integer, List<JSONObject>>  devices  = new LinkedHashMap<>();
   public final Map<String, JSONObject>         invitations = new LinkedHashMap<>();
   public final List<String>                    writes   = new ArrayList<>();
   public final List<JSONObject>                events   = new ArrayList<>();
   public final List<JSONObject>                writeBodies = new ArrayList<>();

   public final Map<String, String> tokenKeys = new LinkedHashMap<>();
   public final java.util.Set<Integer> deniedSubjects = new java.util.HashSet<>();
   public final List<Integer> tokenCallers = new ArrayList<>();
   public final List<JSONObject> loginEvents = new ArrayList<>();
   public boolean moveTokenAfterUpdate;
   public boolean failTokenDelete;
   private int nextUserPk = 100;



   /*******************************************************************************
    ** Route the qbit's requests to this fake.
    *******************************************************************************/
   public FakeAuthentik install()
   {
      FixtureActionUtil.reset();
      FixtureActionUtil.handler = this::handle;
      FixtureActionUtil.groupGraphHandler = this::handle;
      return (this);
   }



   /*******************************************************************************
    ** Add a user (groups by name must already exist).
    *******************************************************************************/
   public FakeAuthentik user(int pk, String username, String email, String type, boolean active, String... groupNames)
   {
      JSONObject user = new JSONObject().put("pk", pk).put("username", username).put("name", username + " Name").put("email", email)
         .put("is_active", active).put("type", type).put("path", "users").put("attributes", new JSONObject()).put("last_updated", "2026-10-01T00:00:00Z")
         .put("date_joined", "2026-01-01T00:00:00Z").put("last_login", "2026-10-02T00:00:00Z");
      users.put(pk, user);
      for(String groupName : groupNames)
      {
         groupByName(groupName).getJSONArray("users").put(pk);
      }
      return (this);
   }



   /*******************************************************************************
    ** Add a group with QQQ permissions, app access and parents (names).
    *******************************************************************************/
   public FakeAuthentik group(String name, boolean superuser, List<String> permissions, List<String> appAccess, String... parentNames)
   {
      JSONObject attributes = new JSONObject();
      if(!permissions.isEmpty())
      {
         attributes.put("qqq.io/permissions", new JSONArray(permissions));
      }
      if(!appAccess.isEmpty())
      {
         attributes.put("qqq.io/app-access", new JSONArray(appAccess));
      }
      JSONArray parents = new JSONArray();
      for(String parentName : parentNames)
      {
         parents.put(groupByName(parentName).getString("pk"));
      }
      String pk = UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8)).toString();
      groups.put(pk, new JSONObject().put("pk", pk).put("name", name).put("is_superuser", superuser).put("parents", parents)
         .put("attributes", attributes).put("users", new JSONArray()));
      return (this);
   }



   /*******************************************************************************
    ** The group pk for a name.
    *******************************************************************************/
   public String pk(String groupName)
   {
      return (groupByName(groupName).getString("pk"));
   }



   /*******************************************************************************
    ** The group object for a name.
    *******************************************************************************/
   public JSONObject groupByName(String name)
   {
      return (groups.values().stream().filter(g -> g.getString("name").equals(name)).findFirst().orElseThrow(() -> new IllegalStateException("no group " + name)));
   }



   /*******************************************************************************
    ** Names of the groups a user is a direct member of.
    *******************************************************************************/
   public List<String> groupNamesOf(int userPk)
   {
      List<String> rs = new ArrayList<>();
      for(JSONObject group : groups.values())
      {
         if(contains(group.getJSONArray("users"), userPk))
         {
            rs.add(group.getString("name"));
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** Whether any group in the user's ancestry is a superuser group.
    *******************************************************************************/
   private boolean inheritedSuperuser(String groupPk, int depth)
   {
      JSONObject group = groups.get(groupPk);
      if(group == null || depth > 20)
      {
         return (false);
      }
      if(group.getBoolean("is_superuser"))
      {
         return (true);
      }
      for(int i = 0; i < group.getJSONArray("parents").length(); i++)
      {
         if(inheritedSuperuser(group.getJSONArray("parents").getString(i), depth + 1))
         {
            return (true);
         }
      }
      return (false);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static boolean contains(JSONArray array, int pk)
   {
      for(int i = 0; i < array.length(); i++)
      {
         if(array.getInt(i) == pk)
         {
            return (true);
         }
      }
      return (false);
   }



   /*******************************************************************************
    ** A user as the API returns it (with groups_obj and derived is_superuser).
    *******************************************************************************/
   private JSONObject render(JSONObject user)
   {
      JSONObject rs        = new JSONObject(user.toString());
      JSONArray  groupsObj = new JSONArray();
      boolean    superuser = user.optBoolean("is_superuser");
      for(JSONObject group : groups.values())
      {
         if(contains(group.getJSONArray("users"), user.getInt("pk")))
         {
            groupsObj.put(new JSONObject().put("pk", group.getString("pk")).put("name", group.getString("name")));
            superuser |= inheritedSuperuser(group.getString("pk"), 0);
         }
      }
      return (rs.put("groups_obj", groupsObj).put("roles_obj", new JSONArray()).put("is_superuser", superuser));
   }



   /*******************************************************************************
    ** A group as the API returns it.
    *******************************************************************************/
   private JSONObject render(JSONObject group, boolean includeUsers)
   {
      JSONObject rs = new JSONObject(group.toString());
      if(!includeUsers)
      {
         rs.remove("users");
      }
      JSONArray parentsObj = new JSONArray();
      for(int i = 0; i < group.getJSONArray("parents").length(); i++)
      {
         JSONObject parent = groups.get(group.getJSONArray("parents").getString(i));
         if(parent != null)
         {
            parentsObj.put(new JSONObject().put("pk", parent.getString("pk")).put("name", parent.getString("name")));
         }
      }
      return (rs.put("parents_obj", parentsObj).put("children_obj", new JSONArray()).put("roles_obj", new JSONArray()));
   }



   /*******************************************************************************
    ** The fake server.
    *******************************************************************************/
   public QHttpResponse handle(HttpRequestBase request)
   {
      URI    uri    = request.getURI();
      String path   = uri.getPath().replace("/api/v3", "");
      String method = request.getMethod();
      Map<String, List<String>> query = parseQuery(uri.getRawQuery());
      if(path.equals("/application/o/token/"))
      {
         try
         {
            Map<String, List<String>> form = parseQuery(EntityUtils.toString(((HttpEntityEnclosingRequest) request).getEntity()));
            String subject = first(form, "subject_token");
            int pk = subject != null && subject.startsWith("subject:") ? Integer.parseInt(subject.substring(8)) : -1;
            if(!users.containsKey(pk) || deniedSubjects.contains(pk))
            {
               return (ok(400, new JSONObject().put("error", "invalid_grant")));
            }
            return (ok(200, new JSONObject().put("access_token", "user-bearer:" + pk).put("expires_in", 120)));
         }
         catch(Exception e)
         {
            return (ok(400, new JSONObject().put("error", "invalid_request")));
         }
      }
      JSONObject body = body(request);
      String authorization = request.getFirstHeader("Authorization") == null ? "" : request.getFirstHeader("Authorization").getValue();
      int caller = authorization.startsWith("Bearer user-bearer:") ? Integer.parseInt(authorization.substring("Bearer user-bearer:".length())) : 5;

      if(!method.equals("GET"))
      {
         writes.add(method + " " + path + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery()));
         writeBodies.add(body == null ? new JSONObject() : body);
      }

      if(path.startsWith("/core/tokens/") && !path.equals("/core/tokens/") || path.equals("/core/tokens/") && method.equals("POST"))
      {
         return (tokenRequest(method, path, body, caller));
      }
      if(path.equals("/core/users/service_account/"))
      {
         int pk = nextUserPk++;
         String name = body.getString("name");
         user(pk, name, "", "service_account", true);
         users.get(pk).getJSONObject("attributes").put("goauthentik.io/user/token-expires", body.optBoolean("expiring", true));
         String identifier = "service-account-" + name + "-password";
         seedToken(identifier, pk, "app_password", body.getString("expires"));
         return (ok(200, new JSONObject().put("username", name).put("user_pk", pk).put("user_uid", UUID.randomUUID().toString()).put("token", tokenKeys.get(identifier))));
      }
      if(method.equals("GET"))
      {
         return (get(path, query));
      }

      if(path.equals("/events/events/"))
      {
         events.add(body);
         return (ok(201, new JSONObject().put("pk", UUID.randomUUID().toString())));
      }
      if(path.equals("/core/users/") && method.equals("POST"))
      {
         int pk = nextUserPk++;
         JSONObject user = new JSONObject(body.toString()).put("pk", pk).put("last_updated", "2026-10-12T00:00:00Z");
         if(!user.has("attributes"))
         {
            user.put("attributes", new JSONObject());
         }
         users.put(pk, user);
         return (ok(201, render(user)));
      }
      if(path.equals("/core/groups/") && method.equals("POST"))
      {
         String pk = UUID.nameUUIDFromBytes(body.getString("name").getBytes(StandardCharsets.UTF_8)).toString();
         JSONObject group = new JSONObject(body.toString()).put("pk", pk).put("users", new JSONArray());
         groups.put(pk, group);
         return (ok(201, render(group, true)));
      }
      if(path.matches("/core/users/\\d+/") && method.equals("PATCH"))
      {
         JSONObject user = users.get(Integer.parseInt(path.split("/")[3]));
         for(String key : body.keySet())
         {
            user.put(key, body.get(key));
         }
         user.put("last_updated", "2026-10-12T01:00:00Z");
         return (ok(200, render(user)));
      }
      if(path.matches("/core/users/[0-9]+/") && method.equals("DELETE"))
      {
         int pk = Integer.parseInt(path.split("/")[3]);
         users.remove(pk);
         for(JSONObject group : groups.values())
         {
            JSONArray kept = new JSONArray();
            for(int i = 0; i < group.getJSONArray("users").length(); i++)
            {
               if(group.getJSONArray("users").getInt(i) != pk)
               {
                  kept.put(group.getJSONArray("users").getInt(i));
               }
            }
            group.put("users", kept);
         }
         return (ok(204, null));
      }
      if(path.matches("/core/groups/[^/]+/") && method.equals("DELETE"))
      {
         groups.remove(path.split("/")[3]);
         return (ok(204, null));
      }
      if(path.matches("/core/groups/[^/]+/") && method.equals("PATCH"))
      {
         JSONObject group = groups.get(path.split("/")[3]);
         for(String key : body.keySet())
         {
            group.put(key, body.get(key));
         }
         return (ok(200, render(group, true)));
      }
      if(path.matches("/core/groups/[^/]+/(add_user|remove_user)/"))
      {
         JSONObject group = groups.get(path.split("/")[3]);
         int        pk    = body.getInt("pk");
         JSONArray  users = group.getJSONArray("users");
         if(path.endsWith("add_user/"))
         {
            if(!contains(users, pk))
            {
               users.put(pk);
            }
         }
         else
         {
            JSONArray kept = new JSONArray();
            for(int i = 0; i < users.length(); i++)
            {
               if(users.getInt(i) != pk)
               {
                  kept.put(users.getInt(i));
               }
            }
            group.put("users", kept);
         }
         return (ok(204, null));
      }
      if(path.matches("/core/users/\\d+/recovery_email/"))
      {
         return (ok(204, null));
      }
      if(path.matches("/core/tokens/[^/]+/") && method.equals("DELETE"))
      {
         String identifier = path.split("/")[3];
         tokens.values().forEach(list -> list.removeIf(t -> t.getString("identifier").equals(identifier)));
         return (ok(204, null));
      }
      if(path.equals("/core/authenticated_sessions/bulk_delete/"))
      {
         sessions.remove(first(query, "user_pks"));
         return (ok(204, null));
      }
      if(path.matches("/authenticators/admin/[a-z]+/[^/]+/") && method.equals("DELETE"))
      {
         String id = path.split("/")[4];
         devices.values().forEach(list -> list.removeIf(d -> String.valueOf(d.get("pk")).equals(id)));
         return (ok(204, null));
      }
      if(path.equals("/stages/invitation/invitations/") && method.equals("POST"))
      {
         String pk = UUID.randomUUID().toString();
         invitations.put(pk, new JSONObject(body.toString()).put("pk", pk));
         return (ok(201, invitations.get(pk)));
      }
      if(path.matches("/stages/invitation/invitations/[^/]+/send_email/"))
      {
         return (ok(200, new JSONObject()));
      }
      if(path.matches("/stages/invitation/invitations/[^/]+/") && method.equals("DELETE"))
      {
         invitations.remove(path.split("/")[4]);
         return (ok(204, null));
      }
      return (FixtureActionUtil.response(404, "{\"detail\":\"Not found.\"}"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private QHttpResponse get(String path, Map<String, List<String>> query)
   {
      if(path.equals("/core/users/"))
      {
         List<JSONObject> rs = new ArrayList<>();
         for(JSONObject user : users.values())
         {
            JSONObject rendered = render(user);
            if(query.containsKey("email") && !first(query, "email").equalsIgnoreCase(user.optString("email")))
            {
               continue;
            }
            if(query.containsKey("username") && !first(query, "username").equalsIgnoreCase(user.optString("username")))
            {
               continue;
            }
            if(query.containsKey("type") && !query.get("type").contains(user.optString("type")))
            {
               continue;
            }
            if(query.containsKey("is_active") && user.optBoolean("is_active") != Boolean.parseBoolean(first(query, "is_active")))
            {
               continue;
            }
            if(query.containsKey("path_startswith") && !user.optString("path").startsWith(first(query, "path_startswith")))
            {
               continue;
            }
            List<String> names = groupNamesOf(user.getInt("pk"));
            if(query.containsKey("groups_by_name") && names.stream().noneMatch(query.get("groups_by_name")::contains))
            {
               continue;
            }
            if(query.containsKey("groups_by_pk") && names.stream().map(this::pk).noneMatch(query.get("groups_by_pk")::contains))
            {
               continue;
            }
            rs.add(rendered);
         }
         if("username".equals(first(query, "ordering")))
         {
            rs.sort(java.util.Comparator.comparing(user -> user.getString("username")));
         }
         if(query.containsKey("page_size"))
         {
            int size = Integer.parseInt(first(query, "page_size"));
            int number = Integer.parseInt(first(query, "page"));
            int from = Math.min(rs.size(), (number - 1) * size);
            int to = Math.min(rs.size(), from + size);
            return (ok(200, new JSONObject().put("pagination", new JSONObject().put("count", rs.size()).put("current", number)
               .put("total_pages", Math.max(1, (rs.size() + size - 1) / size))).put("results", new JSONArray(rs.subList(from, to)))));
         }
         return (page(rs));
      }
      if(path.matches("/core/users/\\d+/"))
      {
         JSONObject user = users.get(Integer.parseInt(path.split("/")[3]));
         return (user == null ? FixtureActionUtil.response(404, "{}") : ok(200, render(user)));
      }
      if(path.equals("/core/groups/"))
      {
         boolean includeUsers = "true".equals(first(query, "include_users"));
         List<JSONObject> rs = new ArrayList<>();
         for(JSONObject group : groups.values())
         {
            if(query.containsKey("name") && !first(query, "name").equals(group.getString("name")))
            {
               continue;
            }
            rs.add(render(group, includeUsers));
         }
         return (page(rs));
      }
      if(path.matches("/core/groups/[^/]+/"))
      {
         JSONObject group = groups.get(path.split("/")[3]);
         return (group == null ? FixtureActionUtil.response(404, "{}") : ok(200, render(group, "true".equals(first(query, "include_users")))));
      }
      if(path.equals("/core/tokens/"))
      {
         List<JSONObject> rs = new ArrayList<>();
         if(query.containsKey("user__username"))
         {
            rs.addAll(tokens.getOrDefault(first(query, "user__username"), List.of()));
         }
         else
         {
            tokens.values().forEach(rs::addAll);
         }
         rs.replaceAll(this::renderToken);
         String intent = first(query, "intent");
         if(intent != null)
         {
            rs.removeIf(t -> !intent.equals(t.optString("intent")));
         }
         return (page(rs));
      }
      if(path.equals("/core/authenticated_sessions/"))
      {
         return (page(new ArrayList<>()));
      }
      if(path.equals("/authenticators/admin/all/"))
      {
         JSONArray rs = new JSONArray();
         devices.getOrDefault(Integer.parseInt(first(query, "user")), List.of()).forEach(rs::put);
         return (ok(200, rs));
      }
      if(path.equals("/stages/email/"))
      {
         return (page(List.of(new JSONObject().put("pk", "11111111-1111-1111-1111-111111111111").put("name", first(query, "name")))));
      }
      if(path.equals("/flows/instances/"))
      {
         return (page(List.of(new JSONObject().put("pk", "22222222-2222-2222-2222-222222222222").put("slug", first(query, "slug")))));
      }
      if(path.matches("/stages/invitation/invitations/[^/]+/"))
      {
         JSONObject invitation = invitations.get(path.split("/")[4]);
         return (invitation == null ? FixtureActionUtil.response(404, "{}") : ok(200, invitation));
      }
      if(path.equals("/events/events/"))
      {
         List<JSONObject> selected = new ArrayList<>(loginEvents);
         String action = first(query, "action");
         if(action != null)
         {
            selected.removeIf(event -> !action.equals(event.optString("action")));
         }
         if("-created".equals(first(query, "ordering")))
         {
            selected.sort(java.util.Comparator.comparing((JSONObject event) -> java.time.Instant.parse(event.getString("created"))).reversed());
         }
         int size = query.containsKey("page_size") ? Integer.parseInt(first(query, "page_size")) : 100;
         int number = query.containsKey("page") ? Integer.parseInt(first(query, "page")) : 1;
         int from = Math.min(selected.size(), (number - 1) * size);
         int to = Math.min(selected.size(), from + size);
         return (ok(200, new JSONObject().put("pagination", new JSONObject().put("count", selected.size()).put("current", number)
            .put("total_pages", Math.max(1, (selected.size() + size - 1) / size))).put("results", new JSONArray(selected.subList(from, to)))));
      }
      if(path.equals("/managed/blueprints/") || path.equals("/core/applications/"))
      {
         return (page(new ArrayList<>()));
      }
      return (FixtureActionUtil.response(404, "{\"detail\":\"Not found.\"}"));
   }



   /*******************************************************************************
    ** Seed an app password or API token with an independent fake key.
    *******************************************************************************/
   public JSONObject seedToken(String identifier, int owner, String intent, String expires)
   {
      JSONObject token = new JSONObject().put("identifier", identifier).put("user", owner).put("intent", intent)
         .put("description", "Test access").put("expiring", true).put("expires", expires).put("managed", JSONObject.NULL);
      tokens.computeIfAbsent(users.get(owner).getString("username"), k -> new ArrayList<>()).add(token);
      tokenKeys.put(identifier, UUID.randomUUID().toString() + UUID.randomUUID());
      return (token);
   }



   /*******************************************************************************
    ** Metadata never contains a key, including list and detail responses.
    *******************************************************************************/
   private JSONObject renderToken(JSONObject token)
   {
      JSONObject result = new JSONObject(token.toString());
      if(token.has("user") && users.containsKey(token.getInt("user")))
      {
         result.put("user_obj", render(users.get(token.getInt("user"))));
      }
      return (result);
   }



   /*******************************************************************************
    ** Authentik 2026.8.3 caller ownership, PATCH defaults, caps and key access.
    *******************************************************************************/
   private QHttpResponse tokenRequest(String method, String path, JSONObject body, int caller)
   {
      tokenCallers.add(caller);
      if(path.equals("/core/tokens/") && method.equals("POST"))
      {
         int owner = render(users.get(caller)).optBoolean("is_superuser") ? body.optInt("user", caller) : caller;
         JSONObject token = seedToken(body.getString("identifier"), owner, body.optString("intent", "api"), body.optString("expires", java.time.Instant.now().plusSeconds(1800).toString()));
         token.put("description", body.optString("description"));
         if(!capExpiry(token))
         {
            tokens.values().forEach(list -> list.remove(token));
            tokenKeys.remove(token.getString("identifier"));
            return (ok(400, new JSONObject().put("expires", "Token expires exceeds maximum lifetime")));
         }
         return (ok(201, renderToken(token)));
      }
      String identifier = path.split("/")[3];
      JSONObject token = tokens.values().stream().flatMap(List::stream).filter(t -> identifier.equals(t.optString("identifier"))).findFirst().orElse(null);
      if(token == null)
      {
         return (ok(404, new JSONObject()));
      }
      if(path.endsWith("/view_key/"))
      {
         return (token.optInt("user") == caller ? ok(200, new JSONObject().put("key", tokenKeys.get(identifier))) : ok(403, new JSONObject()));
      }
      if(method.equals("GET"))
      {
         return (ok(200, renderToken(token)));
      }
      if(caller != 5 && token.optInt("user") != caller)
      {
         return (ok(403, new JSONObject()));
      }
      if(method.equals("DELETE"))
      {
         if(failTokenDelete)
         {
            return (ok(400, new JSONObject().put("detail", "delete refused")));
         }
         tokens.values().forEach(list -> list.removeIf(t -> identifier.equals(t.optString("identifier"))));
         tokenKeys.remove(identifier);
         return (ok(204, null));
      }
      if(path.endsWith("/set_key/"))
      {
         tokenKeys.put(identifier, body.getString("key"));
      }
      else if(method.equals("PATCH"))
      {
         // validate_user runs for explicitly supplied user; setdefault is later.
         if(body.has("user") && body.getInt("user") != token.getInt("user"))
         {
            return (ok(400, new JSONObject().put("user", "User cannot be changed")));
         }
         JSONObject original = new JSONObject(token.toString());
         token.put("intent", body.optString("intent", "api")).put("user", body.optInt("user", caller));
         if(body.has("expires"))
         {
            token.put("expires", body.getString("expires"));
         }
         token.put("expiring", body.optBoolean("expiring", token.optBoolean("expiring")));
         if(!capExpiry(token))
         {
            original.keySet().forEach(key -> token.put(key, original.get(key)));
            return (ok(400, new JSONObject().put("expires", "Token expires exceeds maximum lifetime")));
         }
      }
      if(moveTokenAfterUpdate)
      {
         token.put("user", 4).put("intent", "api");
      }
      return (ok(200, renderToken(token)));
   }



   /*******************************************************************************
    ** Brand attributes, then group attributes, then user attributes set the cap.
    *******************************************************************************/
   private boolean capExpiry(JSONObject token)
   {
      java.time.Instant now = java.time.Instant.now();
      long seconds = 1800;
      if("app_password".equals(token.optString("intent")))
      {
         JSONObject attributes = new JSONObject(brandAttributes.toString());
         com.kingsrook.qbits.authentik.permissions.GroupGraph graph = com.kingsrook.qbits.authentik.permissions.GroupGraph.fromGroups(groups.values());
         graph.groupsOfUser(token.getInt("user")).stream().flatMap(pk -> graph.selfAndAncestors(pk).stream())
            .distinct().sorted(java.util.Comparator.comparing(com.kingsrook.qbits.authentik.permissions.GroupGraph.Node::name)).forEach(group ->
            {
               JSONObject values = groups.get(group.pk()).getJSONObject("attributes");
               values.keySet().forEach(key -> attributes.put(key, values.get(key)));
            });
         JSONObject values = users.get(token.getInt("user")).getJSONObject("attributes");
         values.keySet().forEach(key -> attributes.put(key, values.get(key)));
         String lifetime = attributes.optString("goauthentik.io/user/token-maximum-lifetime");
         if(lifetime.matches("days=[0-9]+"))
         {
            seconds = Long.parseLong(lifetime.substring(5)) * 86400;
         }
      }
      java.time.Instant cap = now.plusSeconds(seconds);
      java.time.Instant requested = java.time.Instant.parse(token.getString("expires"));
      if("api".equals(token.optString("intent")))
      {
         token.put("expires", cap.toString());
         return (true);
      }
      return (!requested.isAfter(cap));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static QHttpResponse page(List<JSONObject> results)
   {
      return (ok(200, new JSONObject().put("pagination", new JSONObject().put("count", results.size()).put("current", 1).put("total_pages", 1))
         .put("results", new JSONArray(results))));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static QHttpResponse ok(int status, Object body)
   {
      return (FixtureActionUtil.response(status, body == null ? "" : body.toString()));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static JSONObject body(HttpRequestBase request)
   {
      try
      {
         if(request instanceof HttpEntityEnclosingRequest entityRequest && entityRequest.getEntity() != null)
         {
            return (new JSONObject(EntityUtils.toString(entityRequest.getEntity())));
         }
      }
      catch(IOException e)
      {
         throw (new IllegalStateException(e));
      }
      return (null);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String first(Map<String, List<String>> query, String name)
   {
      List<String> values = query.get(name);
      return (values == null || values.isEmpty() ? null : values.get(0));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static Map<String, List<String>> parseQuery(String rawQuery)
   {
      Map<String, List<String>> rs = new LinkedHashMap<>();
      if(rawQuery == null)
      {
         return (rs);
      }
      for(String pair : rawQuery.split("&"))
      {
         String[] kv = pair.split("=", 2);
         rs.computeIfAbsent(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), k -> new ArrayList<>()).add(kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
      }
      return (rs);
   }

}
