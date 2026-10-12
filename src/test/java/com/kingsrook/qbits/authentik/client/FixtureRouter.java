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

package com.kingsrook.qbits.authentik.client;


import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import com.kingsrook.qqq.backend.module.api.actions.QHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** A FixtureActionUtil handler that answers like a small Authentik built from
 ** the recorded 2026.8.3 fixtures: users (with groups), groups (with users),
 ** tokens, blueprints, events and sessions, honouring the query parameters
 ** the qbit sends. Tests mutate the JSON to build scenarios.
 *******************************************************************************/
public class FixtureRouter implements Function<HttpRequestBase, QHttpResponse>
{
   public final List<JSONObject> users      = results("users-list");
   public final List<JSONObject> groups     = results("groups-list-with-users");
   public final List<JSONObject> tokens     = results("tokens-list");
   public final List<JSONObject> blueprints = results("blueprints-list");
   public final List<JSONObject> events     = results("events-by-service-account");
   public final List<JSONObject> sessions   = results("sessions-list");



   /*******************************************************************************
    ** Results of a recorded list fixture (mutable copies).
    *******************************************************************************/
   public static List<JSONObject> results(String fixture)
   {
      JSONArray        array = new JSONObject(FixtureActionUtil.fixture(fixture)).getJSONArray("results");
      List<JSONObject> rs    = new ArrayList<>();
      for(int i = 0; i < array.length(); i++)
      {
         rs.add(new JSONObject(array.getJSONObject(i).toString()));
      }
      return (rs);
   }



   /*******************************************************************************
    ** Install as the FixtureActionUtil handler (and as the group graph).
    *******************************************************************************/
   public FixtureRouter install()
   {
      FixtureActionUtil.handler = this;
      FixtureActionUtil.groupGraphBody = page(groups).toString();
      return (this);
   }



   /*******************************************************************************
    ** Refresh the group-graph body after mutating groups.
    *******************************************************************************/
   public void refreshGraph()
   {
      FixtureActionUtil.groupGraphBody = page(groups).toString();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public QHttpResponse apply(HttpRequestBase request)
   {
      String path = request.getURI().getPath().replaceFirst("^/api/v3", "");
      if(path.equals("/core/users/"))
      {
         return (ok(page(filter(users, request, "username", "username"))));
      }
      if(path.matches("/core/users/[0-9]+/"))
      {
         int pk = Integer.parseInt(path.split("/")[3]);
         return (users.stream().filter(u -> u.getInt("pk") == pk).findFirst().map(FixtureRouter::ok).orElse(FixtureActionUtil.response(404, "{}")));
      }
      if(path.equals("/core/groups/"))
      {
         return (ok(page(filter(groups, request, "name", "name"))));
      }
      if(path.matches("/core/groups/[^/]+/"))
      {
         String pk = path.split("/")[3];
         return (groups.stream().filter(g -> g.getString("pk").equals(pk)).findFirst().map(FixtureRouter::ok).orElse(FixtureActionUtil.response(404, "{}")));
      }
      if(path.equals("/core/tokens/"))
      {
         return (ok(page(tokens)));
      }
      if(path.equals("/managed/blueprints/"))
      {
         return (ok(page(blueprints)));
      }
      if(path.equals("/events/events/"))
      {
         return (ok(page(filter(events, request, "username", null))));
      }
      if(path.equals("/core/authenticated_sessions/"))
      {
         return (ok(page(sessions)));
      }
      return (FixtureActionUtil.response(404, "{\"detail\":\"Not found.\"}"));
   }



   /*******************************************************************************
    ** Apply a simple equality query parameter, plus the users attributes filter.
    *******************************************************************************/
   private static List<JSONObject> filter(List<JSONObject> objects, HttpRequestBase request, String param, String property)
   {
      String           value = param(request, param);
      String           attrs = param(request, "attributes");
      Predicate<JSONObject> keep = o -> true;
      if(value != null && property != null)
      {
         keep = keep.and(o -> value.equals(o.optString(property)));
      }
      if(attrs != null)
      {
         JSONObject wanted = new JSONObject(attrs);
         keep = keep.and(o ->
         {
            JSONObject attributes = o.optJSONObject("attributes");
            return (attributes != null && wanted.keySet().stream().allMatch(k -> String.valueOf(wanted.get(k)).equals(String.valueOf(attributes.opt(k)))));
         });
      }
      return (objects.stream().filter(keep).toList());
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String param(HttpRequestBase request, String name)
   {
      String query = request.getURI().getRawQuery();
      if(query == null)
      {
         return (null);
      }
      for(String pair : query.split("&"))
      {
         String[] parts = pair.split("=", 2);
         if(parts[0].equals(name) && parts.length == 2)
         {
            return (URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
         }
      }
      return (null);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   public static JSONObject page(List<JSONObject> objects)
   {
      return (new JSONObject()
         .put("pagination", new JSONObject().put("count", objects.size()).put("current", 1).put("total_pages", 1))
         .put("results", new JSONArray(objects)));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static QHttpResponse ok(JSONObject body)
   {
      return (FixtureActionUtil.response(200, body.toString()));
   }

}
