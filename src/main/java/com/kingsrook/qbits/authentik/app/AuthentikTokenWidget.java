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

package com.kingsrook.qbits.authentik.app;


import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.TokenScopeStore;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikTokenActivity;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.TableData;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Standard TABLE widget: inventory, age and actionable cleanup suggestions.
 ** Computed fields never become API filters; links use owner or token keys.
 *******************************************************************************/
public class AuthentikTokenWidget extends AbstractWidgetRenderer
{
   /*******************************************************************************
    ** Check the permission here as well as in metadata (non-HTTP callers).
    *******************************************************************************/
   @Override
   public RenderWidgetOutput render(RenderWidgetInput input) throws QException
   {
      String backend = String.valueOf(((QWidgetMetaData) input.getWidgetMetaData()).getDefaultValues().get("backendName"));
      return (new RenderWidgetOutput(data(AuthentikActionUtil.forBackend(backend), Instant.now())));
   }



   /*******************************************************************************
    ** Report complete inventory and explicit unknown ages. An API token's
    ** activity is untracked and never qualifies as unused.
    *******************************************************************************/
   public static TableData data(AuthentikActionUtil util, Instant now) throws QException
   {
      if(!AuthentikGuard.has(QContext.getQSession(), IdentityPermission.TOKENS_MANAGE))
      {
         throw (new QPermissionDeniedException("Access token widgets require authentik.tokens.manage."));
      }
      AuthentikQBitConfig config = util.getRuntime().getConfig();
      List<JSONObject> tokens = util.getAllPages("/core/tokens/", Integer.MAX_VALUE);
      Map<String, Instant> activity = AuthentikTokenActivity.lastUsed(util);
      Map<String, List<String>> owners = new LinkedHashMap<>();
      Map<String, List<String>> ages = new LinkedHashMap<>();
      for(String bucket : List.of("<30d", "30-90d", "90-365d", ">365d", "unknown"))
      {
         ages.put(bucket, new ArrayList<>());
      }
      Map<Integer, JSONObject> users = new LinkedHashMap<>();
      List<Map<String, Object>> cleanup = new ArrayList<>();
      TokenScopeStore scopes = new TokenScopeStore(config);
      for(JSONObject token : tokens)
      {
         String id = token.getString("identifier");
         JSONObject owner = token.getJSONObject("user_obj");
         String username = owner.getString("username");
         owners.computeIfAbsent(username, k -> new ArrayList<>()).add(id);
         QRecord scope = scopes.find(id);
         Instant created = scope == null ? null : scope.getValueInstant("createdAt");
         long days = created == null ? -1 : ChronoUnit.DAYS.between(created, now);
         ages.get(days < 0 ? "unknown" : days < 30 ? "<30d" : days < 90 ? "30-90d" : days <= 365 ? "90-365d" : ">365d").add(id);
         int pk = owner.getInt("pk");
         if(!users.containsKey(pk))
         {
            users.put(pk, util.getApiJsonOrNull("/core/users/" + pk + "/"));
         }
         JSONObject live = users.get(pk);
         String links = link(list(config, "username", List.of(username)), username) + " / " + link(list(config, "identifier", List.of(id)), id);
         if(live != null && !live.optBoolean("is_active", true))
         {
            cleanup.add(row("Owner deactivated", 1, links));
         }
         Instant last = activity.get(id);
         Instant cutoff = now.minus(config.getTokenUnusedDays(), ChronoUnit.DAYS);
         // Without a creation time or an event we cannot prove age. A 90-day
         // event window cannot prove inactivity beyond 90 days either.
         boolean unused = last != null ? last.isBefore(cutoff)
            : config.getTokenUnusedDays() <= 90 && created != null && created.isBefore(cutoff);
         if("app_password".equals(token.optString("intent")) && unused)
         {
            cleanup.add(row("Unused for " + config.getTokenUnusedDays() + " days", 1, links));
         }
      }
      List<Map<String, Object>> rows = new ArrayList<>();
      rows.add(row("Total", tokens.size(), link(list(config, null, List.of()), "All access tokens")));
      owners.entrySet().stream().sorted(Comparator.<Map.Entry<String, List<String>>>comparingInt(e -> e.getValue().size()).reversed().thenComparing(Map.Entry::getKey))
         .limit(10).forEach(e -> rows.add(row("Owner: " + e.getKey(), e.getValue().size(), link(list(config, "username", List.of(e.getKey())), "Tokens"))));
      ages.forEach((bucket, ids) -> rows.add(row("Age: " + bucket, ids.size(), ids.isEmpty() ? "" : link(list(config, "identifier", ids), "Tokens"))));
      rows.addAll(cleanup);
      return (new TableData("Access tokens", List.of(
         new TableData.Column("default", "Category", "category", "35%", "left"),
         new TableData.Column("default", "Count", "count", "10%", "right"),
         new TableData.Column("html", "Access tokens", "tokens", "55%", "left")), rows)
         .withRowsPerPage(25).withLinkText("All access tokens / bulk revoke").withLinkURL(list(config, null, List.of())));
   }



   /*******************************************************************************
    ** A standard table row; only the link cell contains escaped anchor markup.
    *******************************************************************************/
   private static Map<String, Object> row(String category, int count, String tokens)
   {
      return (Map.of("category", category, "count", count, "tokens", tokens));
   }



   /*******************************************************************************
    ** Native list filter format shared by Material and Next. Primary-key IN is
    ** supported by the API adapter as individual GETs; no computed filtering.
    *******************************************************************************/
   private static String list(AuthentikQBitConfig config, String field, List<String> values)
   {
      String url = (config.getLinkPrefix() == null ? "" : config.getLinkPrefix()) + "/" + config.applyTablePrefix("token");
      if(field != null)
      {
         JSONObject criteria = new JSONObject().put("fieldName", field).put("operator", values.size() == 1 ? "EQUALS" : "IN").put("values", values);
         String filter = new JSONObject().put("booleanOperator", "AND").put("criteria", new JSONArray().put(criteria)).toString();
         url += "?filter=" + URLEncoder.encode(filter, StandardCharsets.UTF_8);
      }
      return (url);
   }



   /*******************************************************************************
    ** Escape both the link target and text; descriptions are never HTML.
    *******************************************************************************/
   private static String link(String url, String text)
   {
      return ("<a href=\"" + escape(url) + "\">" + escape(text) + "</a>");
   }



   /*******************************************************************************
    ** Minimal HTML escaping for a standard table link cell.
    *******************************************************************************/
   private static String escape(String value)
   {
      return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"));
   }
}
