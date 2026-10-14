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


import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import com.kingsrook.qbits.authentik.admin.TokenScopeStore;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Non-secret local metadata and the most recent app-password login per token.
 *******************************************************************************/
public final class AuthentikTokenActivity
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikTokenActivity()
   {
   }



   /*******************************************************************************
    ** The pinned schema has no created__gt. Walk descending pages until the
    ** 90-day boundary instead of sending a silently ignored query parameter.
    *******************************************************************************/
   public static Map<String, Instant> lastUsed(AuthentikActionUtil util) throws QException
   {
      return (util.getRuntime().getTokenActivityCache().getResultThrowing("login", key ->
      {
         Map<String, Instant> latest = new LinkedHashMap<>();
         Instant cutoff = Instant.now().minus(90, ChronoUnit.DAYS);
         for(int page = 1; ; page++)
         {
            String path = "/events/events/?action=login&ordering=-created&page=" + page + "&page_size=100";
            util.getRuntime().getResponseCache().clearKey(util.getRuntime().getConfig().getApiRoot() + path);
            JSONObject response = util.getApiJson(path);
            JSONArray events = response.getJSONArray("results");
            for(int i = 0; i < events.length(); i++)
            {
               JSONObject event = events.getJSONObject(i);
               Instant at = Instant.parse(event.getString("created"));
               if(at.isBefore(cutoff))
               {
                  return (Map.copyOf(latest));
               }
               JSONObject context = event.optJSONObject("context");
               if("login".equals(event.optString("action")) && context != null && "token".equals(context.optString("method")))
               {
                  JSONObject args = context.optJSONObject("method_args");
                  String identifier = args == null ? "" : args.optString("identifier");
                  if(!identifier.isBlank())
                  {
                     latest.merge(identifier, at, (a, b) -> a.isAfter(b) ? a : b);
                  }
               }
            }
            if(events.isEmpty() || page >= response.getJSONObject("pagination").getInt("total_pages"))
            {
               return (Map.copyOf(latest));
            }
         }
      }).orElseThrow());
   }



   /*******************************************************************************
    ** Enrich only token records, never leaking token keys into the table.
    *******************************************************************************/
   public static void enrich(AuthentikActionUtil util, QRecord record) throws QException
   {
      var config = util.getRuntime().getConfig();
      QRecord scope = QContext.getQInstance().getTable(config.applyTablePrefix("token_scope")) == null ? null
         : new TokenScopeStore(config).find(record.getValueString("identifier"));
      record.setValue("createdAt", scope == null ? null : scope.getValue("createdAt"));
      record.setValue("scopeSummary", TokenScopeStore.summary(scope));
      if("api".equals(record.getValueString("intent")))
      {
         record.setValue("lastUsedNote", "not tracked");
         record.setDisplayValue("lastUsed", "not tracked");
      }
      else
      {
         record.setValue("lastUsed", lastUsed(util).get(record.getValueString("identifier")));
         record.setValue("lastUsedNote", record.getValue("lastUsed") == null ? "No login in the last 90 days" : null);
      }
   }
}
