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

package com.kingsrook.qbits.authentik.processes;


import java.time.Instant;
import java.time.temporal.ChronoUnit;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.admin.AuthentikTokenAlerts;
import com.kingsrook.qbits.authentik.admin.TokenScopeStore;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.processes.BackendStep;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.json.JSONObject;


/*******************************************************************************
 ** Daily app-password expiry reminders, deduplicated in local token metadata.
 *******************************************************************************/
public class AuthentikTokenReminders implements BackendStep
{
   /*******************************************************************************
    ** The scheduler invokes the same guarded path as manual process execution.
    *******************************************************************************/
   @Override
   public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
   {
      run(AuthentikActionUtil.forBackend(input.getValueString("backendName")), Instant.now());
   }



   /*******************************************************************************
    ** Two non-overlapping windows avoid two reminders when first seen on day 1.
    ** Synchronization prevents overlapping local scheduled runs from duplicating.
    *******************************************************************************/
   public static void run(AuthentikActionUtil util, Instant now) throws QException
   {
      if(!(QContext.getQSession() instanceof com.kingsrook.qqq.backend.core.model.session.QSystemUserSession)
         && !AuthentikGuard.has(QContext.getQSession(), IdentityPermission.TOKENS_MANAGE))
      {
         throw (new QPermissionDeniedException("Token reminders require authentik.tokens.manage."));
      }
      AuthentikRuntime runtime = util.getRuntime();
      synchronized(runtime)
      {
         TokenScopeStore store = new TokenScopeStore(runtime.getConfig());
         for(JSONObject token : util.getAllPages("/core/tokens/?intent=app_password", Integer.MAX_VALUE))
         {
            if(!"app_password".equals(token.optString("intent")) || !token.optBoolean("expiring") || token.isNull("expires"))
            {
               continue;
            }
            Instant expires = Instant.parse(token.getString("expires"));
            if(!expires.isAfter(now) || expires.isAfter(now.plus(7, ChronoUnit.DAYS)))
            {
               continue;
            }
            String field = expires.isAfter(now.plus(1, ChronoUnit.DAYS)) ? "lastReminder7d" : "lastReminder1d";
            String id = token.getString("identifier");
            QRecord scope = store.find(id);
            Instant remindedAt = scope == null ? null : scope.getValueInstant(field);
            Instant windowStart = expires.minus(field.equals("lastReminder7d") ? 7 : 1, ChronoUnit.DAYS);
            if(remindedAt != null && !remindedAt.isBefore(windowStart))
            {
               continue;
            }
            int pk = token.has("user") ? token.getInt("user") : token.getJSONObject("user_obj").getInt("pk");
            JSONObject owner = util.getApiJsonOrNull("/core/users/" + pk + "/");
            if(owner == null || owner.optString("email").isBlank())
            {
               continue;
            }
            String message = "Your access token " + token.optString("description") + " (" + id + ") expires on " + expires
               + ". Extend or rotate it in Preferences > Access tokens.";
            if(runtime.getTokenAlerts().send(new AuthentikTokenAlerts.Notice("authentik_token_expiry:" + id + ":" + field + ":" + expires,
               "info", owner.getString("email"), message)))
            {
               store.reminded(id, owner, field, now);
            }
         }
      }
   }
}
