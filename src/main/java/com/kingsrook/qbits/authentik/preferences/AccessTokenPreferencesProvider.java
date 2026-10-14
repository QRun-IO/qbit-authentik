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

package com.kingsrook.qbits.authentik.preferences;


import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.AdminAction;
import com.kingsrook.qbits.authentik.admin.AdminRequest;
import com.kingsrook.qbits.authentik.admin.AuthentikAdmin;
import com.kingsrook.qbits.authentik.admin.AuthentikTokens;
import com.kingsrook.qbits.authentik.admin.OneTimeKey;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.OAuth2SubjectTokenSource;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QBadRequestException;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceActionRequest;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceActionResult;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceChange;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceProviderInterface;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceRequestContext;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceRow;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceValues;
import com.kingsrook.qqq.backend.core.model.secrets.OneTimeSecret;
import org.json.JSONObject;


/*******************************************************************************
 ** Live personal app-password metadata and audited actions. Keys exist only in
 ** the immediate action response, never in stored or reloaded preference values.
 *******************************************************************************/
public class AccessTokenPreferencesProvider implements UserPreferenceProviderInterface
{
   /*******************************************************************************
    ** Resolve the configured qbit in this instance, including custom backend names.
    ** Refuse ambiguity rather than silently selecting another identity directory.
    *******************************************************************************/
   private AuthentikAdmin admin(UserPreferenceRequestContext context) throws QException
   {
      if(QContext.getQSession() != context.getSession())
      {
         throw (new QUserFacingException("The preference session changed; sign in again."));
      }
      List<AuthentikQBitConfig> configs = QContext.getQInstance().getQBits().values().stream()
         .map(qbit -> qbit.getConfig()).filter(AuthentikQBitConfig.class::isInstance).map(AuthentikQBitConfig.class::cast)
         .filter(config -> config.hasFeature(AuthentikFeature.TOKENS)).toList();
      if(configs.size() != 1)
      {
         throw (new QUserFacingException("Access token preferences need one configured Authentik directory."));
      }
      AuthentikAdmin admin = AuthentikAdmin.forBackend(configs.get(0).getApiBackendName());
      admin.getUtil().getRuntime().getGuard().checkTokenPreferencesRead();
      return (admin);
   }



   /*******************************************************************************
    ** Read all pages with server-side owner and intent constraints. A mismatched
    ** response fails closed; metadata is explicitly allowlisted, never copied whole.
    *******************************************************************************/
   @Override
   public UserPreferenceValues load(UserPreferenceRequestContext context) throws QException
   {
      AuthentikAdmin admin = admin(context);
      AuthentikActionUtil util = admin.getUtil();
      util.getRuntime().invalidateCache();
      Integer pk = admin.operator().pk();
      if(pk == null)
      {
         throw (new QUserFacingException(OAuth2SubjectTokenSource.UNAVAILABLE));
      }
      JSONObject owner = util.getApiJson("/core/users/" + pk + "/");
      String username = owner.getString("username");
      List<UserPreferenceRow> rows = new ArrayList<>();
      AuthentikTokens tokens = new AuthentikTokens(admin);
      for(JSONObject token : util.getAllPages("/core/tokens/?user__username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
         + "&intent=app_password", Integer.MAX_VALUE))
      {
         Object user = token.opt("user");
         int ownerPk = user instanceof JSONObject object ? object.optInt("pk", -1) : token.optInt("user", -1);
         if(ownerPk != pk || !"app_password".equals(token.optString("intent")))
         {
            throw (new QUserFacingException("Authentik returned tokens outside your personal token list."));
         }
         String identifier = token.getString("identifier");
         Map<String, Serializable> values = new LinkedHashMap<>();
         values.put("description", token.optString("description", ""));
         values.put("identifier", identifier);
         values.put("intent", "app_password");
         values.put("expires", token.isNull("expires") ? null : Instant.parse(token.getString("expires")));
         values.put("scope", tokens.scopeSummary(identifier));
         rows.add(new UserPreferenceRow().withKey(identifier).withLabel(token.optString("description", identifier)).withValues(values));
      }
      return (new UserPreferenceValues().withLists(Map.of(AccessTokenPreferences.LIST, rows)));
   }



   /*******************************************************************************
    ** Scalar and row edits are unavailable; lifecycle actions own every mutation.
    *******************************************************************************/
   @Override
   public void store(UserPreferenceRequestContext context, UserPreferenceChange change) throws QException
   {
      throw (new QBadRequestException("Use the access token actions to make changes."));
   }



   /*******************************************************************************
    ** Use the same live guards, broker and audit as record actions. The delivery
    ** channel is server-selected and never accepted as a client input field.
    *******************************************************************************/
   @Override
   public UserPreferenceActionResult runAction(UserPreferenceRequestContext context, UserPreferenceActionRequest request) throws QException
   {
      AdminAction action = switch(request.getActionName())
      {
         case "create" -> AdminAction.CREATE_TOKEN;
         case "rotate" -> AdminAction.ROTATE_TOKEN;
         case "extend" -> AdminAction.EXTEND_TOKEN;
         case "revoke" -> AdminAction.REVOKE_TOKEN;
         default -> throw new QBadRequestException("This action isn't available.");
      };
      AdminRequest change = AdminRequest.of(action, request.getRowKey() == null ? "" : request.getRowKey(), "Preferences: " + request.getActionName());
      for(String field : List.of("description", "expiresInDays", "readOnly", "apps", "tables"))
      {
         if(request.getValues().containsKey(field))
         {
            change.with(field, request.getValues().get(field));
         }
      }
      change.with("deliveryChannel", "preferences");
      AuthentikAdmin.AdminResult result = admin(context).execute(change);
      if(!result.ok())
      {
         throw (new QUserFacingException(result.message()));
      }
      UserPreferenceActionResult response = new UserPreferenceActionResult().withMessage(result.message());
      OneTimeKey key = result.takeSecret();
      if(key != null)
      {
         response.withFocusRowKey(key.label()).withSecrets(List.of(new OneTimeSecret().withLabel("Access token")
            .withValue(key.value()).withMasked(key.masked()).withUsageText(key.usageText())));
      }
      result.delivered();
      return (response);
   }
}
