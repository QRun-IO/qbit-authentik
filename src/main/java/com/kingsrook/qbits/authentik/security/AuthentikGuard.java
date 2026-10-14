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

package com.kingsrook.qbits.authentik.security;


import java.util.List;
import java.util.Locale;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.admin.AdminAction;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.client.AuthentikJson;
import com.kingsrook.qbits.authentik.client.AuthentikTableSpec;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.utils.CollectionUtils;
import com.kingsrook.qqq.backend.core.utils.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** The qbit's own enforcement point (DESIGN.md section 5.3). QQQ core actions
 ** do not enforce permissions for non-HTTP callers (QRun-IO/qqq#1061), so every
 ** call into AuthentikActionUtil is checked here first:
 ** - reads need the table's authentik.* permission (system sessions may read,
 **   for the mirror sync);
 ** - sensitive fields need authentik.audit.read;
 ** - writes are refused in this release (read-only MVP), and always refused
 **   for system sessions, in readOnly mode, or without the feature;
 ** - records outside userScope are invisible.
 **
 ** Protection rules for targets (protected accounts, superuser ancestry) are
 ** computed here too, so the UI can show them before writes exist.
 *******************************************************************************/
public class AuthentikGuard
{
   private final AuthentikQBitConfig config;



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   public AuthentikGuard(AuthentikQBitConfig config)
   {
      this.config = config;
   }



   /*******************************************************************************
    ** Check that the current session may read a table.
    *******************************************************************************/
   public void checkRead(AuthentikTableSpec spec) throws QPermissionDeniedException
   {
      QSession session = QContext.getQSession();
      if(!config.hasFeature(AuthentikFeature.READ))
      {
         throw (new QPermissionDeniedException("Authentik reads are not enabled."));
      }
      if(session instanceof QSystemUserSession)
      {
         return;
      }
      requireUser(session);
      if(!has(session, spec.getReadPermission()) && !(spec.getAlternativeReadPermission() != null && has(session, spec.getAlternativeReadPermission())))
      {
         throw (new QPermissionDeniedException("You do not have permission to view " + spec.getLabel() + "."));
      }
   }



   /*******************************************************************************
    ** Writes: refused in this release. Kept as the single gate later phases
    ** extend (feature flags, readOnly, system sessions, per-target rules).
    *******************************************************************************/
   public void checkWrite(AuthentikTableSpec spec, String operation) throws QPermissionDeniedException
   {
      QSession session = QContext.getQSession();
      if(session instanceof QSystemUserSession)
      {
         throw (new QPermissionDeniedException("System sessions may not change Authentik data."));
      }
      if(Boolean.TRUE.equals(config.getReadOnly()))
      {
         throw (new QPermissionDeniedException("The Identity screens are in read-only mode."));
      }
      throw (new QPermissionDeniedException(spec.getLabel() + " cannot be changed from QQQ in this release (" + operation + " is not available; use the Authentik admin UI)."));
   }



   /*******************************************************************************
    ** Authorize one change to Authentik for the current session: a signed-in
    ** user (never a system session), the action's feature on, not read-only,
    ** and the action's authentik.* permission. The returned authorization is
    ** what AuthentikActionUtil.write requires (DESIGN.md section 5.3).
    *******************************************************************************/
   public WriteAuthorization authorize(AdminAction action) throws QPermissionDeniedException
   {
      QSession session = QContext.getQSession();
      if(session instanceof QSystemUserSession)
      {
         throw (new QPermissionDeniedException("System sessions may not change Authentik data."));
      }
      requireUser(session);
      if(Boolean.TRUE.equals(config.getReadOnly()))
      {
         throw (new QPermissionDeniedException("The Identity screens are in read-only mode."));
      }
      if(!config.hasFeature(action.getFeature()))
      {
         throw (new QPermissionDeniedException(action.getLabel() + " is not enabled (feature " + action.getFeature() + ")."));
      }
      if(action.getPermission() != null && !has(session, action.getPermission()))
      {
         throw (new QPermissionDeniedException("You do not have permission to do this (" + action.getPermission().getShortName() + ")."));
      }
      if(action == AdminAction.CREATE_SERVICE_ACCOUNT && !has(session, IdentityPermission.USERS_MANAGE))
      {
         throw (new QPermissionDeniedException("Creating a service account also needs authentik.users.manage."));
      }
      return (new WriteAuthorization(action.name(), operatorEmail()));
   }



   /*******************************************************************************
    ** The current operator: the session user's id reference (an email in apps
    ** that sign in through Authentik), or null.
    *******************************************************************************/
   public String operatorEmail()
   {
      QSession session = QContext.getQSession();
      return (session == null || session.getUser() == null ? null : session.getUser().getIdReference());
   }



   /*******************************************************************************
    ** Self-service metadata reads need a signed-in person, not table permissions.
    ** The Preferences provider must additionally constrain every read to that owner.
    *******************************************************************************/
   public void checkTokenPreferencesRead() throws QPermissionDeniedException
   {
      QSession session = QContext.getQSession();
      requireUser(session);
      if(session instanceof QSystemUserSession || !config.hasFeature(AuthentikFeature.READ) || !config.hasFeature(AuthentikFeature.TOKENS))
      {
         throw (new QPermissionDeniedException("Access token preferences are not available."));
      }
   }



   /*******************************************************************************
    ** Whether the current session may see and filter sensitive fields.
    *******************************************************************************/
   public boolean maySeeSensitive()
   {
      QSession session = QContext.getQSession();
      return (session instanceof QSystemUserSession || has(session, IdentityPermission.AUDIT_READ));
   }



   /*******************************************************************************
    ** Whether a user object is inside the configured user scope. Applied to
    ** every record returned, in addition to the server-side scope filters.
    *******************************************************************************/
   public boolean isUserInScope(JSONObject user)
   {
      String type = user.optString("type", "");
      if(!List.of(AuthentikTables.DEFAULT_USER_TYPES).contains(type))
      {
         return (false);
      }

      if(StringUtils.hasContent(config.getUserScopePathStartsWith()) && !user.optString("path", "").startsWith(config.getUserScopePathStartsWith()))
      {
         return (false);
      }

      List<String> scopeGroups = CollectionUtils.nonNullList(config.getUserScopeGroupNames());
      if(!scopeGroups.isEmpty())
      {
         JSONArray groups = user.optJSONArray("groups_obj");
         if(groups == null)
         {
            return (false);
         }
         for(int i = 0; i < groups.length(); i++)
         {
            JSONObject group = groups.optJSONObject(i);
            if(group != null && scopeGroups.contains(group.optString("name")))
            {
               return (true);
            }
         }
         return (false);
      }
      return (true);
   }



   /*******************************************************************************
    ** Whether a user is protected from all qbit actions (DESIGN.md section
    ** 5.4 rule 1): the service account, users with qqq.io/protected: true,
    ** configured protectedUsernames, and superusers (including superuser
    ** status inherited through group parents, which Authentik reports in
    ** is_superuser).
    *******************************************************************************/
   public ProtectionResult protection(JSONObject user)
   {
      String username = user.optString("username", "");
      if(username.equalsIgnoreCase(config.getEffectiveServiceAccountUsername()))
      {
         return (ProtectionResult.of("the qbit's own service account"));
      }
      if(user.optBoolean("is_superuser", false))
      {
         return (ProtectionResult.of("Authentik superuser"));
      }
      if(isMarkedProtected(user))
      {
         return (ProtectionResult.of("marked qqq.io/protected"));
      }
      for(String protectedName : CollectionUtils.nonNullList(config.getProtectedUsernames()))
      {
         if(username.equalsIgnoreCase(protectedName))
         {
            return (ProtectionResult.of("listed in protectedUsernames"));
         }
      }
      if("internal_service_account".equals(user.optString("type")))
      {
         return (ProtectionResult.of("Authentik internal service account"));
      }
      return (ProtectionResult.NOT_PROTECTED);
   }



   /*******************************************************************************
    ** Whether a user carries qqq.io/protected: true (boolean or "true").
    *******************************************************************************/
   public static boolean isMarkedProtected(JSONObject user)
   {
      JSONObject attributes = user == null ? null : user.optJSONObject("attributes");
      return (attributes != null && isTrue(attributes.opt(AuthentikJson.ATTR_PROTECTED)));
   }



   /*******************************************************************************
    ** Whether the session holds an identity permission.
    *******************************************************************************/
   public static boolean has(QSession session, IdentityPermission permission)
   {
      return (session != null && session.hasPermission(permission.getSessionPermission()));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void requireUser(QSession session) throws QPermissionDeniedException
   {
      if(session == null || session.getUser() == null)
      {
         throw (new QPermissionDeniedException("A signed-in user is required."));
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static boolean isTrue(Object value)
   {
      if(value instanceof Boolean b)
      {
         return (b);
      }
      return (value != null && String.valueOf(value).trim().toLowerCase(Locale.ROOT).equals("true"));
   }



   /*******************************************************************************
    ** Result of a protection check.
    *******************************************************************************/
   public record ProtectionResult(boolean isProtected, String reason)
   {
      public static final ProtectionResult NOT_PROTECTED = new ProtectionResult(false, null);



      /*******************************************************************************
       ** A protected result with a reason.
       *******************************************************************************/
      public static ProtectionResult of(String reason)
      {
         return (new ProtectionResult(true, reason));
      }
   }

}
