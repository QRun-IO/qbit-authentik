/*
 * Copyright 2026 Kingsrook, LLC
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kingsrook.qbits.authentik.permissions;

import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.security.AuthentikSessionIdentity;
import com.kingsrook.qbits.authentik.security.AuthentikTokenScopes;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qbits.authentik.sync.AuthentikMirrorAccess;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QAuthenticationException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import org.json.JSONObject;

/*******************************************************************************
 ** Opt-in customizer for AuthentikRefreshingOAuth2Module. Replaces directory
 ** grants from a fresh mirror; never unions token policies or old permissions.
 ** Host-specific access must use withHostPermissionSource/static group grants.
 ** Automated sessions retain the existing fresh API lookup in the superclass.
 ******************************************************************************/
public class AuthentikRefreshingPermissionMapper extends AuthentikGroupPermissionMapper
{
   static final String CLAIMS = "authentik.verifiedSessionClaims";
   static final String BACKEND = "authentik.sessionBackend";

   /***************************************************************************
    ** Capture only verified identity/credential facts, never access tokens,
    ** old groups or policies. QSession values are internal, not frontend values.
    ***************************************************************************/
   @Override
   public void customizeSession(QInstance instance, QSession session, Map<String, Object> context)
   {
      session.setPermissions(new TreeSet<>());
      session.setValue(CLAIMS, null);
      session.setValue(BACKEND, null);
      try
      {
         Object source = context == null ? null : context.get(CLAIMS_CONTEXT_KEY);
         JSONObject claims = source instanceof JSONObject object ? object : source instanceof Map<?, ?> map ? new JSONObject(map) : null;
         if(AuthentikSessionIdentity.fromVerifiedClaims(claims).isEmpty())
         {
            throw (new QAuthenticationException("A signed immutable Authentik identity is required."));
         }
         String scopeClaim = runtime().getConfig().getTokenScopeClaim();
         JSONObject retained = new JSONObject();
         for(String key : java.util.List.of(AuthentikSessionIdentity.CLAIM, "sub", "iss", "iat", "exp", scopeClaim))
         {
            if(claims.has(key))
            {
               retained.put(key, claims.get(key));
            }
         }
         session.setValue(CLAIMS, retained.toString());
         session.setValue(BACKEND, getApiBackendName());
         refresh(instance, session);
      }
      catch(Exception failure)
      {
         session.setPermissions(new TreeSet<>());
         session.setValue(CLAIMS, null);
         throw (new IllegalStateException("Current Authentik session access could not be established."));
      }
   }

   /***************************************************************************
    ** Reevaluate under a short internal read context and always restore it.
    ** Credential restrictions are reapplied AFTER all current grants and floors.
    ***************************************************************************/
   public void refresh(QInstance instance, QSession session) throws QAuthenticationException
   {
      session.setPermissions(new TreeSet<>());
      var previous = QContext.capture();
      try
      {
         if(!getApiBackendName().equals(session.getValue(BACKEND)))
         {
            throw (new QAuthenticationException("Session authentication backend changed."));
         }
         JSONObject claims = new JSONObject(session.getValue(CLAIMS));
         var identity = AuthentikSessionIdentity.fromVerifiedClaims(claims).orElseThrow();
         QContext.init(instance, new QSystemUserSession(instance));
         var runtime = runtime();
         var config = runtime.getConfig();
         if(!com.kingsrook.qbits.authentik.security.AuthentikIssuer.matches(config.getAuthentikPublicUrl(), claims.opt("iss")))
         {
            throw (new QAuthenticationException("Verified identity issuer does not match the configured Authentik instance."));
         }
         var current = readCurrent(identity);
         if(current.status() != AuthentikMirrorAccess.Status.READY)
         {
            throw (new QAuthenticationException("Current Authentik access is unavailable or denied."));
         }
         var access = current.access();
         Set<String> permissions = new TreeSet<>(configuredStaticPermissions(access.groups()));
         permissions.addAll(AccessComparison.staticPermissions(config, access.groups()));
         var bootstrap = config.getResolvedBootstrapSubjects();
         String sub = claims.optString("sub", "");
         if(bootstrap.contains(Integer.toString(identity.pk())) || bootstrap.contains(identity.uuid())
            || (!sub.isBlank() && !sub.contains("@") && bootstrap.contains(sub)))
         {
            for(var permission : IdentityPermission.values())
            {
               permissions.add(permission.getSessionPermission());
            }
         }
         runtime.markMapperInvoked();
         if(enforced(instance))
         {
            permissions.addAll(access.permissions());
         }
         else if(config.getHostPermissionSource() != null)
         {
            permissions.addAll(config.getHostPermissionSource().userPermissions(access.email() == null ? "" : access.email(), access.groups()));
         }
         session.setPermissions(permissions);
         AuthentikTokenScopes.apply(instance, session, claims);
      }
      catch(Exception failure)
      {
         session.setPermissions(new TreeSet<>());
         throw (new QAuthenticationException("Current Authentik session access could not be established."));
      }
      finally
      {
         QContext.init(previous);
      }
   }

   /***************************************************************************
    ** Shared immutable-identity SQL reader; an unavailable baseline fails closed.
    ***************************************************************************/
   protected AuthentikMirrorAccess.Result readCurrent(AuthentikSessionIdentity identity) throws Exception
   {
      return (new AuthentikMirrorAccess(runtime().getConfig(), Duration.ofMinutes(15)).read(identity.pk(), identity.uuid()));
   }

   /***************************************************************************
    ** Preserve the existing policy cut-over guard and host-permission floor.
    ***************************************************************************/
   protected boolean enforced(QInstance instance)
   {
      return (AccessComparison.state(runtime(), client(instance)).enforced());
   }

   /***************************************************************************
    ** Resolve only the configured API backend of this mapper.
    ***************************************************************************/
   AuthentikRuntime runtime()
   {
      return (AuthentikRuntime.forBackend(getApiBackendName()));
   }
}
