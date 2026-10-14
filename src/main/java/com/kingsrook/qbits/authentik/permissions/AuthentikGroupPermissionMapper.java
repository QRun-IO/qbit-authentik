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

package com.kingsrook.qbits.authentik.permissions;


import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikRedactor;
import com.kingsrook.qbits.authentik.policy.PolicyCatalog;
import com.kingsrook.qbits.authentik.policy.PolicyFormat;
import com.kingsrook.qbits.authentik.policy.PolicyPermissions;
import com.kingsrook.qbits.authentik.security.BootstrapOperators;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.customizers.QCodeLoader;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.modules.authentication.QAuthenticationModuleCustomizerInterface;
import com.kingsrook.qqq.backend.module.api.actions.BaseAPIActionUtil;
import com.kingsrook.qqq.backend.module.api.model.metadata.APIBackendMetaData;
import org.json.JSONArray;
import org.json.JSONObject;
import static com.kingsrook.qqq.backend.core.logging.LogUtils.logPair;


/*******************************************************************************
 ** Sign-in permissions from Authentik groups (DESIGN.md section 5.6). Use as
 ** (or extend in) the host's OAuth2 authentication customizer.
 **
 ** 1. Group names come from the token's "groups" claim (a typical profile
 **    mapping emits direct groups only).
 ** 2. Each group is resolved with its ancestors through the cached group
 **    graph; the union of qqq.io/permissions becomes session permissions,
 **    expanded and checked against the instance's permission catalog.
 ** 3. Static fallbacks (withGroupPermissions) and bootstrapOperatorSubjects are added.
 ** 4. If Authentik cannot be read, only the static fallbacks (and bootstrap
 **    operators) apply: it never grants everything.
 **
 ** The host keeps its own user/full-name handling; this only adds permissions.
 ** QQQ instantiates customizers with no arguments, so the API backend is found
 ** by name (default "authentikApi"; override getApiBackendName for a prefix).
 *******************************************************************************/
public class AuthentikGroupPermissionMapper implements QAuthenticationModuleCustomizerInterface
{
   private static final QLogger LOG = QLogger.getLogger(AuthentikGroupPermissionMapper.class);

   public static final String CLAIMS_CONTEXT_KEY = "jwtPayloadJsonObject";

   private final Map<String, List<String>> staticGroupPermissions = new LinkedHashMap<>();



   /*******************************************************************************
    ** The qbit's API backend name (default: the unprefixed-namespace default).
    *******************************************************************************/
   protected String getApiBackendName()
   {
      return ("authentikApi");
   }



   /*******************************************************************************
    ** Static fallback: always grant these permissions to members of a group
    ** (useful in tests and dev, and as the floor when Authentik is down).
    *******************************************************************************/
   public AuthentikGroupPermissionMapper withGroupPermissions(String groupName, List<String> permissions)
   {
      staticGroupPermissions.put(groupName, new ArrayList<>(permissions));
      return (this);
   }



   /*******************************************************************************
    ** Add permissions from the session's token claims.
    *******************************************************************************/
   @Override
   public void customizeSession(QInstance qInstance, QSession qSession, Map<String, Object> context)
   {
      JSONObject claims = context == null ? null : asClaims(context.get(CLAIMS_CONTEXT_KEY));
      if(claims == null)
      {
         return;
      }
      List<String> groups = groupNames(claims);
      String       email  = claims.optString("email", "").trim();
      String       sub    = claims.optString("sub", "").trim();
      boolean      verified = claims.optBoolean("email_verified", false);

      Set<String> permissions = new TreeSet<>(resolve(qInstance, groups, sub, email, verified));

      //////////////////////////////////////////////////////////////////////////
      // the policy claim (docs/POLICY-FORMAT.md) carries the same group data //
      // as the graph read above; the union also covers an unreachable API    //
      //////////////////////////////////////////////////////////////////////////
      AuthentikRuntime runtime = runtime();
      PolicyFormat     format  = runtime == null ? PolicyFormat.DEFAULT : runtime.getConfig().getPolicyFormat();
      permissions.addAll(PolicyPermissions.fromClaims(PolicyPermissions.claimsWithPolicy(context, format), format,
         qInstance == null ? (runtime == null ? null : runtime.getPolicyCatalog()) : PolicyCatalog.of(qInstance)));

      if(runtime != null)
      {
         permissions.addAll(AccessComparison.staticPermissions(runtime.getConfig(), groups));

         ////////////////////////////////////////////////////////////////////////
         // the cut-over guard (DESIGN.md section 12.8): while it blocks, the   //
         // session gets today's access from the host plus the floor (static   //
         // fallbacks, bootstrap subjects), never the policies alone           //
         ////////////////////////////////////////////////////////////////////////
         runtime.markMapperInvoked();
         AccessComparison.State state;
         try
         {
            state = AccessComparison.state(runtime, client(qInstance));
         }
         catch(Exception e)
         {
            state = new AccessComparison.State(AccessComparison.Status.BLOCKED, "The cut-over guard could not run", java.time.Instant.now());
         }
         if(!state.enforced())
         {
            Set<String> floor = new TreeSet<>(AccessComparison.staticPermissions(runtime.getConfig(), groups));
            for(String group : groups)
            {
               floor.addAll(staticGroupPermissions.getOrDefault(group, List.of()));
            }
            if(!runtime.getConfig().getResolvedBootstrapSubjects().isEmpty() && isBootstrap(qInstance, runtime, sub, email, verified))
            {
               for(IdentityPermission permission : IdentityPermission.values())
               {
                  floor.add(permission.getSessionPermission());
               }
            }
            AuthentikHostPermissionSource source = runtime.getConfig().getHostPermissionSource();
            if(source != null)
            {
               floor.addAll(source.userPermissions(email, groups));
            }
            LOG.warn("Policies are not enforced at this sign-in; granting today's access", logPair("reason", state.message()));
            permissions = floor;
         }
      }
      if(qSession.getPermissions() != null)
      {
         permissions.addAll(qSession.getPermissions());
      }
      qSession.setPermissions(permissions);
      com.kingsrook.qbits.authentik.security.AuthentikTokenScopes.apply(qInstance, qSession, claims);
   }



   /*******************************************************************************
    ** Automated sessions have no claims. Resolve their email idReference to one
    ** active API user before trusting any groups or immutable bootstrap id.
    *******************************************************************************/
   @Override
   public void customizeAutomatedSessionForUser(QInstance qInstance, QSession session, Serializable userId)
   {
      AuthentikRuntime runtime = runtime();
      Set<String> permissions = new TreeSet<>();
      String email = userId == null ? "" : userId.toString().trim();
      try
      {
         JSONObject found = null;
         int matches = 0;
         List<JSONObject> users = email.isEmpty() ? List.of() : client(qInstance).getAllPages(
            "/core/users/?email=" + URLEncoder.encode(email, StandardCharsets.UTF_8) + "&include_groups=true&include_roles=false", 10);
         for(JSONObject user : users)
         {
            if(email.equalsIgnoreCase(user.optString("email", "").trim()))
            {
               found = user;
               matches++;
            }
         }
         // A bounded, possibly truncated lookup cannot prove uniqueness.
         if(users.size() < 10 && matches == 1 && found.optBoolean("is_active", false))
         {
            List<String> groups = new ArrayList<>();
            JSONArray groupObjects = found.optJSONArray("groups_obj");
            if(groupObjects != null)
            {
               for(int i = 0; i < groupObjects.length(); i++)
               {
                  groups.add(groupObjects.getJSONObject(i).getString("name"));
               }
            }
            else if(found.opt("groups") instanceof JSONArray groupPks && !groupPks.isEmpty())
            {
               GroupGraph graph = client(qInstance).groupGraph();
               for(int i = 0; i < groupPks.length(); i++)
               {
                  GroupGraph.Node group = graph.byPk(groupPks.getString(i));
                  if(group != null)
                  {
                     groups.add(group.name());
                  }
               }
            }
            String pk = found.optString("pk", "");
            String sub = runtime != null && runtime.getConfig().getResolvedBootstrapSubjects().contains(pk) ? pk : found.optString("uuid", pk);
            String userEmail = found.getString("email").trim();
            boolean verified = found.optBoolean("email_verified", false);
            permissions.addAll(resolve(qInstance, groups, sub, userEmail, verified));
            if(runtime != null)
            {
               permissions.addAll(AccessComparison.staticPermissions(runtime.getConfig(), groups));
               permissions = automatedSessionPermissions(qInstance, runtime, permissions, groups, sub, userEmail, verified);
            }
         }
         else
         {
            LOG.info("Automated session has no unique active Authentik user; granting only the static fallbacks");
         }
      }
      catch(Exception e)
      {
         permissions.clear();
         // Exception messages can contain the lookup email; log only the type.
         LOG.warn("Authentik could not be read for an automated session; granting only the static fallbacks", logPair("errorType", e.getClass().getSimpleName()));
      }
      if(runtime != null)
      {
         permissions.addAll(AccessComparison.staticPermissions(runtime.getConfig(), List.of()));
      }
      if(session.getPermissions() != null)
      {
         permissions.addAll(session.getPermissions());
      }
      session.setPermissions(permissions);
   }



   /*******************************************************************************
    ** Mirror the sign-in cut-over floor without changing the claims path.
    *******************************************************************************/
   private Set<String> automatedSessionPermissions(QInstance qInstance, AuthentikRuntime runtime, Set<String> permissions,
      List<String> groups, String sub, String email, boolean verified)
   {
      runtime.markMapperInvoked();
      AccessComparison.State state;
      try
      {
         state = AccessComparison.state(runtime, client(qInstance));
      }
      catch(Exception e)
      {
         state = new AccessComparison.State(AccessComparison.Status.BLOCKED, "The cut-over guard could not run", java.time.Instant.now());
      }
      if(state.enforced())
      {
         return (permissions);
      }
      Set<String> floor = new TreeSet<>(AccessComparison.staticPermissions(runtime.getConfig(), groups));
      for(String group : groups)
      {
         floor.addAll(staticGroupPermissions.getOrDefault(group, List.of()));
      }
      if(!runtime.getConfig().getResolvedBootstrapSubjects().isEmpty() && isBootstrap(qInstance, runtime, sub, email, verified))
      {
         for(IdentityPermission permission : IdentityPermission.values())
         {
            floor.add(permission.getSessionPermission());
         }
      }
      AuthentikHostPermissionSource source = runtime.getConfig().getHostPermissionSource();
      if(source != null)
      {
         floor.addAll(source.userPermissions(email, groups));
      }
      LOG.warn("Policies are not enforced for this automated session; granting today's access", logPair("status", state.status()));
      return (floor);
   }



   /*******************************************************************************
    ** The permissions for a user's group names and token identity (sub, email,
    ** email_verified). Bootstrap operators are matched on immutable ids only.
    *******************************************************************************/
   public Set<String> resolve(QInstance qInstance, Collection<String> groupNames, String sub, String email, boolean emailVerified)
   {
      Set<String> rs = new TreeSet<>();
      for(String group : groupNames)
      {
         rs.addAll(staticGroupPermissions.getOrDefault(group, List.of()));
      }

      AuthentikRuntime runtime = runtime();
      if(runtime != null && !runtime.getConfig().getResolvedBootstrapSubjects().isEmpty() && isBootstrap(qInstance, runtime, sub, email, emailVerified))
      {
         LOG.warn("bootstrapOperatorSubjects grants all identity permissions; empty it once an identity administrator is set up in Authentik", logPair("sub", sub));
         for(IdentityPermission permission : IdentityPermission.values())
         {
            rs.add(permission.getSessionPermission());
         }
      }

      try
      {
         AuthentikActionUtil         client   = client(qInstance);
         GroupGraph                  graph    = client.groupGraph();
         EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph, runtime == null ? null : runtime.getPermissionCatalog(), qInstance);
         List<String>                pks      = new ArrayList<>();
         for(String name : groupNames)
         {
            GroupGraph.Node node = graph.byName(name);
            if(node != null)
            {
               pks.add(node.pk());
            }
         }
         EffectivePermissionResolver.Resolution resolution = resolver.resolveGroups(pks);
         if(!resolution.unknown().isEmpty())
         {
            LOG.info("Group attributes name permissions this app does not have", logPair("unknown", resolution.unknown()));
         }
         rs.addAll(resolution.sessionPermissions());
      }
      catch(Exception e)
      {
         LOG.warn("Authentik groups could not be read at sign-in; granting only the static fallbacks", logPair("error", AuthentikRedactor.redactText(e.getMessage(), runtime == null ? null : runtime.getConfig().getResolvedApiToken())));
      }
      return (rs);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private boolean isBootstrap(QInstance qInstance, AuthentikRuntime runtime, String sub, String email, boolean emailVerified)
   {
      try
      {
         return (BootstrapOperators.matches(runtime.getConfig().getResolvedBootstrapSubjects(), client(qInstance), sub, email, emailVerified));
      }
      catch(Exception e)
      {
         return (false);
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AuthentikRuntime runtime()
   {
      try
      {
         return (AuthentikRuntime.forBackend(getApiBackendName()));
      }
      catch(IllegalStateException e)
      {
         return (null);
      }
   }



   /*******************************************************************************
    ** A client bound to the qbit backend of the given instance.
    *******************************************************************************/
   protected AuthentikActionUtil client(QInstance qInstance)
   {
      if(qInstance == null || !(qInstance.getBackend(getApiBackendName()) instanceof APIBackendMetaData backend))
      {
         throw (new IllegalStateException("No Authentik API backend named " + getApiBackendName()));
      }
      BaseAPIActionUtil util = QCodeLoader.getAdHoc(BaseAPIActionUtil.class, backend.getActionUtil());
      util.setBackendMetaData(backend);
      return ((AuthentikActionUtil) util);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static JSONObject asClaims(Object value)
   {
      if(value instanceof JSONObject object)
      {
         return (object);
      }
      if(value instanceof Map<?, ?> map)
      {
         return (new JSONObject(map));
      }
      return (null);
   }



   /*******************************************************************************
    ** Group names from the "groups" claim (array, or a single string).
    *******************************************************************************/
   static List<String> groupNames(JSONObject claims)
   {
      List<String> rs     = new ArrayList<>();
      Object       groups = claims.opt("groups");
      if(groups instanceof JSONArray array)
      {
         for(int i = 0; i < array.length(); i++)
         {
            String name = array.optString(i, "").trim();
            if(!name.isEmpty())
            {
               rs.add(name);
            }
         }
      }
      else if(groups instanceof String name && !name.isBlank())
      {
         rs.add(name.trim());
      }
      return (rs);
   }

}
