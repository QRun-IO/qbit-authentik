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


import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.admin.AdminRequest;
import com.kingsrook.qbits.authentik.admin.TokenScopeStore;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.policy.PolicyCatalog;
import com.kingsrook.qqq.backend.core.actions.customizers.QCodeLoader;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.MetaDataWithPermissionRules;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.module.api.actions.BaseAPIActionUtil;
import com.kingsrook.qqq.backend.module.api.model.metadata.APIBackendMetaData;
import org.json.JSONObject;


/*******************************************************************************
 ** Signed token claims can only narrow the permissions computed by a host.
 *******************************************************************************/
public final class AuthentikTokenScopes
{
   private static final QLogger LOG = QLogger.getLogger(AuthentikTokenScopes.class);

   /*******************************************************************************
    ** Distinguish unrestricted credentials from revoked credentials.
    *******************************************************************************/
   public enum Mode
   {
      SCOPED,
      UNSCOPED,
      DENY_ALL
   }



   /*******************************************************************************
    ** Immutable, non-secret credential restrictions, including advanced scopes.
    *******************************************************************************/
   public record TokenScope(String identifier, Mode mode, boolean readOnly, Set<String> apps, Set<String> tables,
      Set<String> processes, Set<String> reports, Set<String> widgets, Set<String> operationIds)
   {
      /*******************************************************************************
       ** A missing row is unrestricted; a missing token is denied.
       *******************************************************************************/
      public static TokenScope marker(String identifier, Mode mode)
      {
         return (new TokenScope(identifier, mode, false, Set.of(), Set.of(), Set.of(), Set.of(), Set.of(), Set.of()));
      }

      /*******************************************************************************
       ** Decode a local metadata row without retaining the mutable record.
       *******************************************************************************/
      public static TokenScope from(String identifier, QRecord row)
      {
         return (new TokenScope(identifier, Mode.SCOPED, Boolean.TRUE.equals(row.getValueBoolean("readOnly")),
            names(row.getValueString("apps")), names(row.getValueString("tables")), names(row.getValueString("processes")),
            names(row.getValueString("reports")), names(row.getValueString("widgets")), names(row.getValueString("operationIds"))));
      }
   }



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikTokenScopes()
   {
   }



   /*******************************************************************************
    ** One name per line; immutable sets keep cached scopes safe to share.
    *******************************************************************************/
   public static Set<String> names(String value)
   {
      if(value == null || value.isBlank())
      {
         return (Set.of());
      }
      return (Set.copyOf(Arrays.stream(value.split("\\R")).map(String::trim).filter(s -> !s.isEmpty()).toList()));
   }



   /*******************************************************************************
    ** Resolve only qbit backends present in this instance. Cache by identifier
    ** within each runtime, so tenants never share a scope or token existence.
    *******************************************************************************/
   public static Optional<TokenScope> forClaims(QInstance instance, JSONObject claims) throws QException
   {
      if(claims == null)
      {
         return (Optional.empty());
      }
      if(instance != null)
      {
         for(var backend : instance.getBackends().values())
         {
            AuthentikRuntime runtime;
            try
            {
               runtime = AuthentikRuntime.forBackend(backend.getName());
            }
            catch(IllegalStateException ignored)
            {
               continue;
            }
            String claim = runtime.getConfig().getTokenScopeClaim();
            if(!claims.has(claim))
            {
               continue;
            }
            Object value = claims.opt(claim);
            if(!(value instanceof String identifier) || !identifier.matches("[A-Za-z0-9._-]+"))
            {
               return (Optional.of(TokenScope.marker("invalid", Mode.DENY_ALL)));
            }
            return (runtime.getTokenScopeCache().getResultThrowing(identifier, id ->
            {
               APIBackendMetaData api = (APIBackendMetaData) backend;
               AuthentikActionUtil util = (AuthentikActionUtil) QCodeLoader.getAdHoc(BaseAPIActionUtil.class, api.getActionUtil());
               util.setBackendMetaData(api);
               // Check existence even when a local row remains after an external revoke.
               // Do not let a longer general response TTL extend the 60-second
               // revocation window of this dedicated cache.
               runtime.getResponseCache().clearKey(runtime.getConfig().getApiRoot() + "/core/tokens/" + id + "/");
               if(util.getApiJsonOrNull("/core/tokens/" + id + "/") == null)
               {
                  return (TokenScope.marker(id, Mode.DENY_ALL));
               }
               if(instance.getTable(runtime.getConfig().applyTablePrefix("token_scope")) == null)
               {
                  throw (new QException("Token scope metadata is unavailable."));
               }
               QRecord row = new TokenScopeStore(runtime.getConfig()).find(id);
               return (row == null ? TokenScope.marker(id, Mode.UNSCOPED) : TokenScope.from(id, row));
            }));
         }
      }
      // A default token claim must never silently lose enforcement if the qbit is missing.
      return (claims.has("qqq_token") ? Optional.of(TokenScope.marker(claims.optString("qqq_token"), Mode.DENY_ALL)) : Optional.empty());
   }



   /*******************************************************************************
    ** Hosts with their own customizer call this AFTER computing permissions.
    *******************************************************************************/
   public static void apply(QSession session, JSONObject claims)
   {
      apply(QContext.getQInstance(), session, claims);
   }



   /*******************************************************************************
    ** Explicit instance variant for authentication, before QContext is installed.
    *******************************************************************************/
   public static void apply(QInstance instance, QSession session, JSONObject claims)
   {
      try
      {
         forClaims(instance, claims).ifPresent(scope -> narrow(instance, session, scope));
      }
      catch(Exception e)
      {
         session.setPermissions(new TreeSet<>());
         LOG.warn("Token scope could not be verified; denying credential permissions.");
      }
   }



   /*******************************************************************************
    ** STAND-IN(core=QRun-IO/qqq#1153, removeBy=4.1.0-RC.7): intersect, never grant.
    *******************************************************************************/
   public static void narrow(QSession session, TokenScope scope)
   {
      narrow(QContext.getQInstance(), session, scope);
   }



   /*******************************************************************************
    ** Keep only permitted bases and read operations, then attach core's scope
    ** when available. Management hasAccess permissions are not read operations.
    *******************************************************************************/
   private static void narrow(QInstance instance, QSession session, TokenScope scope)
   {
      Set<String> permissions = new TreeSet<>(session.getPermissions() == null ? Set.of() : session.getPermissions());
      if(scope.mode() == Mode.DENY_ALL)
      {
         permissions.clear();
      }
      else if(scope.mode() == Mode.SCOPED)
      {
         if(scope.readOnly())
         {
            permissions.removeIf(p -> p.startsWith("authentik.") || !(p.endsWith(".read") || p.endsWith(".hasAccess")));
         }
         if(!scope.apps().isEmpty() || !scope.tables().isEmpty() || !scope.processes().isEmpty() || !scope.reports().isEmpty() || !scope.widgets().isEmpty())
         {
            Set<String> bases = new LinkedHashSet<>();
            if(instance != null)
            {
               for(String name : scope.tables())
               {
                  if(instance.getTable(name) != null)
                  {
                     bases.add(base(instance, instance.getTable(name), name));
                  }
               }
               // Policy-format names exclude dots; host permission aliases need
               // direct metadata traversal as well as the policy catalog.
               for(String appName : scope.apps())
               {
                  var app = instance.getApp(appName);
                  if(app == null)
                  {
                     continue;
                  }
                  bases.add(base(instance, app, appName));
                  Set<String> appTables = new LinkedHashSet<>();
                  if(app.getChildren() != null)
                  {
                     for(var child : app.getChildren())
                     {
                        if(child instanceof MetaDataWithPermissionRules secured)
                        {
                           bases.add(base(instance, secured, child.getName()));
                        }
                        if(instance.getTable(child.getName()) != null)
                        {
                           appTables.add(child.getName());
                        }
                     }
                  }
                  for(var process : instance.getProcesses().values())
                  {
                     if(process.getTableName() != null && appTables.contains(process.getTableName()))
                     {
                        bases.add(base(instance, process, process.getName()));
                     }
                  }
                  if(app.getWidgets() != null)
                  {
                     for(String name : app.getWidgets())
                     {
                        if(instance.getWidget(name) != null)
                        {
                           bases.add(base(instance, instance.getWidget(name), name));
                        }
                     }
                  }
               }
               for(PolicyCatalog.Group group : PolicyCatalog.of(instance).getGroups())
               {
                  for(PolicyCatalog.Resource resource : group.resources())
                  {
                     if((group.app() != null && scope.apps().contains(group.app())) || scope.processes().contains(resource.name())
                        || scope.reports().contains(resource.name()) || scope.widgets().contains(resource.name()))
                     {
                        bases.add(resource.name());
                     }
                  }
               }
            }
            permissions.removeIf(p -> p.lastIndexOf('.') < 0 || !bases.contains(p.substring(0, p.lastIndexOf('.'))));
         }
      }
      session.setPermissions(permissions);
      session.setValue("qqq.credentialScope", scope.identifier());
      attachCoreScope(session, scope);
   }



   /*******************************************************************************
    ** Use the permission base, which may differ from a table's metadata name.
    *******************************************************************************/
   private static String base(QInstance instance, MetaDataWithPermissionRules object, String name)
   {
      String base = PermissionsHelper.getEffectivePermissionRules(object, instance).getPermissionBaseName();
      return (base == null || base.isBlank() ? name : base);
   }



   /*******************************************************************************
    ** Validate against current operator permissions at Review and execution.
    *******************************************************************************/
   public static void validate(AdminRequest request) throws QUserFacingException
   {
      QInstance instance = QContext.getQInstance();
      for(String field : List.of("apps", "tables"))
      {
         for(String name : names(request.str(field)))
         {
            MetaDataWithPermissionRules object = field.equals("apps") ? instance.getApp(name) : instance.getTable(name);
            if(object == null)
            {
               throw (new QUserFacingException("Unknown " + field + " scope: " + name));
            }
            String base = base(instance, object, name);
            QSession session = QContext.getQSession();
            if(!session.hasPermission(base + ".hasAccess") && !session.hasPermission(base + ".read"))
            {
               throw (new QUserFacingException("You do not currently have read access to scope: " + name));
            }
         }
      }
      for(String advanced : List.of("processes", "reports", "widgets", "operationIds"))
      {
         if(!request.str(advanced).isBlank())
         {
            throw (new QUserFacingException("Advanced token scopes are not offered by Create Token."));
         }
      }
   }



   /*******************************************************************************
    ** Optional core bridge. An incompatible installed contract fails closed;
    ** an absent class uses the permission intersection above.
    *******************************************************************************/
   /*******************************************************************************
    ** An empty scope dimension means "not restricted" (null for core).
    *******************************************************************************/
   private static Set<String> nullIfEmpty(Set<String> set)
   {
      return (set == null || set.isEmpty() ? null : set);
   }



   /*******************************************************************************
    ** STAND-IN(core=QRun-IO/qqq#1168, removeBy=4.1.0-RC.7): until the qbit's QQQ
    ** version has QCredentialScope (qqq#1153), narrow() above enforces the scope
    ** by intersecting the session's permissions; this attaches the core scope by
    ** reflection when it exists. Replace both with a direct withCredentialScope.
    *******************************************************************************/
   private static void attachCoreScope(QSession session, TokenScope scope)
   {
      try
      {
         Class<?> type = Class.forName("com.kingsrook.qqq.backend.core.model.session.QCredentialScope");
         Object value = type.getConstructor().newInstance();
         ///////////////////////////////////////////////////////////////////////
         // core treats a null set as unrestricted and an empty set as        //
         // "nothing": an unlisted dimension must therefore be passed as null //
         ///////////////////////////////////////////////////////////////////////
         Map<String, Object> fields = new java.util.LinkedHashMap<>();
         fields.put("CredentialId", scope.identifier());
         fields.put("ReadOnly", scope.readOnly());
         fields.put("Apps", nullIfEmpty(scope.apps()));
         fields.put("Tables", nullIfEmpty(scope.tables()));
         fields.put("Processes", nullIfEmpty(scope.processes()));
         fields.put("Reports", nullIfEmpty(scope.reports()));
         fields.put("Widgets", nullIfEmpty(scope.widgets()));
         fields.put("OperationIds", nullIfEmpty(scope.operationIds()));
         for(var field : fields.entrySet())
         {
            Method setter = Arrays.stream(type.getMethods()).filter(m -> m.getName().equals("with" + field.getKey()) && m.getParameterCount() == 1)
               .findFirst().orElseThrow(NoSuchMethodException::new);
            Object arg = field.getValue();
            if(arg instanceof Set<?> set && List.class.isAssignableFrom(setter.getParameterTypes()[0]))
            {
               arg = List.copyOf(set);
            }
            setter.invoke(value, arg);
         }
         session.getClass().getMethod("withCredentialScope", type).invoke(session, value);
      }
      catch(ClassNotFoundException ignored)
      {
         // RC.2 has no credential scope; the stand-in above is active.
      }
      catch(ReflectiveOperationException | IllegalArgumentException e)
      {
         session.setPermissions(new TreeSet<>());
         LOG.warn("The installed credential-scope contract is incompatible; denying credential permissions.");
      }
   }
}
