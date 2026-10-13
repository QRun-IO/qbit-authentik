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

package com.kingsrook.qbits.authentik;


import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import com.kingsrook.qbits.authentik.client.AuthentikFilterMapper;
import com.kingsrook.qbits.authentik.client.AuthentikTableSpec;
import com.kingsrook.qbits.authentik.client.TokenBucketThrottle;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.policy.PolicyCatalog;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qqq.backend.core.utils.memoization.Memoization;


/*******************************************************************************
 ** Live state of one qbit instance: config, throttle, guard, filter mapper,
 ** response cache, and the table-name to spec map. Registered by API backend
 ** name, because AuthentikActionUtil is instantiated by QQQ (QCodeLoader) with
 ** no constructor arguments and finds its runtime from the backend it serves.
 *******************************************************************************/
public class AuthentikRuntime
{
   private static final Map<String, AuthentikRuntime> BY_BACKEND = new ConcurrentHashMap<>();

   private final AuthentikQBitConfig             config;
   private final TokenBucketThrottle             throttle;
   private final AuthentikGuard                  guard;
   private final AuthentikFilterMapper           filterMapper = new AuthentikFilterMapper();
   private final Memoization<String, String>     responseCache;
   private final Memoization<String, GroupGraph> groupGraphCache;
   private volatile java.util.Set<String>        permissionCatalog;
   private volatile PolicyCatalog                policyCatalog;
   private final Map<String, AuthentikTableSpec> specsByTableName = new ConcurrentHashMap<>();



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   public AuthentikRuntime(AuthentikQBitConfig config)
   {
      this.config = config;
      this.throttle = new TokenBucketThrottle(config.getThrottleRequestsPerSecond(), config.getThrottleBurst());
      this.guard = new AuthentikGuard(config);
      this.responseCache = new Memoization<String, String>(Duration.ofSeconds(config.getListCacheTtlSeconds())).withMaxSize(500);
      this.groupGraphCache = new Memoization<String, GroupGraph>(Duration.ofSeconds(config.getGroupCacheTtlSeconds())).withMaxSize(1);
   }



   /*******************************************************************************
    ** Register a runtime for its config's API backend (replacing any previous).
    *******************************************************************************/
   public static AuthentikRuntime register(AuthentikRuntime runtime)
   {
      BY_BACKEND.put(runtime.config.getApiBackendName(), runtime);
      return (runtime);
   }



   /*******************************************************************************
    ** Find the runtime for an API backend name.
    *******************************************************************************/
   public static AuthentikRuntime forBackend(String backendName)
   {
      AuthentikRuntime runtime = BY_BACKEND.get(backendName);
      if(runtime == null)
      {
         throw (new IllegalStateException("No Authentik qbit runtime is registered for backend " + backendName + " (was the qbit produced?)"));
      }
      return (runtime);
   }



   /*******************************************************************************
    ** Associate a produced (prefixed) table name with its spec.
    *******************************************************************************/
   public void registerTable(String tableName, AuthentikTableSpec spec)
   {
      specsByTableName.put(tableName, spec);
   }



   /*******************************************************************************
    ** The spec for a produced table name, or null.
    *******************************************************************************/
   public AuthentikTableSpec getSpec(String tableName)
   {
      return (specsByTableName.get(tableName));
   }



   /*******************************************************************************
    ** Whether responses should be cached at all.
    *******************************************************************************/
   public boolean isCacheEnabled()
   {
      return (config.getListCacheTtlSeconds() != null && config.getListCacheTtlSeconds() > 0);
   }



   /*******************************************************************************
    ** Drop every cached response (after writes, or when a webhook arrives).
    *******************************************************************************/
   public void invalidateCache()
   {
      responseCache.clear();
      groupGraphCache.clear();
   }



   /*******************************************************************************
    ** Cache for the group graph (groupCacheTtlSeconds; 0 disables).
    *******************************************************************************/
   public Memoization<String, GroupGraph> getGroupGraphCache()
   {
      return (groupGraphCache);
   }



   /*******************************************************************************
    ** QQQ permission names that qqq.io/permissions may grant: every permission
    ** the instance's metadata defines (PermissionsHelper), computed once.
    *******************************************************************************/
   public java.util.Set<String> getPermissionCatalog()
   {
      if(permissionCatalog == null)
      {
         com.kingsrook.qqq.backend.core.model.metadata.QInstance qInstance = com.kingsrook.qqq.backend.core.context.QContext.getQInstance();
         if(qInstance == null)
         {
            return (java.util.Set.of());
         }
         java.util.Set<String> catalog = new java.util.TreeSet<>(com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper.getAllAvailablePermissionNames(qInstance));
         catalog.addAll(getPolicyCatalog().permissionNames());
         permissionCatalog = catalog;
      }
      return (permissionCatalog);
   }



   /*******************************************************************************
    ** What a policy can grant in the current instance (built once, lazily: the
    ** instance is complete by the first request).
    *******************************************************************************/
   public PolicyCatalog getPolicyCatalog()
   {
      if(policyCatalog == null)
      {
         com.kingsrook.qqq.backend.core.model.metadata.QInstance qInstance = com.kingsrook.qqq.backend.core.context.QContext.getQInstance();
         if(qInstance == null)
         {
            return (PolicyCatalog.of(new com.kingsrook.qqq.backend.core.model.metadata.QInstance()));
         }
         policyCatalog = PolicyCatalog.of(qInstance);
      }
      return (policyCatalog);
   }



   /*******************************************************************************
    ** Getter for config
    *******************************************************************************/
   public AuthentikQBitConfig getConfig()
   {
      return (config);
   }



   /*******************************************************************************
    ** Getter for throttle
    *******************************************************************************/
   public TokenBucketThrottle getThrottle()
   {
      return (throttle);
   }



   /*******************************************************************************
    ** Getter for guard
    *******************************************************************************/
   public AuthentikGuard getGuard()
   {
      return (guard);
   }



   /*******************************************************************************
    ** Getter for filterMapper
    *******************************************************************************/
   public AuthentikFilterMapper getFilterMapper()
   {
      return (filterMapper);
   }



   /*******************************************************************************
    ** Getter for responseCache (session-independent: the API always runs as
    ** the service account; permission filtering happens after the cache).
    *******************************************************************************/
   public Memoization<String, String> getResponseCache()
   {
      return (responseCache);
   }

}
