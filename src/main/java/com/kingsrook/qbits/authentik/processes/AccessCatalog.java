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

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import com.kingsrook.qbits.authentik.policy.PolicyCatalog;

/*******************************************************************************
 ** Bounded resource pages for direct grants. Bulk edits never imply wildcards.
 *******************************************************************************/
public final class AccessCatalog
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AccessCatalog()
   {
   }

   /*******************************************************************************
    ** Search local QQQ metadata, not the Authentik directory. Return 25 resources
    ** with explicit permission IDs and stable ordering, plus application filters.
    *******************************************************************************/
   public static Map<String, Object> page(Collection<String> permissions, PolicyCatalog catalog, Map<String, String> query)
   {
      Map<String, PolicyCatalog.Resource> resources = new TreeMap<>();
      Map<String, String> apps = new TreeMap<>();
      Map<String, String> appLabels = new TreeMap<>();
      for(var group : catalog.getGroups())
      {
         String app = group.app() == null ? "" : group.app();
         appLabels.put(app, group.label());
         for(var resource : group.resources())
         {
            resources.put(resource.name(), resource);
            apps.put(resource.name(), app);
         }
      }
      Map<String, List<Map<String, String>>> byResource = new TreeMap<>();
      for(String permission : permissions)
      {
         int dot = permission.lastIndexOf('.');
         String base = dot < 0 ? permission : permission.substring(0, dot);
         String action = dot < 0 ? "Grant" : permission.substring(dot + 1);
         byResource.computeIfAbsent(base, ignored -> new ArrayList<>()).add(Map.of("id", permission, "label", action));
      }
      String search = query.getOrDefault("search", "").toLowerCase(Locale.ROOT).strip();
      String appFilter = query.getOrDefault("app", "*");
      String kindFilter = query.getOrDefault("kind", "*");
      List<Map<String, Object>> matches = new ArrayList<>();
      for(var entry : byResource.entrySet())
      {
         var resource = resources.get(entry.getKey());
         String label = resource == null ? entry.getKey() : resource.label();
         String kind = resource == null ? "OTHER" : resource.kind().name();
         String app = apps.getOrDefault(entry.getKey(), "");
         if(!appFilter.equals("*") && !appFilter.equals(app) || !kindFilter.equals("*") && !kindFilter.equals(kind))
         {
            continue;
         }
         if(!(entry.getKey() + " " + label + " " + entry.getValue()).toLowerCase(Locale.ROOT).contains(search))
         {
            continue;
         }
         entry.getValue().sort(java.util.Comparator.comparing(option -> option.get("id")));
         matches.add(Map.of("name", entry.getKey(), "label", label, "kind", kind, "app", app, "permissions", entry.getValue()));
      }
      int requested;
      try
      {
         requested = Math.max(0, Integer.parseInt(query.getOrDefault("page", "0")));
      }
      catch(NumberFormatException e)
      {
         requested = 0;
      }
      int page = Math.min(requested, Math.max(0, (matches.size() - 1) / 25));
      int start = page * 25;
      appLabels.putIfAbsent("", PolicyCatalog.OTHER);
      Map<String, Object> result = new LinkedHashMap<>();
      result.put("rows", matches.subList(start, Math.min(start + 25, matches.size())));
      result.put("total", matches.size());
      result.put("page", page);
      result.put("pageSize", 25);
      result.put("apps", appLabels.entrySet().stream().map(entry -> Map.of("id", entry.getKey(), "label", entry.getValue())).toList());
      return (result);
   }
}
