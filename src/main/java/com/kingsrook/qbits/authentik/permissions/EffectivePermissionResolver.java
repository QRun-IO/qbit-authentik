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


import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.security.IdentityPermission;


/*******************************************************************************
 ** Turns groups (and their ancestors) into QQQ permissions (DESIGN.md
 ** section 5.6). Pure: give it a GroupGraph and a permission catalog.
 **
 ** Rules:
 ** - A group confers the union of qqq.io/permissions on itself and every
 **   ancestor ("inherited parents").
 ** - "authentik.*" expands to every identity permission; an identity short
 **   name ("authentik.users.read") becomes its session form
 **   ("authentik.users.read.hasAccess").
 ** - Any other name ending in ".*" expands against the catalog (prefix match);
 **   with no catalog it is dropped, never granted as a literal wildcard.
 ** - Names not in the catalog are reported as unknown and NOT granted (when a
 **   catalog is given); with no catalog they pass through unchanged.
 *******************************************************************************/
public class EffectivePermissionResolver
{
   private final GroupGraph  graph;
   private final Set<String> catalog;



   /*******************************************************************************
    ** Result for a set of groups.
    *******************************************************************************/
   public record Resolution(Set<String> sessionPermissions, Map<String, Set<String>> grantedBy, Set<String> unknown, Set<String> appAccess)
   {
   }



   /*******************************************************************************
    ** Constructor.
    **
    ** @param graph   the group hierarchy
    ** @param catalog QQQ permission names that may be granted (session form,
    **                e.g. from PermissionsHelper.getAllAvailablePermissionNames);
    **                null to pass non-identity names through unchecked
    *******************************************************************************/
   public EffectivePermissionResolver(GroupGraph graph, Collection<String> catalog)
   {
      this.graph = graph;
      this.catalog = catalog == null ? null : new TreeSet<>(catalog);
      if(this.catalog != null)
      {
         for(IdentityPermission permission : IdentityPermission.values())
         {
            this.catalog.add(permission.getSessionPermission());
         }
      }
   }



   /*******************************************************************************
    ** Effective permissions of a set of groups (e.g. a user's direct groups).
    *******************************************************************************/
   public Resolution resolveGroups(Collection<String> groupPks)
   {
      Set<String>              permissions = new TreeSet<>();
      Map<String, Set<String>> grantedBy   = new LinkedHashMap<>();
      Set<String>              unknown     = new TreeSet<>();
      Set<String>              appAccess   = new TreeSet<>();

      Set<String> visited = new LinkedHashSet<>();
      for(String pk : groupPks)
      {
         for(GroupGraph.Node node : graph.selfAndAncestors(pk))
         {
            if(!visited.add(node.pk()))
            {
               continue;
            }
            appAccess.addAll(node.appAccess());
            List<String> raws = new ArrayList<>(node.permissions());
            raws.addAll(node.policyPermissions());
            for(String raw : raws)
            {
               Set<String> expanded = expand(raw);
               if(expanded.isEmpty())
               {
                  unknown.add(raw);
               }
               for(String permission : expanded)
               {
                  permissions.add(permission);
                  grantedBy.computeIfAbsent(permission, k -> new TreeSet<>()).add(node.name());
               }
            }
         }
      }
      return (new Resolution(permissions, grantedBy, unknown, appAccess));
   }



   /*******************************************************************************
    ** Effective permissions of a user from the graph's memberships.
    *******************************************************************************/
   public Resolution resolveUser(int userPk)
   {
      return (resolveGroups(graph.groupsOfUser(userPk)));
   }



   /*******************************************************************************
    ** Expand one attribute entry into session permissions (empty when it
    ** grants nothing known).
    *******************************************************************************/
   public Set<String> expand(String raw)
   {
      Set<String> rs = new TreeSet<>();
      if(raw == null || raw.isBlank())
      {
         return (rs);
      }
      String name = raw.trim();

      if(name.equals(IdentityPermission.WILDCARD))
      {
         for(IdentityPermission permission : IdentityPermission.values())
         {
            rs.add(permission.getSessionPermission());
         }
         return (rs);
      }

      if(IdentityPermission.fromName(name).isPresent())
      {
         rs.add(IdentityPermission.fromName(name).get().getSessionPermission());
         return (rs);
      }

      if(name.endsWith(".*"))
      {
         String prefix = name.substring(0, name.length() - 1);
         if(catalog != null)
         {
            catalog.stream().filter(c -> c.startsWith(prefix)).forEach(rs::add);
         }
         return (rs);
      }

      if(catalog == null || catalog.contains(name))
      {
         rs.add(name);
      }
      return (rs);
   }



   /*******************************************************************************
    ** Whether a resolution holds every given identity permission.
    *******************************************************************************/
   public static boolean holdsAll(Resolution resolution, List<IdentityPermission> required)
   {
      return (required.stream().allMatch(p -> resolution.sessionPermissions().contains(p.getSessionPermission())));
   }

}
