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


import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.http.NameValuePair;


/*******************************************************************************
 ** Every Authentik operation the qbit uses, with the query parameters it
 ** sends. The schema drift tests check this surface against the pinned
 ** schema (and, in CI, against new Authentik releases). Table operations are
 ** derived from AuthentikTables; others are listed here.
 *******************************************************************************/
public final class AuthentikApiSurface
{

   /*******************************************************************************
    ** One operation: method, schema path template, and parameters used.
    *******************************************************************************/
   public record Operation(String method, String path, Set<String> params)
   {
   }



   /*******************************************************************************
    ** Not instantiable.
    *******************************************************************************/
   private AuthentikApiSurface()
   {
   }



   /*******************************************************************************
    ** Operations outside the table specs.
    *******************************************************************************/
   static List<Operation> extraOperations()
   {
      List<Operation> rs = new ArrayList<>();
      rs.add(new Operation("get", "/admin/version/", Set.of()));
      rs.add(new Operation("post", "/core/tokens/", Set.of()));
      rs.add(new Operation("patch", "/core/tokens/{key}/", Set.of()));
      rs.add(new Operation("delete", "/core/tokens/{key}/", Set.of()));
      rs.add(new Operation("get", "/core/tokens/{key}/view_key/", Set.of()));
      rs.add(new Operation("post", "/core/tokens/{key}/set_key/", Set.of()));
      rs.add(new Operation("post", "/core/users/service_account/", Set.of()));

      ///////////////////////////////////////////////////////////
      // virtual membership table, group graph, drift report  //
      ///////////////////////////////////////////////////////////
      rs.add(new Operation("get", "/core/groups/", Set.of("include_users", "include_parents", "include_children", "name", "ordering", "page", "page_size")));
      rs.add(new Operation("get", "/core/groups/{key}/", Set.of("include_users")));
      rs.add(new Operation("get", "/core/users/", Set.of("username", "include_groups", "attributes", "type", "path_startswith", "groups_by_name", "page", "page_size")));
      rs.add(new Operation("get", "/core/users/{key}/", Set.of()));
      rs.add(new Operation("get", "/managed/blueprints/", Set.of("page", "page_size")));
      rs.add(new Operation("get", "/core/tokens/", Set.of("user__username", "intent", "page", "page_size")));
      rs.add(new Operation("get", "/events/events/", Set.of("username", "ordering", "page", "page_size")));
      return (rs);
   }



   /*******************************************************************************
    ** All operations. Detail paths use "{key}" for the id segment.
    *******************************************************************************/
   public static List<Operation> operations()
   {
      List<Operation> rs = new ArrayList<>();
      for(AuthentikTableSpec spec : AuthentikTables.all().values())
      {
         if(spec.isVirtual())
         {
            continue;
         }
         Set<String> listParams = new LinkedHashSet<>(List.of("page", "page_size", "ordering"));
         for(AuthentikFieldSpec field : spec.getFields())
         {
            listParams.addAll(field.getFilterParams().values());
            if(field.isSearchable())
            {
               listParams.add("search");
            }
         }
         spec.getDefaultListParams().stream().map(NameValuePair::getName).forEach(listParams::add);
         if(AuthentikTables.USER.equals(spec.getName()))
         {
            listParams.addAll(List.of("type", "path_startswith", "groups_by_name"));
         }
         rs.add(new Operation("get", spec.getPath(), listParams));

         Set<String> getParams = new LinkedHashSet<>();
         spec.getDefaultGetParams().stream().map(NameValuePair::getName).forEach(getParams::add);
         rs.add(new Operation("get", spec.getPath() + "{key}/", getParams));
      }
      rs.addAll(extraOperations());
      return (rs);
   }

}
