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
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 ** Deep role ancestry and concurrent snapshot reads at representative scale.
 ** This is an in-process resolver check, not an API or distributed-write SLA.
 *******************************************************************************/
class PermissionScaleTest
{
   /*******************************************************************************
    ** Resolve 1,000 users across a 1,000-level hierarchy from four threads,
    ** including an ancestry cycle and a new snapshot after a grant is removed.
    *******************************************************************************/
   @Test
   @Timeout(30)
   void deepHierarchyAndConcurrentReadersRemainCorrect() throws Exception
   {
      List<JSONObject> groups = new ArrayList<>();
      var catalog = new TreeSet<String>();
      for(int i = 0; i < 1000; i++)
      {
         String permission = "document" + i + ".read";
         catalog.add(permission);
         groups.add(new JSONObject().put("pk", "g" + i).put("name", "Role " + i)
            .put("parents", new JSONArray(i == 0 ? List.of() : List.of("g" + (i - 1))))
            .put("users", new JSONArray().put(i + 1)).put("attributes", new JSONObject()
               .put("qqq.io/permissions", new JSONArray().put(permission))));
      }
      GroupGraph graph = GroupGraph.fromGroups(groups);
      var resolver = new EffectivePermissionResolver(graph, catalog);
      long started = System.nanoTime();
      try(var workers = Executors.newFixedThreadPool(4))
      {
         List<Callable<Integer>> queries = new ArrayList<>();
         for(int user = 1; user <= 1000; user++)
         {
            int userPk = user;
            queries.add(() -> resolver.resolveUser(userPk).sessionPermissions().size());
         }
         var results = workers.invokeAll(queries);
         for(int i = 0; i < results.size(); i++)
         {
            assertThat(results.get(i).get()).isEqualTo(i + 1);
         }
      }
      System.out.println("Resolver scale: 1000 users, 1000 ancestry levels, 4 readers, " + ((System.nanoTime() - started) / 1_000_000) + " ms");
      groups.get(0).put("parents", new JSONArray().put("g999"));
      assertThat(new EffectivePermissionResolver(GroupGraph.fromGroups(groups), catalog).resolveUser(1).sessionPermissions()).hasSize(1000);
      groups.get(0).put("parents", new JSONArray()).put("attributes", new JSONObject());
      var refreshed = new EffectivePermissionResolver(GroupGraph.fromGroups(groups), catalog);
      assertThat(refreshed.resolveUser(1000).sessionPermissions()).hasSize(999).doesNotContain("document0.read");
      assertThat(resolver.resolveUser(1000).sessionPermissions()).hasSize(1000);
   }
}
