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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.policy.PolicyCatalog;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 ** Large metadata catalogs stay bounded and filters use resource metadata.
 *******************************************************************************/
class AccessCatalogTest
{
   /*******************************************************************************
    ** Walk every page of 1,000 tables without duplicates or omitted permissions.
    *******************************************************************************/
   @Test
   @SuppressWarnings("unchecked")
   void thousandTablesArePagedAndSearchable()
   {
      QInstance instance = new QInstance();
      instance.addBackend(new QBackendMetaData().withName("memory").withBackendType(MemoryBackendModule.class));
      QAppMetaData app = new QAppMetaData().withName("sales").withLabel("Sales");
      instance.addApp(app);
      for(int i = 0; i < 1000; i++)
      {
         QTableMetaData table = new QTableMetaData().withName(String.format("table%04d", i)).withLabel("Resource " + i).withBackendName("memory")
            .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.READ_INSERT_EDIT_DELETE_PERMISSIONS));
         instance.addTable(table);
         app.withChild(table);
      }
      PolicyCatalog catalog = PolicyCatalog.of(instance);
      var permissions = catalog.permissionNames();
      var seen = new HashSet<String>();
      for(int page = 0; page < 40; page++)
      {
         var result = AccessCatalog.page(permissions, catalog, Map.of("page", String.valueOf(page), "kind", "TABLE", "app", "sales"));
         assertThat(result.get("total")).isEqualTo(1000);
         var rows = (List<Map<String, Object>>) result.get("rows");
         assertThat(rows).hasSize(25);
         for(var row : rows)
         {
            assertThat(seen.add((String) row.get("name"))).isTrue();
            assertThat((List<?>) row.get("permissions")).hasSize(4);
         }
      }
      assertThat(seen).hasSize(1000);
      assertThat(AccessCatalog.page(permissions, catalog, Map.of("search", "Resource 999")).get("total")).isEqualTo(1);
      assertThat(AccessCatalog.page(permissions, catalog, Map.of("app", "missing")).get("total")).isEqualTo(0);
      assertThat(AccessCatalog.page(permissions, catalog, Map.of("kind", "TABLE", "page", "2147483647")).get("page")).isEqualTo(39);
      assertThat(AccessCatalog.page(permissions, catalog, Map.of("page", "invalid")).get("page")).isEqualTo(0);
   }
}
