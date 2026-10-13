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

package com.kingsrook.qbits.authentik.policy;


import java.util.List;
import java.util.Set;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.reporting.QReportMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Unit tests for PolicyCatalog: the editor's enumeration of what a policy can
 ** grant in a QInstance, grouped by app.
 *******************************************************************************/
class PolicyCatalogTest
{

   /*******************************************************************************
    **
    *******************************************************************************/
   private static QPermissionRules rules(PermissionLevel level)
   {
      return (new QPermissionRules().withLevel(level));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static QTableMetaData table(String name, String label, PermissionLevel level)
   {
      return (new QTableMetaData().withName(name).withLabel(label).withBackendName("memory").withPrimaryKeyField("id")
         .withField(new QFieldMetaData("id", QFieldType.INTEGER)).withPermissionRules(rules(level)));
   }



   /*******************************************************************************
    ** An instance with every kind of object and permission shape.
    *******************************************************************************/
   static QInstance instance()
   {
      QInstance instance = new QInstance();
      instance.addBackend(new QBackendMetaData().withName("memory").withBackendType(MemoryBackendModule.class));

      QTableMetaData page    = table("cms_page", "Pages", PermissionLevel.READ_INSERT_EDIT_DELETE_PERMISSIONS);
      QTableMetaData audit   = table("cms_audit", "Audit", PermissionLevel.READ_INSERT_EDIT_DELETE_PERMISSIONS).withoutCapabilities(Capability.TABLE_INSERT, Capability.TABLE_UPDATE, Capability.TABLE_DELETE);
      QTableMetaData legacy  = table("legacy", "Legacy", PermissionLevel.READ_WRITE_PERMISSIONS);
      QTableMetaData gate    = table("gate", "Gate", PermissionLevel.HAS_ACCESS_PERMISSION);
      QTableMetaData shared1 = table("shared_one", "Shared One", PermissionLevel.HAS_ACCESS_PERMISSION);
      shared1.getPermissionRules().setPermissionBaseName("shared_base");
      QTableMetaData shared2 = table("shared_two", "Shared Two", PermissionLevel.HAS_ACCESS_PERMISSION);
      shared2.getPermissionRules().setPermissionBaseName("shared_base");
      QTableMetaData open    = table("open_table", "Open", PermissionLevel.NOT_PROTECTED);
      QTableMetaData dotted  = table("dotted", "Dotted", PermissionLevel.HAS_ACCESS_PERMISSION);
      dotted.getPermissionRules().setPermissionBaseName("cms.publish");
      QTableMetaData orphan  = table("orphan", "Orphan", PermissionLevel.READ_INSERT_EDIT_DELETE_PERMISSIONS);
      for(QTableMetaData t : List.of(page, audit, legacy, gate, shared1, shared2, open, dotted, orphan))
      {
         instance.addTable(t);
      }

      instance.addProcess(new QProcessMetaData().withName("publishPage").withLabel("Publish").withTableName("cms_page").withIsHidden(true)
         .withPermissionRules(rules(PermissionLevel.HAS_ACCESS_PERMISSION)));
      instance.addProcess(new QProcessMetaData().withName("loose").withLabel("Loose").withPermissionRules(rules(PermissionLevel.HAS_ACCESS_PERMISSION)));
      instance.addReport(new QReportMetaData().withName("pageReport").withLabel("Page Report").withPermissionRules(rules(PermissionLevel.HAS_ACCESS_PERMISSION)));
      instance.addWidget(new QWidgetMetaData().withName("pageStats").withLabel("Page Stats").withPermissionRules(rules(PermissionLevel.HAS_ACCESS_PERMISSION)));
      instance.addWidget(new QWidgetMetaData().withName("openWidget").withLabel("Open Widget").withPermissionRules(rules(PermissionLevel.NOT_PROTECTED)));

      instance.addApp(new QAppMetaData().withName("content").withLabel("Content").withSortOrder(1)
         .withChild(page).withChild(audit).withChild(legacy).withChild(gate).withChild(shared1).withChild(shared2).withChild(open).withChild(dotted)
         .withChild(instance.getReport("pageReport")).withWidgets(List.of("pageStats"))
         .withPermissionRules(rules(PermissionLevel.HAS_ACCESS_PERMISSION)));
      instance.addApp(new QAppMetaData().withName("emptyApp").withLabel("Empty").withSortOrder(2).withPermissionRules(rules(PermissionLevel.NOT_PROTECTED)));
      return (instance);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void groupsByAppWithTheActionsQqqChecks()
   {
      PolicyCatalog catalog = PolicyCatalog.of(instance());

      assertThat(catalog.getGroups()).extracting(PolicyCatalog.Group::label).containsExactly("Content", "Other");
      PolicyCatalog.Group content = catalog.getGroups().get(0);
      assertThat(content.resources()).extracting(PolicyCatalog.Resource::name)
         .containsExactly("content", "cms_audit", "gate", "legacy", "cms_page", "shared_base", "publishPage", "pageReport", "pageStats");

      assertThat(catalog.get("content").actions()).containsExactly(PolicyAction.HAS_ACCESS);
      assertThat(catalog.get("cms_page").actions()).containsExactly(PolicyAction.READ, PolicyAction.INSERT, PolicyAction.EDIT, PolicyAction.DELETE);
      assertThat(catalog.get("cms_audit").actions()).as("capabilities limit the actions").containsExactly(PolicyAction.READ);
      assertThat(catalog.get("legacy").actions()).containsExactly(PolicyAction.READ);
      assertThat(catalog.get("legacy").note()).contains("write permission");
      assertThat(catalog.get("gate").actions()).containsExactly(PolicyAction.HAS_ACCESS);
      assertThat(catalog.get("publishPage").kind()).isEqualTo(PolicyCatalog.Kind.PROCESS);
      assertThat(catalog.get("publishPage").label()).as("a hidden record action, with its table").isEqualTo("Publish (Pages action)");
      assertThat(catalog.get("shared_base").label()).as("one entry per base name").isEqualTo("Shared One / Shared Two");

      assertThat(catalog.getGroups().get(1).resources()).extracting(PolicyCatalog.Resource::name).containsExactly("orphan", "loose");
      assertThat(catalog.get("open_table")).as("not protected: nothing to grant").isNull();
      assertThat(catalog.get("openWidget")).isNull();
      assertThat(catalog.get("emptyApp")).isNull();
      assertThat(catalog.get("cms.publish")).as("a dotted base name cannot be a resource").isNull();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void permissionNamesAndUnknowns()
   {
      PolicyCatalog catalog = PolicyCatalog.of(instance());
      assertThat(catalog.permissionNames()).contains("cms_page.read", "cms_page.delete", "content.hasAccess", "publishPage.hasAccess", "pageReport.hasAccess")
         .doesNotContain("cms_page.hasAccess", "cms_audit.edit", "open_table.read");
      assertThat(catalog.unknownPermissions(Set.of("cms_page.read", "cms_page.hasAccess", "gone.read"))).containsExactly("cms_page.hasAccess", "gone.read");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void json()
   {
      JSONArray json = PolicyCatalog.of(instance()).toJson();
      JSONObject content = json.getJSONObject(0);
      assertThat(content.getString("app")).isEqualTo("content");
      assertThat(content.getString("label")).isEqualTo("Content");
      JSONObject legacy = content.getJSONArray("resources").getJSONObject(3);
      assertThat(legacy.getString("name")).isEqualTo("legacy");
      assertThat(legacy.getString("kind")).isEqualTo("TABLE");
      assertThat(legacy.getJSONArray("actions").toList()).containsExactly("read");
      assertThat(legacy.has("note")).isTrue();
      assertThat(json.getJSONObject(1).isNull("app")).isTrue();
      assertThat(PolicyCatalog.of(new QInstance()).getGroups()).isEmpty();
   }
}
