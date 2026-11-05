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

import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.admin.AdminTestSupport;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Widget data keeps inherited grants and direct edits separate.
 *******************************************************************************/
class AccessEditorWidgetTest
{
   /*******************************************************************************
    ** Membership-backed user previews must load the graph with member IDs.
    *******************************************************************************/
   @Test
   void userPreviewExplainsInheritedAccess() throws QException
   {
      var t = AdminTestSupport.create();
      t.authentik.user(3, "sam", "sam@example.test", "internal", true, "kof-website-publishers");
      var def = AuthentikProcesses.definitions(t.config).stream().filter(d -> d.key().equals("editUserPermissions")).findFirst().orElseThrow();
      var data = AccessEditorWidget.load(t.config, def, "3");
      assertThat(data.getFields()).hasSize(1);
      assertThat(data.getFields().get(0).get("selected")).isEqualTo(List.of());
      assertThat(data.getFields().get(0).get("inherited")).isEqualTo(Map.of("cms.publish.hasAccess", java.util.Set.of("kof-website-publishers")));
      assertThatThrownBy(() -> AccessEditorWidget.load(t.config, def, "missing")).hasMessageContaining("Select a user");
   }

   /*******************************************************************************
    ** Group selectors retain stable identities and labels for existing parents.
    *******************************************************************************/
   @Test
   void groupEditorKeepsParentIdentity() throws QException
   {
      var t = AdminTestSupport.create();
      t.authentik.group("Editors", false, List.of(), List.of(), "kof-website-publishers");
      var def = AuthentikProcesses.definitions(t.config).stream().filter(d -> d.key().equals("editGroup")).findFirst().orElseThrow();
      var data = AccessEditorWidget.load(t.config, def, t.authentik.pk("Editors"));
      assertThat(data.getFields().get(0).get("source")).isEqualTo("authentik_group");
      assertThat(data.getFields().get(0).get("selected")).isEqualTo(List.of(Map.of("id", t.authentik.pk("kof-website-publishers"), "label", "kof-website-publishers")));
   }
   /*******************************************************************************
    ** Core picker search must produce a server-supported single-field filter.
    *******************************************************************************/
   @Test
   void searchableSelectorsUseSupportedFilters() throws QException
   {
      AdminTestSupport.create();
      for(String source : List.of("authentik_user", "authentik_group"))
      {
         var result = new com.kingsrook.qqq.backend.core.actions.values.SearchPossibleValueSourceAction().execute(
            new com.kingsrook.qqq.backend.core.model.actions.values.SearchPossibleValueSourceInput()
               .withPossibleValueSourceName(source).withSearchTerm(source.endsWith("user") ? "sam" : "kof"));
         assertThat(result.getResults()).isNotEmpty();
      }
   }

}
