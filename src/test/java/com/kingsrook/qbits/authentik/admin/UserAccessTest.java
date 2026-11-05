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

package com.kingsrook.qbits.authentik.admin;

import java.util.List;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Direct user grants must remain isolated and obey all normal write guards.
 *******************************************************************************/
class UserAccessTest
{
   private AdminTestSupport t;

   /*******************************************************************************
    ** Isolated directory with two administrators and one ordinary user.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws QException
   {
      t = AdminTestSupport.create();
   }

   /*******************************************************************************
    ** A fresh direct-grant request.
    *******************************************************************************/
   private AdminRequest request(String user, String permissions, String fingerprint)
   {
      return (AdminRequest.of(AdminAction.EDIT_USER_PERMISSIONS, user, "Review access")
         .with("permissions", permissions).with("expectedFingerprint", fingerprint));
   }

   /*******************************************************************************
    ** Create, resolve and revoke direct access without affecting another user.
    *******************************************************************************/
   @Test
   void grantsResolveAndRevoke() throws QException
   {
      assertThat(t.admin().execute(request("3", "cms.publish.hasAccess", "absent")).ok()).isTrue();
      JSONObject group = t.admin().userAccessGroup("3");
      assertThat(group.getJSONArray("users").toList()).containsExactly(3);
      GroupGraph graph = GroupGraph.fromGroups(t.authentik.groups.values());
      var resolver = new EffectivePermissionResolver(graph, AuthentikRuntime.forBackend(t.config.getApiBackendName()).getPermissionCatalog());
      assertThat(resolver.resolveUser(3).sessionPermissions()).contains("cms.publish.hasAccess");
      assertThat(resolver.resolveUser(7).sessionPermissions()).doesNotContain("cms.publish.hasAccess");
      assertThat(t.admin().execute(request("3", "", AuthentikSafety.groupFingerprint(group))).ok()).isTrue();
      assertThat(t.admin().userAccessGroup("3").getJSONObject("attributes").optJSONArray("qqq.io/permissions")).isNull();
   }

   /*******************************************************************************
    ** Self, protected and out-of-subset changes produce no API writes.
    *******************************************************************************/
   @Test
   void refusesProtectedSelfAndEscalation() throws QException
   {
      for(String user : List.of("1", "4", "5", "6"))
      {
         assertThat(t.admin().execute(request(user, "cms.publish.hasAccess", "absent")).ok()).isFalse();
      }
      assertThat(t.admin().execute(request("3", "kof22.analytics.hasAccess", "absent")).ok()).isFalse();
      assertThat(t.writes()).isEmpty();
   }

   /*******************************************************************************
    ** A stale create cannot create another granting group.
    *******************************************************************************/
   @Test
   void refusesStaleCreateAndMissingFingerprint() throws QException
   {
      assertThat(t.admin().execute(request("3", "cms.publish.hasAccess", "")).ok()).isFalse();
      assertThat(t.admin().execute(request("3", "cms.publish.hasAccess", "absent")).ok()).isTrue();
      int count = t.authentik.groups.size();
      assertThat(t.admin().execute(request("3", "", "absent")).ok()).isFalse();
      assertThat(t.authentik.groups).hasSize(count);
   }

   /*******************************************************************************
    ** Client input and externally supplied previews cannot bypass two-person
    ** approval, and execution must reconsider changes made after preview.
    *******************************************************************************/
   @Test
   void approvalAuthorityCannotComeFromInputOrPreview() throws QException
   {
      var forged = request("3", "authentik.users.read", "absent").with("approved", true);
      assertThat(t.admin().execute(forged).pending()).isTrue();
      assertThat(t.writes()).isEmpty();

      var admin = t.admin();
      var preview = admin.plan(request("7", "cms.publish.hasAccess", "absent"));
      assertThatThrownBy(() -> admin.execute(preview, "second@example.test")).hasMessageContaining("stored approval");
      assertThat(t.admin().execute(request("7", "cms.publish.hasAccess", "absent")).ok()).isTrue();
      assertThat(admin.execute(preview, null).ok()).isFalse();
   }

   /*******************************************************************************
    ** Dedicated groups cannot be shared, inherited or edited through group tools.
    *******************************************************************************/
   @Test
   void dedicatedGroupsCannotBeRepurposed() throws QException
   {
      assertThat(t.admin().execute(request("3", "cms.publish.hasAccess", "absent")).ok()).isTrue();
      JSONObject group = t.admin().userAccessGroup("3");
      String pk = group.getString("pk");
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.ADD_MEMBER, pk + ":7", "Share")).ok()).isFalse();
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.REMOVE_MEMBER, pk + ":3", "Remove")).ok()).isFalse();
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, pk, "Edit").with("permissions", "")).ok()).isFalse();
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.CREATE_GROUP, "", "Inherit").with("name", "Shared")
         .with("parentIds", pk)).ok()).isFalse();
      t.authentik.groups.get(pk).put("users", new JSONArray().put(3).put(7));
      assertThat(t.admin().execute(request("3", "", AuthentikSafety.groupFingerprint(group))).ok()).isFalse();
   }

   /*******************************************************************************
    ** Role marking has no Authentik administrative meaning; IDs drive inheritance.
    *******************************************************************************/
   @Test
   void applicationRoleCreationAndAssignment() throws QException
   {
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.CREATE_GROUP, "", "Create role").with("name", "Publisher, editorial")
         .with("applicationRole", true).with("permissions", "cms.publish.hasAccess")).ok()).isTrue();
      JSONObject role = t.authentik.groupByName("Publisher, editorial");
      assertThat(role.getJSONObject("attributes").getBoolean("qqq.io/application-role")).isTrue();
      assertThat(role.optJSONArray("roles")).isNull();
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.CREATE_GROUP, "", "Assign role").with("name", "Editors")
         .with("parentIds", role.getString("pk"))).ok()).isTrue();
      assertThat(t.authentik.groupByName("Editors").getJSONArray("parents").toList()).containsExactly(role.getString("pk"));
   }
}
