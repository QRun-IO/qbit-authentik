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


import java.util.EnumSet;
import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.policy.PolicyStore;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.processes.RunProcessAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessOutput;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Full user and group CRUD (DESIGN.md section 12.5): username and attribute
 ** edits, delete user and delete group, and their gating.
 *******************************************************************************/
class UserGroupCrudTest
{
   private AdminTestSupport t;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeEach
   void setUp() throws QException
   {
      t = AdminTestSupport.create(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP,
         AuthentikFeature.POLICIES, AuthentikFeature.DELETE));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AuthentikAdmin.AdminResult run(AdminRequest request) throws QException
   {
      return (t.admin().execute(request));
   }



   /*******************************************************************************
    ** Username changes are validated and unique.
    *******************************************************************************/
   @Test
   void editUsername() throws QException
   {
      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "rename").with("username", "second")).message()).contains("already has the username");
      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "rename").with("username", "has space")).message()).contains("A username is");

      AuthentikAdmin.AdminResult renamed = run(AdminRequest.of(AdminAction.EDIT_USER, "3", "rename").with("username", "samuel"));
      assertThat(renamed.ok()).as(renamed.message()).isTrue();
      assertThat(t.authentik.users.get(3).getString("username")).isEqualTo("samuel");
   }



   /*******************************************************************************
    ** Other attributes replace the non-reserved part; reserved keys survive and
    ** cannot be set; blank leaves them as they are; editing needs audit.read.
    *******************************************************************************/
   @Test
   void editUserAttributes() throws QException
   {
      t.authentik.users.get(3).put("attributes", new JSONObject().put("qqq.io/protected", false).put("goauthentik.io/user/token-expires", true).put("team", "web").put("old", 1));

      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.EDIT_USER, "3", "update").with("otherAttributes", "{\"team\": \"ops\", \"desk\": 4}"));
      assertThat(result.ok()).as(result.message()).isTrue();
      JSONObject attributes = t.authentik.users.get(3).getJSONObject("attributes");
      assertThat(attributes.getString("team")).isEqualTo("ops");
      assertThat(attributes.getInt("desk")).isEqualTo(4);
      assertThat(attributes.has("old")).isFalse();
      assertThat(attributes.getBoolean("qqq.io/protected")).isFalse();
      assertThat(attributes.getBoolean("goauthentik.io/user/token-expires")).isTrue();

      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "update").with("otherAttributes", "{\"qqq.io/protected\": true}")).message()).contains("reserved");
      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "update").with("otherAttributes", "[1]")).message()).contains("JSON object");
      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "update").with("otherAttributes", "").with("name", "Sam B")).ok()).isTrue();
      assertThat(t.authentik.users.get(3).getJSONObject("attributes").getString("team")).as("blank keeps them").isEqualTo("ops");

      ///////////////////////////////////////////////////////
      // an operator without authentik.audit.read: refused //
      ///////////////////////////////////////////////////////
      t.authentik.groupByName("identity-admins").getJSONObject("attributes").put("qqq.io/permissions", new JSONArray(List.of(
         "authentik.users.read", "authentik.users.manage", "authentik.memberships.manage", "authentik.permissions.manage", "authentik.groups.manage")));
      t.admin().getUtil().getRuntime().invalidateCache();
      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "update").with("otherAttributes", "{\"team\": \"x\"}")).message()).contains("authentik.audit.read");
   }



   /*******************************************************************************
    ** Group attributes the same way.
    *******************************************************************************/
   @Test
   void editGroupAttributes() throws QException
   {
      String pk = t.authentik.pk("kof-website-analysts");
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.EDIT_GROUP, pk, "update").with("otherAttributes", "{\"owner\": \"data team\"}"));
      assertThat(result.ok()).as(result.message()).isTrue();
      JSONObject attributes = t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes");
      assertThat(attributes.getString("owner")).isEqualTo("data team");
      assertThat(attributes.getJSONArray("qqq.io/permissions").toList()).containsExactly("kof22.analytics.hasAccess");
      assertThat(run(AdminRequest.of(AdminAction.EDIT_GROUP, pk, "update").with("otherAttributes", "{\"owner\": \"data team\"}")).noChange()).isTrue();
   }



   /*******************************************************************************
    ** Delete user: typed confirmation, never protected accounts or yourself.
    *******************************************************************************/
   @Test
   void deleteUser() throws QException
   {
      assertThat(run(AdminRequest.of(AdminAction.DELETE_USER, "3", "left")).message()).contains("Type the username (sam)");
      assertThat(run(AdminRequest.of(AdminAction.DELETE_USER, "4", "left").with("confirmText", "breakglass")).message()).contains("Protected");
      assertThat(run(AdminRequest.of(AdminAction.DELETE_USER, "1", "left").with("confirmText", "operator")).message()).contains("your own account");
      assertThat(t.changes()).isEmpty();

      AuthentikAdmin.AdminResult deleted = run(AdminRequest.of(AdminAction.DELETE_USER, "3", "left the company").with("confirmText", "sam"));
      assertThat(deleted.ok()).as(deleted.message()).isTrue();
      assertThat(t.authentik.users).doesNotContainKey(3);
      assertThat(t.changes()).containsExactly("DELETE /core/users/3/");
   }



   /*******************************************************************************
    ** Delete group: typed, and only empty groups without children; the policy
    ** record goes with it.
    *******************************************************************************/
   @Test
   void deleteGroup() throws Exception
   {
      String publishers = t.authentik.pk("kof-website-publishers");
      assertThat(run(AdminRequest.of(AdminAction.DELETE_GROUP, publishers, "cleanup").with("confirmText", "kof-website-publishers")).message()).contains("member(s)");

      t.authentik.group("child-of-analysts", false, List.of(), List.of(), "kof-website-analysts");
      t.admin().getUtil().getRuntime().invalidateCache();
      String analysts = t.authentik.pk("kof-website-analysts");
      assertThat(run(AdminRequest.of(AdminAction.DELETE_GROUP, analysts, "cleanup")).message()).contains("Type the group name");
      assertThat(run(AdminRequest.of(AdminAction.DELETE_GROUP, analysts, "cleanup").with("confirmText", "kof-website-analysts")).message()).contains("child groups (child-of-analysts)");

      String child = t.authentik.pk("child-of-analysts");
      PolicyStore.save(t.config, child, "child-of-analysts", new JSONObject().put("PolicySpec", "qqq-iam").put("PolicyVersion", "1.0.0").put("Statement", new JSONArray()), 0, "x", null);
      AuthentikAdmin.AdminResult deleted = run(AdminRequest.of(AdminAction.DELETE_GROUP, child, "cleanup").with("confirmText", "child-of-analysts"));
      assertThat(deleted.ok()).as(deleted.message()).isTrue();
      assertThat(t.authentik.groups).doesNotContainKey(child);
      assertThat(PolicyStore.find(t.config, child)).isNull();
      assertThat(run(AdminRequest.of(AdminAction.DELETE_GROUP, t.authentik.pk("authentik Admins"), "x").with("confirmText", "authentik Admins")).message()).contains("Superuser groups");
   }



   /*******************************************************************************
    ** DELETE is off by default: no processes, and the action is refused; the
    ** permission is still required with it on.
    *******************************************************************************/
   @Test
   void gating() throws QException
   {
      assertThat(t.qInstance.getProcess("authentikDeleteUser")).isNotNull();
      assertThat(t.qInstance.getProcess("authentikDeleteGroup").getMaxInputRecords()).isEqualTo(1);

      AdminTestSupport off = AdminTestSupport.create();
      assertThat(off.qInstance.getProcess("authentikDeleteUser")).isNull();
      assertThat(off.qInstance.getProcess("authentikDeleteGroup")).isNull();
      assertThat(off.admin().execute(AdminRequest.of(AdminAction.DELETE_USER, "3", "x").with("confirmText", "sam")).ok()).isFalse();

      t.loginAs(AuthentikTestSupport.OPERATOR, IdentityPermission.USERS_READ, IdentityPermission.GROUPS_MANAGE);
      assertThat(run(AdminRequest.of(AdminAction.DELETE_USER, "3", "x").with("confirmText", "sam")).ok()).isFalse();
      assertThat(t.authentik.users).containsKey(3);
   }



   /*******************************************************************************
    ** Edit User prefills username and (with audit.read) other attributes.
    *******************************************************************************/
   @Test
   void editUserPrefill() throws QException
   {
      t.authentik.users.get(3).put("attributes", new JSONObject().put("team", "web").put("qqq.io/x", 1));
      RunProcessInput input = new RunProcessInput();
      input.setProcessName("authentikEditUser");
      input.addValue("recordIds", "3");
      RunProcessOutput output = new RunProcessAction().execute(input);
      assertThat(output.getValues().get("username")).isEqualTo("sam");
      assertThat(new JSONObject(String.valueOf(output.getValues().get("otherAttributes"))).toMap()).containsOnlyKeys("team");

      t.loginAs(AuthentikTestSupport.OPERATOR, IdentityPermission.USERS_READ, IdentityPermission.USERS_MANAGE);
      RunProcessInput limited = new RunProcessInput();
      limited.setProcessName("authentikEditUser");
      limited.addValue("recordIds", "3");
      assertThat(new RunProcessAction().execute(limited).getValues().get("otherAttributes")).isNull();
   }
}
