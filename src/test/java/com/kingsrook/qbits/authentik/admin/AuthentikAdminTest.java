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
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** The guard rules of DESIGN.md section 5.4 and the actions of section 6.3,
 ** exercised against an in-memory Authentik (FakeAuthentik). Each rule is tested
 ** both ways: it refuses what it must, and it allows what it should, and a
 ** refusal never reaches Authentik.
 *******************************************************************************/
class AuthentikAdminTest
{
   private AdminTestSupport t;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeEach
   void setUp() throws QException
   {
      t = AdminTestSupport.create();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AuthentikAdmin.AdminResult run(AdminRequest request) throws QException
   {
      return (t.admin().execute(request));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AdminRequest add(int userPk, String group)
   {
      return (AdminRequest.of(AdminAction.ADD_MEMBER, t.authentik.pk(group) + ":" + userPk, "because"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<QRecord> rows(String table) throws QException
   {
      QueryInput input = new QueryInput();
      input.setTableName(t.config.applyTablePrefix(table));
      return (new QueryAction().execute(input).getRecords());
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // memberships and the subset (no escalation) rule
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Adding to a group whose permissions the operator holds works, is audited
    ** before the call, and posts an event naming the human operator.
    *******************************************************************************/
   @Test
   void addMemberHeldPermissions() throws QException
   {
      AuthentikAdmin.AdminResult result = run(add(3, "kof-website-publishers"));

      assertThat(result.ok()).isTrue();
      assertThat(t.authentik.groupNamesOf(3)).containsExactly("kof-website-publishers");
      assertThat(t.changes()).containsExactly("POST /core/groups/" + t.authentik.pk("kof-website-publishers") + "/add_user/");
      assertThat(t.authentik.events).hasSize(1);
      assertThat(t.authentik.events.get(0).getString("action")).isEqualTo("custom_qqq_admin_action");
      assertThat(t.authentik.events.get(0).getJSONObject("context").getString("operator")).isEqualTo(AuthentikTestSupport.OPERATOR);
      assertThat(t.authentik.events.get(0).getJSONObject("context").getString("reason")).isEqualTo("because");

      List<QRecord> audit = rows(AuthentikLocalTables.ADMIN_ACTION);
      assertThat(audit).hasSize(1);
      assertThat(audit.get(0).getValueString("status")).isEqualTo("SUCCEEDED");
      assertThat(audit.get(0).getValueString("actionName")).isEqualTo("ADD_MEMBER");
      assertThat(audit.get(0).getValueString("operator")).isEqualTo(AuthentikTestSupport.OPERATOR);
      assertThat(audit.get(0).getValueString("targetLabel")).contains("sam");
      assertThat(audit.get(0).getValueString("authentikEventPk")).isNotBlank();
   }



   /*******************************************************************************
    ** The subset rule: an operator cannot hand out permissions they do not hold.
    *******************************************************************************/
   @Test
   void addMemberRefusedWhenGroupGrantsWhatOperatorLacks() throws QException
   {
      AuthentikAdmin.AdminResult result = run(add(3, "kof-website-analysts"));

      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("kof22.analytics.hasAccess");
      assertThat(t.writes()).isEmpty();
      assertThat(rows(AuthentikLocalTables.ADMIN_ACTION).get(0).getValueString("status")).isEqualTo("REFUSED");
   }



   /*******************************************************************************
    ** Adding to a group that gives sign-in to an app the operator cannot open is
    ** refused too (app-access subset).
    *******************************************************************************/
   @Test
   void addMemberRefusedWhenGroupGrantsAppAccessOperatorLacks() throws QException
   {
      t.authentik.group("kof-secret-app", false, List.of(), List.of("secret-app"));
      AuthentikAdmin.AdminResult result = run(add(3, "kof-secret-app"));

      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("secret-app");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** The subset rule uses the operator's LIVE groups, not the session claim:
    ** an operator whose session says authentik.* but who was removed from the
    ** groups in Authentik holds nothing.
    *******************************************************************************/
   @Test
   void subsetRuleUsesLiveGroupsNotTheSession() throws QException
   {
      t.authentik.groupByName("kof-website-publishers").put("users", new JSONArray());
      AuthentikAdmin.AdminResult result = run(add(3, "kof-website-publishers"));

      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("cms.publish.hasAccess");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Superuser groups cannot be managed (adding to one would make a superuser).
    *******************************************************************************/
   @Test
   void superuserGroupsAreProtected() throws QException
   {
      AuthentikAdmin.AdminResult result = run(add(3, "authentik Admins"));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).containsIgnoringCase("superuser");
      assertThat(t.writes()).isEmpty();

      t.authentik.group("kof-under-superuser", false, List.of(), List.of(), "authentik Admins");
      AuthentikAdmin.AdminResult descendant = run(add(3, "kof-under-superuser"));
      assertThat(descendant.ok()).isFalse();
      assertThat(descendant.message()).containsIgnoringCase("superuser");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Protected accounts and self-edits are refused.
    *******************************************************************************/
   @Test
   void protectedAccountsAndSelfEditsAreRefused() throws QException
   {
      for(int pk : new int[] { 4, 5, 1 })
      {
         AuthentikAdmin.AdminResult result = run(add(pk, "kof-website-publishers"));
         assertThat(result.ok()).as("user " + pk).isFalse();
      }
      assertThat(run(add(4, "kof-website-publishers")).message()).containsIgnoringCase("protected");
      assertThat(run(add(1, "kof-website-publishers")).message()).contains("your own account");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Service accounts are listed but can only be deactivated or have app
    ** passwords revoked.
    *******************************************************************************/
   @Test
   void serviceAccountsOnlyDeactivateAndRevoke() throws QException
   {
      assertThat(run(add(6, "kof-website-publishers")).message()).contains("Service accounts can only");
      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "6", "because").with("name", "x")).message()).contains("Service accounts can only");

      AuthentikAdmin.AdminResult deactivate = run(AdminRequest.of(AdminAction.DEACTIVATE_USER, "6", "because").with("confirmText", "svc-publisher"));
      assertThat(deactivate.ok()).isTrue();
      assertThat(t.authentik.users.get(6).getBoolean("is_active")).isFalse();
   }



   /*******************************************************************************
    ** Removing a member works and is audited.
    *******************************************************************************/
   @Test
   void removeMember() throws QException
   {
      t.authentik.groupByName("kof-website-publishers").getJSONArray("users").put(3);
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.REMOVE_MEMBER, t.authentik.pk("kof-website-publishers") + ":3", "because"));

      assertThat(result.ok()).isTrue();
      assertThat(t.authentik.groupNamesOf(3)).isEmpty();
      assertThat(t.changes()).containsExactly("POST /core/groups/" + t.authentik.pk("kof-website-publishers") + "/remove_user/");
   }



   /*******************************************************************************
    ** Removing someone who is not a member, or adding a member again, is a no-op
    ** that sends nothing.
    *******************************************************************************/
   @Test
   void alreadyDoneIsNoChange() throws QException
   {
      AuthentikAdmin.AdminResult notMember = run(AdminRequest.of(AdminAction.REMOVE_MEMBER, t.authentik.pk("kof-website-publishers") + ":3", "because"));
      assertThat(notMember.ok()).isTrue();
      assertThat(notMember.noChange()).isTrue();

      AuthentikAdmin.AdminResult again = run(add(2, "identity-admins"));
      assertThat(again.noChange()).isTrue();
      assertThat(t.writes()).isEmpty();
      assertThat(rows(AuthentikLocalTables.ADMIN_ACTION)).isEmpty();
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // last-admin protection
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** The last person who can manage memberships and permissions cannot be
    ** removed; with a second administrator the same change is allowed.
    *******************************************************************************/
   @Test
   void lastAdminCannotBeRemoved() throws QException
   {
      // acting person: holds the session permissions but is not an administrator in Authentik
      t.loginAs("sam@example.test", IdentityPermission.MEMBERSHIPS_MANAGE);

      AuthentikAdmin.AdminResult allowed = run(AdminRequest.of(AdminAction.REMOVE_MEMBER, t.authentik.pk("identity-admins") + ":2", "because"));
      assertThat(allowed.ok()).as(allowed.message()).isTrue();

      AuthentikAdmin.AdminResult refused = run(AdminRequest.of(AdminAction.REMOVE_MEMBER, t.authentik.pk("identity-admins") + ":1", "because"));
      assertThat(refused.ok()).isFalse();
      assertThat(refused.message()).contains("last person");
      assertThat(t.authentik.groupNamesOf(1)).contains("identity-admins");
   }



   /*******************************************************************************
    ** Deactivating the last administrator is refused.
    *******************************************************************************/
   @Test
   void lastAdminCannotBeDeactivated() throws QException
   {
      t.authentik.groupByName("identity-admins").put("users", new JSONArray(List.of(1)));
      t.loginAs("sam@example.test", IdentityPermission.USERS_MANAGE);

      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.DEACTIVATE_USER, "1", "because").with("confirmText", "operator"));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("last active person");
      assertThat(t.authentik.users.get(1).getBoolean("is_active")).isTrue();
   }



   /*******************************************************************************
    ** Removing the permissions from the only administrator group is refused.
    *******************************************************************************/
   @Test
   void lastAdminCannotLosePermissionsByGroupEdit() throws QException
   {
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("identity-admins"), "because")
         .with("permissions", "").with("appAccess", "kof22-website-prod"));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("nobody able to manage");
      assertThat(t.writes()).isEmpty();
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // permissions and app access
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Adding a permission the operator holds works, and the write merges only the
    ** two qqq.io keys into the group's CURRENT attributes (other attributes and
    ** edits made in the Authentik UI survive).
    *******************************************************************************/
   @Test
   void editPermissionsMergesIntoCurrentAttributes() throws QException
   {
      t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").put("note", "set in the Authentik UI");

      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-analysts"), "because")
         .with("permissions", "kof22.analytics.hasAccess\ncms.publish.hasAccess").with("appAccess", ""));

      assertThat(result.ok()).as(result.message()).isTrue();
      JSONObject attributes = t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes");
      assertThat(attributes.getString("note")).isEqualTo("set in the Authentik UI");
      assertThat(attributes.getJSONArray("qqq.io/permissions").toList()).containsExactly("kof22.analytics.hasAccess", "cms.publish.hasAccess");
      assertThat(attributes.has("qqq.io/app-access")).isFalse();
      assertThat(t.changes()).containsExactly("PATCH /core/groups/" + t.authentik.pk("kof-website-analysts") + "/");
   }



   /*******************************************************************************
    ** A permission the operator does not hold cannot be granted; removing one
    ** needs no subset; unknown names are rejected.
    *******************************************************************************/
   @Test
   void editPermissionsSubsetAndUnknownNames() throws QException
   {
      AuthentikAdmin.AdminResult escalation = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-publishers"), "because")
         .with("permissions", "cms.publish.hasAccess\nkof22.analytics.hasAccess").with("appAccess", "kof22-website-prod"));
      assertThat(escalation.ok()).isFalse();
      assertThat(escalation.message()).contains("kof22.analytics.hasAccess");

      AuthentikAdmin.AdminResult unknown = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-publishers"), "because")
         .with("permissions", "cms.publish.hasAccess\nnot.a.real.permission").with("appAccess", "kof22-website-prod"));
      assertThat(unknown.ok()).isFalse();
      assertThat(unknown.message()).contains("Unknown permission");

      AuthentikAdmin.AdminResult removal = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-analysts"), "because")
         .with("permissions", "").with("appAccess", ""));
      assertThat(removal.ok()).isTrue();
      assertThat(t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").has("qqq.io/permissions")).isFalse();
   }



   /*******************************************************************************
    ** App access: an operator can only give sign-in to apps they can open.
    *******************************************************************************/
   @Test
   void editAppAccessSubset() throws QException
   {
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-analysts"), "because")
         .with("permissions", "kof22.analytics.hasAccess").with("appAccess", "secret-app"));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("secret-app");

      AuthentikAdmin.AdminResult allowed = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-analysts"), "because")
         .with("permissions", "kof22.analytics.hasAccess").with("appAccess", "kof22-website-prod"));
      assertThat(allowed.ok()).isTrue();
   }



   /*******************************************************************************
    ** A change made in the Authentik UI after the form was opened is not
    ** overwritten (stale check by fingerprint).
    *******************************************************************************/
   @Test
   void staleGroupIsRefused() throws QException
   {
      String fingerprint = AuthentikSafety.groupFingerprint(t.authentik.groupByName("kof-website-analysts"));
      t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").put("qqq.io/permissions", new JSONArray(List.of("kof22.analytics.hasAccess", "cms.publish.hasAccess")));

      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-analysts"), "because")
         .with("permissions", "cms.publish.hasAccess").with("appAccess", "").with("expectedFingerprint", fingerprint));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("changed");
      assertThat(t.writes()).isEmpty();
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // two-person approval
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Granting authentik.* is queued for a second person: nothing is sent to
    ** Authentik, the request is stored, and the same person cannot approve it. A
    ** different person who holds authentik.approve applies it, and the change is
    ** planned again under their own permissions.
    *******************************************************************************/
   @Test
   void grantingIdentityPermissionsNeedsASecondPerson() throws QException
   {
      AdminRequest request = AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-publishers"), "give them user read")
         .with("permissions", "cms.publish.hasAccess\nauthentik.users.read").with("appAccess", "kof22-website-prod");
      AuthentikAdmin.AdminResult queued = run(request);

      assertThat(queued.ok()).isTrue();
      assertThat(queued.pending()).isTrue();
      assertThat(t.writes()).isEmpty();
      List<QRecord> approvals = rows(AuthentikLocalTables.APPROVAL_REQUEST);
      assertThat(approvals).hasSize(1);
      assertThat(approvals.get(0).getValueString("status")).isEqualTo("PENDING");
      assertThat(approvals.get(0).getValueString("requester")).isEqualTo(AuthentikTestSupport.OPERATOR);
      assertThat(rows(AuthentikLocalTables.ADMIN_ACTION).get(0).getValueString("status")).isEqualTo("PENDING_APPROVAL");

      java.io.Serializable id = approvals.get(0).getValue("id");
      AuthentikAdmin.AdminResult self = t.admin().approve(id);
      assertThat(self.ok()).isFalse();
      assertThat(self.message()).contains("cannot approve your own");

      t.loginAs("second@example.test", IdentityPermission.APPROVE, IdentityPermission.PERMISSIONS_MANAGE);
      AuthentikAdmin.AdminResult approved = t.admin().approve(id);
      assertThat(approved.ok()).as(approved.message()).isTrue();
      assertThat(t.authentik.groupByName("kof-website-publishers").getJSONObject("attributes").getJSONArray("qqq.io/permissions").toList())
         .containsExactly("cms.publish.hasAccess", "authentik.users.read");
      assertThat(rows(AuthentikLocalTables.APPROVAL_REQUEST).get(0).getValueString("status")).isEqualTo("APPROVED");
      assertThat(rows(AuthentikLocalTables.APPROVAL_REQUEST).get(0).getValueString("approver")).isEqualTo("second@example.test");

      AuthentikAdmin.AdminResult twice = t.admin().approve(id);
      assertThat(twice.ok()).isFalse();
      assertThat(twice.message()).contains("already decided");
   }



   /*******************************************************************************
    ** Rejecting stores the decision and changes nothing in Authentik; deciding
    ** needs authentik.approve.
    *******************************************************************************/
   @Test
   void rejectAndApproverPermission() throws QException
   {
      run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-publishers"), "r")
         .with("permissions", "cms.publish.hasAccess\nauthentik.users.read").with("appAccess", "kof22-website-prod"));
      java.io.Serializable id = rows(AuthentikLocalTables.APPROVAL_REQUEST).get(0).getValue("id");

      t.loginAs("second@example.test", IdentityPermission.PERMISSIONS_MANAGE);
      assertThat(t.admin().reject(id).message()).contains("authentik.approve");

      t.loginAs("second@example.test", IdentityPermission.APPROVE);
      assertThat(t.admin().reject(id).ok()).isTrue();
      assertThat(rows(AuthentikLocalTables.APPROVAL_REQUEST).get(0).getValueString("status")).isEqualTo("REJECTED");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** With two-person approval off, authentik.* grants apply at once.
    *******************************************************************************/
   @Test
   void approvalCanBeTurnedOff() throws QException
   {
      t.config.withTwoPersonApproval(false);
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-publishers"), "because")
         .with("permissions", "cms.publish.hasAccess\nauthentik.users.read").with("appAccess", "kof22-website-prod"));
      assertThat(result.ok()).isTrue();
      assertThat(result.pending()).isFalse();
      assertThat(t.changes()).hasSize(1);
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // groups
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Create a group with a parent, permissions and app access.
    *******************************************************************************/
   @Test
   void createGroup() throws QException
   {
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.CREATE_GROUP, "", "because").with("name", "kof-editors")
         .with("parents", "kof-website-publishers").with("permissions", "cms.publish.hasAccess").with("appAccess", "kof22-website-prod"));

      assertThat(result.ok()).as(result.message()).isTrue();
      JSONObject group = t.authentik.groupByName("kof-editors");
      assertThat(group.getJSONArray("parents").getString(0)).isEqualTo(t.authentik.pk("kof-website-publishers"));
      assertThat(group.getBoolean("is_superuser")).isFalse();
      assertThat(group.getJSONObject("attributes").getJSONArray("qqq.io/permissions").toList()).containsExactly("cms.publish.hasAccess");
   }



   /*******************************************************************************
    ** Group creation rules: unique names, no superuser parents, the subset rule
    ** for parents and permissions.
    *******************************************************************************/
   @Test
   void createGroupRules() throws QException
   {
      assertThat(run(AdminRequest.of(AdminAction.CREATE_GROUP, "", "b").with("name", "identity-admins")).message()).contains("already exists");
      assertThat(run(AdminRequest.of(AdminAction.CREATE_GROUP, "", "b").with("name", "x").with("parents", "authentik Admins")).message()).containsIgnoringCase("superuser");
      assertThat(run(AdminRequest.of(AdminAction.CREATE_GROUP, "", "b").with("name", "x").with("parents", "kof-website-analysts")).message()).contains("kof22.analytics.hasAccess");
      assertThat(run(AdminRequest.of(AdminAction.CREATE_GROUP, "", "b").with("name", "x").with("permissions", "kof22.analytics.hasAccess")).message()).contains("do not hold");
      assertThat(run(AdminRequest.of(AdminAction.CREATE_GROUP, "", "b").with("name", "x").with("parents", "nope")).message()).contains("No parent group");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Re-parenting: loops and superuser parents are refused.
    *******************************************************************************/
   @Test
   void editGroupParents() throws QException
   {
      t.authentik.group("kof-child", false, List.of(), List.of(), "kof-website-publishers");

      AuthentikAdmin.AdminResult loop = run(AdminRequest.of(AdminAction.EDIT_GROUP, t.authentik.pk("kof-website-publishers"), "b").with("parents", "kof-child"));
      assertThat(loop.message()).contains("loop");

      AuthentikAdmin.AdminResult superuser = run(AdminRequest.of(AdminAction.EDIT_GROUP, t.authentik.pk("kof-child"), "b").with("parents", "authentik Admins"));
      assertThat(superuser.message()).containsIgnoringCase("superuser");

      String childPk = t.authentik.pk("kof-child");
      AuthentikAdmin.AdminResult rename = run(AdminRequest.of(AdminAction.EDIT_GROUP, childPk, "b").with("name", "kof-grandchild"));
      assertThat(rename.ok()).as(rename.message()).isTrue();
      assertThat(t.authentik.groups.get(childPk).getString("name")).isEqualTo("kof-grandchild");

      AuthentikAdmin.AdminResult superuserGroup = run(AdminRequest.of(AdminAction.EDIT_GROUP, t.authentik.pk("authentik Admins"), "b").with("name", "renamed"));
      assertThat(superuserGroup.message()).containsIgnoringCase("superuser");
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // users
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Create a user: no password is sent, memberships are added, and
    ** Authentik emails the recovery link (QQQ never sees it).
    *******************************************************************************/
   @Test
   void createUserNeverSetsAPassword() throws QException
   {
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.CREATE_USER, "", "new hire").with("username", "newbie").with("name", "New Bie")
         .with("email", "newbie@example.test").with("groups", "kof-website-publishers"));

      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(t.changes()).hasSize(3);
      assertThat(t.changes().get(0)).isEqualTo("POST /core/users/");
      assertThat(t.changes().get(1)).endsWith("/add_user/");
      assertThat(t.changes().get(2)).isEqualTo("POST /core/users/100/recovery_email/");

      JSONObject createBody = t.authentik.writeBodies.get(0);
      assertThat(createBody.keySet()).doesNotContain("password", "password_hash");
      assertThat(createBody.getString("username")).isEqualTo("newbie");
      assertThat(createBody.getBoolean("is_active")).isTrue();
      assertThat(createBody.getJSONObject("attributes").getString("qqq.io/created-by")).isEqualTo(AuthentikTestSupport.OPERATOR);
      JSONObject recovery = t.authentik.writeBodies.get(2);
      assertThat(recovery.getString("email_stage")).isEqualTo("11111111-1111-1111-1111-111111111111");
      assertThat(t.authentik.groupNamesOf(100)).containsExactly("kof-website-publishers");
   }



   /*******************************************************************************
    ** Create-user checks.
    *******************************************************************************/
   @Test
   void createUserRules() throws QException
   {
      AdminRequest base = AdminRequest.of(AdminAction.CREATE_USER, "", "b").with("username", "newbie").with("name", "New Bie").with("email", "newbie@example.test");
      assertThat(run(AdminRequest.of(AdminAction.CREATE_USER, "", "b").with("username", "sam").with("name", "n").with("email", "x@example.test")).message()).contains("already exists");
      assertThat(run(AdminRequest.of(AdminAction.CREATE_USER, "", "b").with("username", "x").with("name", "n").with("email", "sam@example.test")).message()).contains("email");
      assertThat(run(AdminRequest.of(AdminAction.CREATE_USER, "", "b").with("username", "x").with("name", "n").with("email", "not-an-email")).message()).contains("valid email");
      assertThat(run(AdminRequest.of(AdminAction.CREATE_USER, "", "b").with("username", "bad name!").with("name", "n").with("email", "a@example.test")).message()).contains("username");
      assertThat(run(base.with("groups", "kof-website-analysts")).message()).contains("do not hold");
      assertThat(run(AdminRequest.of(AdminAction.CREATE_USER, "", "b").with("username", "x").with("name", "n").with("email", "a@example.test").with("groups", "nope")).message()).contains("No group");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** If a step after the user exists fails, the message says the user was
    ** created and what to do next.
    *******************************************************************************/
   @Test
   void createUserPartialFailureIsExplained() throws QException
   {
      com.kingsrook.qbits.authentik.client.FixtureActionUtil.handler = request ->
      {
         if(request.getURI().getPath().endsWith("/recovery_email/"))
         {
            return (com.kingsrook.qbits.authentik.client.FixtureActionUtil.response(500, "{\"detail\":\"boom\"}"));
         }
         return (t.authentik.handle(request));
      };
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.CREATE_USER, "", "b").with("username", "newbie").with("name", "New Bie").with("email", "newbie@example.test"));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("was created").contains("Send password reset email");
      assertThat(rows(AuthentikLocalTables.ADMIN_ACTION).get(0).getValueString("status")).isEqualTo("FAILED");
   }



   /*******************************************************************************
    ** Invite a user: an invitation with the email, and its email.
    *******************************************************************************/
   @Test
   void inviteAndCancel() throws QException
   {
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.INVITE_USER, "", "b").with("email", "guest@example.test"));
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(t.changes().get(0)).isEqualTo("POST /stages/invitation/invitations/");
      assertThat(t.changes().get(1)).endsWith("/send_email/");
      JSONObject invitation = t.authentik.writeBodies.get(0);
      assertThat(invitation.getBoolean("single_use")).isTrue();
      assertThat(invitation.getJSONObject("fixed_data").getString("email")).isEqualTo("guest@example.test");
      assertThat(t.authentik.writeBodies.get(1).getJSONArray("email_addresses").getString(0)).isEqualTo("guest@example.test");

      String pk = t.authentik.invitations.keySet().iterator().next();
      assertThat(run(AdminRequest.of(AdminAction.CANCEL_INVITATION, pk, "b")).ok()).isTrue();
      assertThat(t.authentik.invitations).isEmpty();
   }



   /*******************************************************************************
    ** Deactivation is typed-confirmed, protected accounts are untouchable, and
    ** app passwords are revoked only when asked (and never API tokens).
    *******************************************************************************/
   @Test
   void deactivateAndReactivate() throws QException
   {
      t.authentik.tokens.put("sam", new java.util.ArrayList<>(List.of(
         new JSONObject().put("identifier", "sam-app").put("intent", "app_password"),
         new JSONObject().put("identifier", "sam-api").put("intent", "api"))));

      AuthentikAdmin.AdminResult untyped = run(AdminRequest.of(AdminAction.DEACTIVATE_USER, "3", "b"));
      assertThat(untyped.ok()).isFalse();
      assertThat(untyped.message()).contains("Type the username");
      assertThat(t.writes()).isEmpty();

      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.DEACTIVATE_USER, "3", "b").with("confirmText", "sam").with("revokeAppPasswords", true));
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(t.authentik.users.get(3).getBoolean("is_active")).isFalse();
      assertThat(t.changes()).containsExactly("PATCH /core/users/3/", "DELETE /core/tokens/sam-app/");
      assertThat(t.authentik.tokens.get("sam")).extracting(j -> j.getString("identifier")).containsExactly("sam-api");

      assertThat(run(AdminRequest.of(AdminAction.DEACTIVATE_USER, "3", "b").with("confirmText", "sam")).noChange()).isTrue();
      assertThat(run(AdminRequest.of(AdminAction.REACTIVATE_USER, "3", "b")).ok()).isTrue();
      assertThat(t.authentik.users.get(3).getBoolean("is_active")).isTrue();
      assertThat(run(AdminRequest.of(AdminAction.DEACTIVATE_USER, "4", "b").with("confirmText", "breakglass")).message()).containsIgnoringCase("protected");
   }



   /*******************************************************************************
    ** Edit a user: only changed fields are sent; a stale form is refused;
    ** invalid input is refused.
    *******************************************************************************/
   @Test
   void editUser() throws QException
   {
      String fingerprint = AuthentikSafety.userFingerprint(t.authentik.users.get(3));
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.EDIT_USER, "3", "b").with("name", "Samuel").with("email", "sam@example.test")
         .with("path", "users").with("expectedFingerprint", fingerprint));
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(t.authentik.users.get(3).getString("name")).isEqualTo("Samuel");

      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "b").with("name", "Again").with("expectedFingerprint", fingerprint)).message()).contains("was changed");
      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "b").with("email", "second@example.test")).message()).contains("Another user");
      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "b").with("name", "")).message()).contains("name cannot be empty");
      assertThat(run(AdminRequest.of(AdminAction.EDIT_USER, "3", "b")).noChange()).isTrue();
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // credentials and sessions
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Password reset is Authentik's own email; MFA reset deletes every device
    ** (typed confirmation); app passwords only; sessions via bulk delete.
    *******************************************************************************/
   @Test
   void credentialActions() throws QException
   {
      assertThat(run(AdminRequest.of(AdminAction.SEND_RECOVERY_EMAIL, "3", "b")).ok()).isTrue();
      assertThat(t.changes().get(0)).isEqualTo("POST /core/users/3/recovery_email/");

      t.authentik.devices.put(3, new java.util.ArrayList<>(List.of(
         new JSONObject().put("pk", "11").put("type", "authentik_stages_authenticator_totp.totpdevice"),
         new JSONObject().put("pk", "12").put("type", "authentik_stages_authenticator_webauthn.webauthndevice"))));
      assertThat(run(AdminRequest.of(AdminAction.RESET_MFA, "3", "b")).message()).contains("Type the username");
      AuthentikAdmin.AdminResult mfa = run(AdminRequest.of(AdminAction.RESET_MFA, "3", "b").with("confirmText", "sam"));
      assertThat(mfa.ok()).as(mfa.message()).isTrue();
      assertThat(t.changes()).contains("DELETE /authenticators/admin/totp/11/", "DELETE /authenticators/admin/webauthn/12/");
      assertThat(run(AdminRequest.of(AdminAction.RESET_MFA, "3", "b").with("confirmText", "sam")).noChange()).isTrue();

      t.authentik.tokens.put("sam", new java.util.ArrayList<>(List.of(new JSONObject().put("identifier", "sam-api").put("intent", "api"))));
      assertThat(run(AdminRequest.of(AdminAction.REVOKE_APP_PASSWORDS, "3", "b").with("confirmText", "sam")).noChange()).isTrue();
   }



   /*******************************************************************************
    ** Revoke sessions has nothing to do for a user with no sessions (the fake
    ** has none), and refuses protected users.
    *******************************************************************************/
   @Test
   void sessionsRules() throws QException
   {
      assertThat(run(AdminRequest.of(AdminAction.REVOKE_SESSIONS, "3", "b")).noChange()).isTrue();
      assertThat(run(AdminRequest.of(AdminAction.REVOKE_SESSIONS, "4", "b")).message()).containsIgnoringCase("protected");
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // gates: permission, feature, read-only, reason, audit
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Without the action's authentik.* permission nothing happens.
    *******************************************************************************/
   @Test
   void permissionIsRequired() throws QException
   {
      t.loginAs(AuthentikTestSupport.OPERATOR, IdentityPermission.USERS_READ);
      AuthentikAdmin.AdminResult result = run(add(3, "kof-website-publishers"));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("authentik.memberships.manage");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Read-only mode and disabled features refuse every write.
    *******************************************************************************/
   @Test
   void readOnlyAndFeatureFlags() throws QException
   {
      t.config.setReadOnly(true);
      assertThat(run(add(3, "kof-website-publishers")).message()).contains("read-only");
      t.config.setReadOnly(false);

      AdminTestSupport readOnlyFeatures = AdminTestSupport.create(EnumSet.of(AuthentikFeature.READ));
      AuthentikAdmin.AdminResult result = readOnlyFeatures.admin().execute(AdminRequest.of(AdminAction.ADD_MEMBER, readOnlyFeatures.authentik.pk("kof-website-publishers") + ":3", "b"));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("not enabled");
      assertThat(readOnlyFeatures.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Every change needs a reason.
    *******************************************************************************/
   @Test
   void reasonIsRequired() throws QException
   {
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.ADD_MEMBER, t.authentik.pk("kof-website-publishers") + ":3", " "));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("reason");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** If the audit row cannot be written, Authentik is not called.
    *******************************************************************************/
   @Test
   void noAuditRowNoCall() throws QException
   {
      t.qInstance.getTables().remove(t.config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION));
      assertThatThrownBy(() -> run(add(3, "kof-website-publishers"))).isInstanceOf(Exception.class);
      assertThat(t.writes()).isEmpty();
      assertThat(t.authentik.groupNamesOf(3)).isEmpty();
   }



   /*******************************************************************************
    ** A failed Authentik call is audited as FAILED with the (redacted) reason and
    ** reported to the operator.
    *******************************************************************************/
   @Test
   void failedCallIsAudited() throws QException
   {
      com.kingsrook.qbits.authentik.client.FixtureActionUtil.handler = request ->
         request.getMethod().equals("POST") && request.getURI().getPath().endsWith("/add_user/")
            ? com.kingsrook.qbits.authentik.client.FixtureActionUtil.response(403, "{\"detail\":\"no permission " + AuthentikTestSupport.TEST_TOKEN + "\"}")
            : t.authentik.handle(request);
      AuthentikAdmin.AdminResult result = run(add(3, "kof-website-publishers"));

      assertThat(result.ok()).isFalse();
      assertThat(result.message()).doesNotContain(AuthentikTestSupport.TEST_TOKEN);
      QRecord row = rows(AuthentikLocalTables.ADMIN_ACTION).get(0);
      assertThat(row.getValueString("status")).isEqualTo("FAILED");
      assertThat(row.getValueString("errorMessage")).doesNotContain(AuthentikTestSupport.TEST_TOKEN);
   }



   /*******************************************************************************
    ** Nothing can change Authentik without the guard's authorization: the util
    ** refuses a write with none, and a system session cannot get one.
    *******************************************************************************/
   @Test
   void writesNeedTheGuard() throws QException
   {
      assertThatThrownBy(() -> t.admin().getUtil().write(null, "POST", "/core/groups/x/add_user/", new JSONObject().put("pk", 1)))
         .hasMessageContaining("through the guard");

      com.kingsrook.qqq.backend.core.context.QContext.init(t.qInstance, new com.kingsrook.qqq.backend.core.model.session.QSystemUserSession());
      assertThatThrownBy(() -> t.admin().getUtil().getRuntime().getGuard().authorize(AdminAction.ADD_MEMBER)).hasMessageContaining("System sessions");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Bootstrap operators hold every authentik.* permission even when their
    ** groups are wrong (the lockout escape hatch), but still cannot grant what
    ** they do not hold elsewhere.
    *******************************************************************************/
   @Test
   void bootstrapOperatorSubjectsHoldIdentityPermissions() throws QException
   {
      t.authentik.groupByName("identity-admins").put("users", new JSONArray());
      t.config.withBootstrapOperatorSubjects("1");
      t.authentik.groupByName("kof-website-publishers").put("users", new JSONArray());

      AuthentikAdmin.AdminResult grantIdentity = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, t.authentik.pk("kof-website-analysts"), "b")
         .with("permissions", "authentik.users.read").with("appAccess", ""));
      assertThat(grantIdentity.ok()).as(grantIdentity.message()).isTrue();
      assertThat(run(add(3, "kof-website-publishers")).message()).contains("cms.publish.hasAccess");
   }

}
