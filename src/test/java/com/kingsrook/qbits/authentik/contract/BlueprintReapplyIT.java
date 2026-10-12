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

package com.kingsrook.qbits.authentik.contract;


import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static com.kingsrook.qbits.authentik.contract.AuthentikTestStack.BOOTSTRAP_BLUEPRINT;
import static com.kingsrook.qbits.authentik.contract.AuthentikTestStack.BREAK_GLASS;
import static com.kingsrook.qbits.authentik.contract.AuthentikTestStack.INFRA_BLUEPRINT;
import static com.kingsrook.qbits.authentik.contract.AuthentikTestStack.SERVICE_ACCOUNT;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Contract tests (c) and (d): the whole design rests on these.
 **
 ** (c) With identity objects declared `state: created` and no member lists,
 **     re-applying BOTH blueprints changes nothing made through the API or
 **     the UI (memberships, group attributes, the service account's role
 **     assignment), and re-asserts the qbit role's global permissions after
 **     one was removed by hand.
 **
 ** (d) The hazard the cluster-gitops lint exists for: a `present` group with
 **     `users:` wipes API-added members, a `present` user with `groups:`
 **     wipes API-added memberships (today's james.maes entry), and `present`
 **     `attributes:` wipes qqq.io/* edits, on every apply.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(30)
class BlueprintReapplyIT
{
   private static AuthentikTestStack stack;
   private static TestApi            admin;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeAll
   static void beforeAll()
   {
      stack = AuthentikTestStack.get();
      admin = stack.admin();
   }



   /*******************************************************************************
    ** (c)
    *******************************************************************************/
   @Test
   void apiEditsSurviveReapplyOfCreatedEntries()
   {
      admin.post("/core/users/", new JSONObject().put("username", "reapply.member").put("name", "Reapply Member").put("type", "internal").put("path", "users"));
      int member = admin.userPk("reapply.member");

      ///////////////////////////////////////////////////////////////////////
      // edits as QQQ (the service account) or the UI (admin) would make  //
      ///////////////////////////////////////////////////////////////////////
      String identityAdmins = admin.groupPk("identity-admins");
      String kof22Admins    = admin.groupPk("kof22-admins");
      assertThat(admin.post("/core/groups/" + identityAdmins + "/add_user/", new JSONObject().put("pk", member)).status()).isEqualTo(204);
      assertThat(admin.post("/core/groups/" + kof22Admins + "/add_user/", new JSONObject().put("pk", member)).status()).isEqualTo(204);
      assertThat(admin.patch("/core/groups/" + kof22Admins + "/", new JSONObject().put("attributes",
         new JSONObject().put("qqq.io/permissions", new JSONArray().put("adminEsb.hasAccess")).put("qqq.io/app-access", new JSONArray().put("kof22-website-prod")))).status()).isEqualTo(200);
      assertThat(admin.patch("/core/groups/" + identityAdmins + "/", new JSONObject().put("attributes",
         new JSONObject().put("qqq.io/permissions", new JSONArray().put("identity.*").put("cms.publish")).put("qqq.io/app-access", new JSONArray().put("kof22-website-prod")))).status()).isEqualTo(200);

      String roleUuid = admin.first("/rbac/roles/?name=" + SERVICE_ACCOUNT).getString("pk");
      try
      {
         assertThat(admin.patch("/rbac/permissions/assigned_by_roles/" + roleUuid + "/unassign/", new JSONObject().put("permissions", new JSONArray().put("authentik_core.view_user"))).status()).isEqualTo(204);
         assertThat(stack.serviceAccount().get("/core/users/?page_size=1").status()).as("view_user removed in the UI").isEqualTo(403);
      }
      finally
      {
         stack.applyAndWait(INFRA_BLUEPRINT);
         stack.applyAndWait(BOOTSTRAP_BLUEPRINT);
      }

      assertThat(memberNames("identity-admins")).contains("reapply.member");
      assertThat(memberNames("kof22-admins")).contains("reapply.member");
      assertThat(admin.first("/core/groups/?name=kof22-admins").getJSONObject("attributes").getJSONArray("qqq.io/permissions").toList()).containsExactly("adminEsb.hasAccess");
      assertThat(admin.first("/core/groups/?name=identity-admins").getJSONObject("attributes").getJSONArray("qqq.io/permissions").toList()).containsExactly("identity.*", "cms.publish");

      ////////////////////////////////////////////////////////////////////////
      // role permission re-asserted; role assignment and break-glass kept //
      ////////////////////////////////////////////////////////////////////////
      assertThat(stack.serviceAccount().get("/core/users/?page_size=1").status()).as("view_user re-asserted by the re-apply").isEqualTo(200);
      JSONObject serviceAccount = admin.first("/core/users/?username=" + SERVICE_ACCOUNT + "&include_roles=true");
      assertThat(BootstrapBlueprintIT.names(serviceAccount.getJSONArray("roles_obj"))).containsExactly(SERVICE_ACCOUNT);
      assertThat(admin.first("/core/users/?username=" + BREAK_GLASS).getBoolean("is_superuser")).isTrue();

      ///////////////////////////////////////////////////////////
      // put the seed groups back as the bootstrap created them //
      ///////////////////////////////////////////////////////////
      admin.post("/core/groups/" + identityAdmins + "/remove_user/", new JSONObject().put("pk", member));
      admin.post("/core/groups/" + kof22Admins + "/remove_user/", new JSONObject().put("pk", member));
      admin.patch("/core/groups/" + kof22Admins + "/", new JSONObject().put("attributes", new JSONObject()));
      admin.patch("/core/groups/" + identityAdmins + "/", new JSONObject().put("attributes",
         new JSONObject().put("qqq.io/permissions", new JSONArray().put("identity.*")).put("qqq.io/app-access", new JSONArray().put("kof22-website-prod"))));
   }



   /*******************************************************************************
    ** (d)
    *******************************************************************************/
   @Test
   void presentEntriesWipeApiEdits()
   {
      String yaml = """
         version: 1
         metadata:
           name: lint-demo-present
         entries:
           - model: authentik_core.group
             state: present
             id: demo-group
             identifiers:
               name: lint-demo-group
             attrs:
               attributes:
                 note: declared in git
               users:
                 - !Find [authentik_core.user, [username, akadmin]]
           - model: authentik_core.user
             state: present
             identifiers:
               username: lint.demo.user
             attrs:
               name: Lint Demo User
               type: internal
               path: users
               groups:
                 - !KeyOf demo-group
         """;
      stack.createContentBlueprint("lint-demo-present", yaml);

      admin.post("/core/users/", new JSONObject().put("username", "lint.added").put("name", "Added Via API").put("type", "internal").put("path", "users"));
      int    added      = admin.userPk("lint.added");
      int    demoUser   = admin.userPk("lint.demo.user");
      String demoGroup  = admin.groupPk("lint-demo-group");
      String publishers = admin.groupPk("kof-website-publishers");

      assertThat(admin.post("/core/groups/" + demoGroup + "/add_user/", new JSONObject().put("pk", added)).status()).isEqualTo(204);
      assertThat(admin.post("/core/groups/" + publishers + "/add_user/", new JSONObject().put("pk", demoUser)).status()).isEqualTo(204);
      assertThat(admin.patch("/core/groups/" + demoGroup + "/", new JSONObject().put("attributes", new JSONObject().put("note", "declared in git").put("qqq.io/permissions", new JSONArray().put("cms.publish")))).status()).isEqualTo(200);
      assertThat(memberNames("lint-demo-group")).contains("lint.added");

      stack.applyAndWait("lint-demo-present");

      assertThat(memberNames("lint-demo-group")).as("present users: replaces the member set").doesNotContain("lint.added").contains("akadmin");
      assertThat(memberNames("kof-website-publishers")).as("present groups: on a user replaces its memberships").doesNotContain("lint.demo.user");
      assertThat(admin.first("/core/groups/?name=lint-demo-group").getJSONObject("attributes").has("qqq.io/permissions")).as("present attributes: replaces the dict").isFalse();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<String> memberNames(String group)
   {
      JSONArray    users = admin.first("/core/groups/?name=" + TestApi.encode(group) + "&include_users=true").getJSONArray("users_obj");
      List<String> rs    = new ArrayList<>();
      for(int i = 0; i < users.length(); i++)
      {
         rs.add(users.getJSONObject(i).getString("username"));
      }
      return (rs);
   }

}
