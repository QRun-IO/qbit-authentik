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


import java.util.List;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static com.kingsrook.qbits.authentik.contract.AuthentikTestStack.BREAK_GLASS;
import static com.kingsrook.qbits.authentik.contract.AuthentikTestStack.SERVICE_ACCOUNT;
import static com.kingsrook.qbits.authentik.contract.AuthentikTestStack.SUPERUSER_GROUP;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Contract test (b) and open point (ii): what Authentik itself refuses the
 ** qbit's service account, holding the phase 2/3 write permissions it will
 ** eventually get, but never enable_group_superuser.
 **
 ** ESCALATION is refused in every form (add to a superuser group or a
 ** descendant, re-parent under one, user groups PATCH, group users PATCH,
 ** create under one, set is_superuser).
 **
 ** LOCKOUT is NOT refused: with remove_user_from_group / change_user /
 ** change_group the service account can remove a superuser from the superuser
 ** group, deactivate break-glass, strip qqq.io/protected, or rename the
 ** superuser group. Those tests pin today's behaviour so an Authentik change
 ** is noticed; the qbit's guard is the only control (DESIGN.md section 5.1).
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(50)
class SuperuserFloorIT
{
   private static final List<String> PHASE_2_3_PERMISSIONS = List.of(
      "authentik_core.add_user_to_group", "authentik_core.remove_user_from_group",
      "authentik_core.add_group", "authentik_core.change_group", "authentik_core.add_user", "authentik_core.change_user");

   private static AuthentikTestStack stack;
   private static TestApi            admin;
   private static TestApi            sa;
   private static String             roleUuid;
   private static int                probeUser;
   private static String             superuserGroup;
   private static String             childOfSuperuser;
   private static String             plainGroup;



   /*******************************************************************************
    ** Grant the later-phase write permissions (test-only, additive) and create
    ** probe objects.
    *******************************************************************************/
   @BeforeAll
   static void beforeAll()
   {
      stack = AuthentikTestStack.get();
      admin = stack.admin();
      sa = stack.serviceAccount();

      roleUuid = admin.first("/rbac/roles/?name=" + SERVICE_ACCOUNT).getString("pk");
      admin.post("/rbac/permissions/assigned_by_roles/" + roleUuid + "/assign/", new JSONObject().put("permissions", new JSONArray(PHASE_2_3_PERMISSIONS)));

      admin.post("/core/users/", new JSONObject().put("username", "floor.probe").put("name", "Floor Probe").put("type", "internal").put("path", "users"));
      probeUser = admin.userPk("floor.probe");
      superuserGroup = admin.groupPk(SUPERUSER_GROUP);
      admin.post("/core/groups/", new JSONObject().put("name", "floor-child-of-admins").put("parents", new JSONArray().put(superuserGroup)));
      childOfSuperuser = admin.groupPk("floor-child-of-admins");
      admin.post("/core/groups/", new JSONObject().put("name", "floor-plain"));
      plainGroup = admin.groupPk("floor-plain");
   }



   /*******************************************************************************
    ** Remove the test-only grants again.
    *******************************************************************************/
   @AfterAll
   static void afterAll()
   {
      if(admin != null && roleUuid != null)
      {
         admin.patch("/rbac/permissions/assigned_by_roles/" + roleUuid + "/unassign/", new JSONObject().put("permissions", new JSONArray(PHASE_2_3_PERMISSIONS)));
      }
   }



   /*******************************************************************************
    ** Sanity: an ordinary membership change is allowed.
    *******************************************************************************/
   @Test
   void ordinaryMembershipAllowed()
   {
      assertThat(sa.post("/core/groups/" + plainGroup + "/add_user/", new JSONObject().put("pk", probeUser)).status()).isEqualTo(204);
      assertThat(sa.post("/core/groups/" + plainGroup + "/remove_user/", new JSONObject().put("pk", probeUser)).status()).isEqualTo(204);
   }



   /*******************************************************************************
    ** (b) add_user to a superuser group, or to a group under one: 403.
    *******************************************************************************/
   @Test
   void addToSuperuserAncestryRefused()
   {
      TestApi.Response direct = sa.post("/core/groups/" + superuserGroup + "/add_user/", new JSONObject().put("pk", probeUser));
      assertThat(direct.status()).isEqualTo(403);
      assertThat(direct.body()).contains("superuser group");

      TestApi.Response child = sa.post("/core/groups/" + childOfSuperuser + "/add_user/", new JSONObject().put("pk", probeUser));
      assertThat(child.status()).isEqualTo(403);
   }



   /*******************************************************************************
    ** (b) / open point (ii): re-parenting under a superuser group or one of its
    ** descendants, creating a group under one, and setting is_superuser: 400.
    *******************************************************************************/
   @Test
   void reparentUnderSuperuserRefused()
   {
      TestApi.Response underAdmins = sa.patch("/core/groups/" + plainGroup + "/", new JSONObject().put("parents", new JSONArray().put(superuserGroup)));
      assertThat(underAdmins.status()).isEqualTo(400);
      assertThat(underAdmins.body()).contains("superuser parent group");

      TestApi.Response underChild = sa.patch("/core/groups/" + plainGroup + "/", new JSONObject().put("parents", new JSONArray().put(childOfSuperuser)));
      assertThat(underChild.status()).isEqualTo(400);

      TestApi.Response create = sa.post("/core/groups/", new JSONObject().put("name", "floor-new-under-admins").put("parents", new JSONArray().put(superuserGroup)));
      assertThat(create.status()).isEqualTo(400);

      TestApi.Response flag = sa.patch("/core/groups/" + plainGroup + "/", new JSONObject().put("is_superuser", true));
      assertThat(flag.status()).isEqualTo(400);

      TestApi.Response unflag = sa.patch("/core/groups/" + superuserGroup + "/", new JSONObject().put("is_superuser", false));
      assertThat(unflag.status()).isEqualTo(400);
   }



   /*******************************************************************************
    ** (b) the bulk forms: user.groups and group.users PATCH.
    *******************************************************************************/
   @Test
   void bulkMembershipFormsRefused()
   {
      assertThat(sa.patch("/core/users/" + probeUser + "/", new JSONObject().put("groups", new JSONArray().put(superuserGroup))).status()).isEqualTo(400);
      assertThat(sa.patch("/core/groups/" + superuserGroup + "/", new JSONObject().put("users", new JSONArray().put(probeUser))).status()).isEqualTo(400);
   }



   /*******************************************************************************
    ** Tokens, impersonation, deletion and recovery links stay out of reach.
    *******************************************************************************/
   @Test
   void hardFloorEndpointsRefused()
   {
      assertThat(sa.post("/core/users/" + probeUser + "/impersonate/", new JSONObject().put("reason", "contract test")).status()).isEqualTo(403);
      assertThat(sa.delete("/core/users/" + probeUser + "/").status()).isEqualTo(403);
      assertThat(sa.post("/core/users/" + probeUser + "/recovery/", new JSONObject()).status()).isEqualTo(403);
   }



   /*******************************************************************************
    ** Residual risk (pinned): any authenticated user, the service account
    ** included, may create API tokens FOR ITSELF without add_token; a `user`
    ** in the request is ignored. A compromised QQQ could mint a second
    ** service-account token that outlives a rotation, so the drift report
    ** flags service-account tokens beyond the expected one. Creating a token
    ** for another user is not possible.
    *******************************************************************************/
   @Test
   void serviceAccountCanMintTokensOnlyForItself()
   {
      int saPk = admin.userPk(SERVICE_ACCOUNT);
      try
      {
         TestApi.Response created = sa.post("/core/tokens/", new JSONObject().put("identifier", "floor-token").put("user", probeUser).put("intent", "api").put("expiring", true));
         assertThat(created.status()).isEqualTo(201);
         JSONObject token = admin.getOk("/core/tokens/floor-token/");
         assertThat(token.getInt("user")).as("owner forced to the caller").isEqualTo(saPk);

         assertThat(sa.get("/core/tokens/floor-token/view_key/").status()).as("and it can read that token's key").isEqualTo(200);
      }
      finally
      {
         admin.delete("/core/tokens/floor-token/");
      }
   }



   /*******************************************************************************
    ** Residual risk (pinned): Authentik does NOT stop the lockout direction.
    ** Each change is reverted immediately by the admin.
    *******************************************************************************/
   @Test
   void lockoutDirectionIsNotRefusedByAuthentik()
   {
      int breakGlass = admin.userPk(BREAK_GLASS);
      try
      {
         assertThat(sa.post("/core/groups/" + superuserGroup + "/remove_user/", new JSONObject().put("pk", breakGlass)).status()).isEqualTo(204);
      }
      finally
      {
         admin.post("/core/groups/" + superuserGroup + "/add_user/", new JSONObject().put("pk", breakGlass));
      }

      try
      {
         assertThat(sa.patch("/core/users/" + breakGlass + "/", new JSONObject().put("is_active", false)).status()).isEqualTo(200);
      }
      finally
      {
         admin.patch("/core/users/" + breakGlass + "/", new JSONObject().put("is_active", true));
      }

      try
      {
         assertThat(sa.patch("/core/users/" + breakGlass + "/", new JSONObject().put("attributes", new JSONObject())).status()).isEqualTo(200);
      }
      finally
      {
         admin.patch("/core/users/" + breakGlass + "/", new JSONObject().put("attributes", new JSONObject().put("qqq.io/protected", true)));
      }

      try
      {
         assertThat(sa.patch("/core/groups/" + superuserGroup + "/", new JSONObject().put("name", SUPERUSER_GROUP + " renamed")).status()).isEqualTo(200);
      }
      finally
      {
         admin.patch("/core/groups/" + superuserGroup + "/", new JSONObject().put("name", SUPERUSER_GROUP));
      }

      JSONObject restored = admin.first("/core/users/?username=" + BREAK_GLASS + "&include_groups=true");
      assertThat(restored.getBoolean("is_active")).isTrue();
      assertThat(restored.getBoolean("is_superuser")).isTrue();
      assertThat(restored.getJSONObject("attributes").getBoolean("qqq.io/protected")).isTrue();
   }

}
