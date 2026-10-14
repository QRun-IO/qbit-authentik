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
 ** Contract test (h): the bootstrap blueprint on an EMPTY Authentik, ordered
 ** by its metaapplyblueprint entry, applies cleanly alongside the
 ** infrastructure blueprint, and creates exactly the bootstrap objects of
 ** DESIGN.md section 4.3. Also open point (i): the role's GLOBAL permissions
 ** come from attrs.permissions on a present role entry.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(10)
class BootstrapBlueprintIT
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
    ** Both blueprints, present in /blueprints/custom at first boot, applied.
    *******************************************************************************/
   @Test
   void bothBlueprintsAppliedOnEmptyInstance()
   {
      assertThat(stack.blueprint(INFRA_BLUEPRINT).getString("status")).isEqualTo("successful");
      assertThat(stack.blueprint(BOOTSTRAP_BLUEPRINT).getString("status")).isEqualTo("successful");
   }



   /*******************************************************************************
    ** The service account: type, path, protected marker, role, and no groups.
    *******************************************************************************/
   @Test
   void serviceAccountCreatedWithRoleAndNoGroups()
   {
      JSONObject user = admin.first("/core/users/?username=" + SERVICE_ACCOUNT + "&include_roles=true&include_groups=true");
      assertThat(user.getString("type")).isEqualTo("service_account");
      assertThat(user.getString("path")).isEqualTo("service-accounts/qqq");
      assertThat(user.getJSONObject("attributes").getBoolean("qqq.io/protected")).isTrue();
      assertThat(user.getBoolean("is_superuser")).isFalse();
      assertThat(user.getJSONArray("groups")).isEmpty();
      assertThat(names(user.getJSONArray("roles_obj"))).containsExactly(SERVICE_ACCOUNT);
   }



   /*******************************************************************************
    ** Break-glass: a protected superuser through authentik Admins.
    *******************************************************************************/
   @Test
   void breakGlassIsProtectedSuperuser()
   {
      JSONObject user = admin.first("/core/users/?username=" + BREAK_GLASS + "&include_groups=true");
      assertThat(user.getBoolean("is_superuser")).isTrue();
      assertThat(user.getJSONObject("attributes").getBoolean("qqq.io/protected")).isTrue();
      assertThat(names(user.getJSONArray("groups_obj"))).containsExactly(AuthentikTestStack.SUPERUSER_GROUP);
   }



   /*******************************************************************************
    ** The four seed groups exist, with no members; only identity-admins has
    ** attributes, and drafters has no app access (owner decision pending).
    *******************************************************************************/
   @Test
   void seedGroupsCreatedWithoutMembers()
   {
      for(String name : List.of("identity-admins", "kof22-admins", "kof-website-publishers", "kof-website-drafters"))
      {
         JSONObject group = admin.first("/core/groups/?name=" + name + "&include_users=true");
         assertThat(group).as(name).isNotNull();
         assertThat(group.getBoolean("is_superuser")).as(name).isFalse();
         assertThat(group.getJSONArray("parents")).as(name).isEmpty();
      }

      JSONObject identityAdmins = admin.first("/core/groups/?name=identity-admins").getJSONObject("attributes");
      assertThat(identityAdmins.getJSONArray("qqq.io/permissions").toList()).containsExactly("authentik.*");
      assertThat(identityAdmins.getJSONArray("qqq.io/app-access").toList()).containsExactly(AuthentikTestStack.APP_SLUG);

      JSONObject drafters = admin.first("/core/groups/?name=kof-website-drafters").getJSONObject("attributes");
      assertThat(drafters.has("qqq.io/app-access")).isFalse();
   }



   /*******************************************************************************
    ** Open point (i): global permissions from attrs.permissions, plus the
    ** object permission on the recovery email stage from `permissions:`.
    *******************************************************************************/
   @Test
   void roleHasGlobalAndObjectPermissions()
   {
      TestApi sa = stack.serviceAccount();
      assertThat(sa.get("/core/users/?page_size=1").status()).isEqualTo(200);
      assertThat(sa.get("/core/groups/?page_size=1").status()).isEqualTo(200);
      assertThat(sa.get("/events/events/?page_size=1").status()).isEqualTo(200);
      assertThat(sa.get("/managed/blueprints/?page_size=1").status()).isEqualTo(200);
      assertThat(sa.get("/core/authenticated_sessions/?page_size=1").status()).isEqualTo(200);

      JSONObject stage = admin.first("/stages/email/?name=kof22-recovery-email");
      assertThat(sa.get("/stages/email/" + stage.getString("pk") + "/").status()).isEqualTo(200);

      // The production v1 role reads all token metadata but never other keys.
      assertThat(sa.get("/core/tokens/?page_size=1").status()).isEqualTo(200);
      assertThat(sa.get("/core/tokens/" + AuthentikTestStack.SA_TOKEN_ID + "/view_key/").status()).isEqualTo(403);
      TestApi.Response group = sa.post("/core/groups/", new JSONObject().put("name", "bootstrap-write-probe"));
      assertThat(group.status()).isEqualTo(201);
      try
      {
         assertThat(sa.delete("/core/groups/" + group.json().getString("pk") + "/").status()).isEqualTo(403);
      }
      finally
      {
         assertThat(admin.delete("/core/groups/" + group.json().getString("pk") + "/").status()).isEqualTo(204);
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   static List<String> names(JSONArray array)
   {
      List<String> rs = new ArrayList<>();
      for(int i = 0; i < array.length(); i++)
      {
         rs.add(array.getJSONObject(i).getString("name"));
      }
      return (rs);
   }

}
