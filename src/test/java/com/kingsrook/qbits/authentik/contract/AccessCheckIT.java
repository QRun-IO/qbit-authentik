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


import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static com.kingsrook.qbits.authentik.contract.AuthentikTestStack.APP_SLUG;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Open point (iii): what the access matrix can rely on.
 **
 ** - check_access honours for_user ONLY for superusers. For the service
 **   account it silently evaluates the CALLER instead: the answer would be
 **   wrong, not refused. No permission fixes this, and the service account must
 **   never be a superuser, so the qbit computes access itself.
 ** - POST /policies/all/{uuid}/test/ (the alternative) fails with HTTP 500
 **   (WrongAppError) for non-superusers on expression policies in 2026.8.3.
 ** - The application LIST shows a non-superuser only the apps it can itself
 **   access (here: none); GET by slug works with view_application. So
 **   applicationsInScope must be explicit slugs.
 ** - The app's policy bindings are readable with view_policybinding.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(40)
class AccessCheckIT
{
   private static TestApi admin;
   private static TestApi sa;
   private static int     publisher;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeAll
   static void beforeAll()
   {
      AuthentikTestStack stack = AuthentikTestStack.get();
      admin = stack.admin();
      sa = stack.serviceAccount();
      admin.post("/core/users/", new JSONObject().put("username", "access.publisher").put("name", "Access Publisher").put("type", "internal").put("path", "users"));
      publisher = admin.userPk("access.publisher");
      admin.post("/core/groups/" + admin.groupPk("kof-website-publishers") + "/add_user/", new JSONObject().put("pk", publisher));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void checkAccessForUserIsIgnoredForNonSuperusers()
   {
      assertThat(admin.getOk("/core/applications/" + APP_SLUG + "/check_access/?for_user=" + publisher).getBoolean("passing")).isTrue();

      TestApi.Response asServiceAccount = sa.get("/core/applications/" + APP_SLUG + "/check_access/?for_user=" + publisher);
      assertThat(asServiceAccount.status()).isEqualTo(200);
      assertThat(asServiceAccount.json().getBoolean("passing")).as("evaluated for the service account itself, not for_user").isFalse();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void policyTestEndpointFailsForNonSuperusers()
   {
      String policy = admin.first("/policies/all/?search=kof22-require-admins-group").getString("pk");
      assertThat(admin.post("/policies/all/" + policy + "/test/", new JSONObject().put("user", publisher)).json().getBoolean("passing")).isTrue();

      String           role       = admin.first("/rbac/roles/?name=" + AuthentikTestStack.SERVICE_ACCOUNT).getString("pk");
      org.json.JSONArray permission = new org.json.JSONArray().put("authentik_policies.view_policy");
      admin.post("/rbac/permissions/assigned_by_roles/" + role + "/assign/", new JSONObject().put("permissions", permission));
      try
      {
         assertThat(sa.post("/policies/all/" + policy + "/test/", new JSONObject().put("user", publisher)).status()).isEqualTo(500);
      }
      finally
      {
         admin.patch("/rbac/permissions/assigned_by_roles/" + role + "/unassign/", new JSONObject().put("permissions", permission));
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void applicationsAreReadableBySlugButNotListed()
   {
      assertThat(sa.getOk("/core/applications/").getJSONArray("results")).isEmpty();
      assertThat(sa.getOk("/core/applications/?superuser_full_list=true").getJSONArray("results")).isEmpty();

      JSONObject application = sa.getOk("/core/applications/" + APP_SLUG + "/");
      assertThat(application.getString("policy_engine_mode")).isEqualTo("any");

      JSONObject bindings = sa.getOk("/policies/bindings/?target=" + application.getString("pbm_uuid"));
      assertThat(bindings.getJSONArray("results").length()).isEqualTo(1);
      assertThat(bindings.getJSONArray("results").getJSONObject(0).getJSONObject("policy_obj").getString("name")).isEqualTo("kof22-require-admins-group");
   }

}
