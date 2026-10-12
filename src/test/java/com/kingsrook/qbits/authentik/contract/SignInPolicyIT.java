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
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static com.kingsrook.qbits.authentik.contract.AuthentikTestStack.APP_SLUG;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** The proposed cluster-gitops infrastructure changes, on the real importer:
 ** - the attribute-driven sign-in policy (qqq.io/app-access, inherited from
 **   parent groups, string or list, no substring matches) with the group-name
 **   fallback (DESIGN.md section 4.4 step 2), evaluated by the admin's
 **   check_access?for_user (superusers may use for_user);
 ** - the webhook plumbing (section 7.1) exists and is INERT: its rule has no
 **   destination, so Authentik creates no notifications (events/models.py
 **   NotificationRule.destination_users yields nobody).
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(45)
class SignInPolicyIT
{
   private static TestApi admin;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeAll
   static void beforeAll()
   {
      admin = AuthentikTestStack.get().admin();
   }



   /*******************************************************************************
    ** Create a user in a new group with the given attributes (and parent).
    *******************************************************************************/
   private int userInGroup(String name, JSONObject attributes, String parentPk)
   {
      JSONObject group = new JSONObject().put("name", "signin-" + name).put("attributes", attributes);
      if(parentPk != null)
      {
         group.put("parents", new JSONArray().put(parentPk));
      }
      admin.post("/core/groups/", group);
      admin.post("/core/users/", new JSONObject().put("username", "signin." + name).put("name", "Sign-in " + name).put("type", "internal").put("path", "users"));
      int user = admin.userPk("signin." + name);
      admin.post("/core/groups/" + admin.groupPk("signin-" + name) + "/add_user/", new JSONObject().put("pk", user));
      return (user);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private boolean passes(int user)
   {
      return (admin.getOk("/core/applications/" + APP_SLUG + "/check_access/?for_user=" + user).getBoolean("passing"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void appAccessAttributeGrantsSignIn()
   {
      assertThat(passes(userInGroup("list", new JSONObject().put("qqq.io/app-access", new JSONArray().put("other-app").put(APP_SLUG)), null))).isTrue();
      assertThat(passes(userInGroup("string", new JSONObject().put("qqq.io/app-access", APP_SLUG), null))).isTrue();
      assertThat(passes(userInGroup("prefix", new JSONObject().put("qqq.io/app-access", APP_SLUG + "-old"), null))).as("no substring match").isFalse();
      assertThat(passes(userInGroup("none", new JSONObject(), null))).isFalse();

      String parent = admin.groupPk("signin-list");
      assertThat(passes(userInGroup("child", new JSONObject(), parent))).as("inherited from a parent group").isTrue();
   }



   /*******************************************************************************
    ** Transition fallback by group name; drafters get nothing until the owner
    ** sets qqq.io/app-access on that group.
    *******************************************************************************/
   @Test
   void groupNameFallbackAndDrafters()
   {
      admin.post("/core/users/", new JSONObject().put("username", "signin.fallback").put("name", "Fallback").put("type", "internal").put("path", "users"));
      int fallback = admin.userPk("signin.fallback");
      admin.post("/core/groups/" + admin.groupPk("kof22-admins") + "/add_user/", new JSONObject().put("pk", fallback));
      assertThat(passes(fallback)).isTrue();

      admin.post("/core/users/", new JSONObject().put("username", "signin.drafter").put("name", "Drafter").put("type", "internal").put("path", "users"));
      int drafter = admin.userPk("signin.drafter");
      admin.post("/core/groups/" + admin.groupPk("kof-website-drafters") + "/add_user/", new JSONObject().put("pk", drafter));
      assertThat(passes(drafter)).isFalse();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void webhookPlumbingIsPresentAndInert()
   {
      JSONObject transport = admin.first("/events/transports/?name=qqq-kof22-admin");
      assertThat(transport.getString("mode")).isEqualTo("webhook");
      assertThat(transport.getString("webhook_url")).isEqualTo("https://admin.kof22.com/qqq/v1/authentik/webhook");
      assertThat(transport.getBoolean("send_once")).isTrue();
      assertThat(transport.isNull("webhook_mapping_body")).isFalse();
      assertThat(transport.isNull("webhook_mapping_headers")).isFalse();

      JSONObject rule = admin.first("/events/rules/?name=qqq-kof22-admin-sync");
      assertThat(rule.getBoolean("destination_event_user")).isFalse();
      assertThat(rule.isNull("destination_group")).isTrue();
      assertThat(rule.getJSONArray("transports").toList()).containsExactly(transport.getString("pk"));

      JSONArray bindings = admin.getOk("/policies/bindings/?target=" + rule.getString("pk") + "&page_size=50").getJSONArray("results");
      assertThat(bindings.length()).isEqualTo(11);
   }

}
