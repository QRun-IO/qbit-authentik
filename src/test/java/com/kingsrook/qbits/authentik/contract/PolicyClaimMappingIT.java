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


import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import com.kingsrook.qbits.authentik.policy.PolicyFormat;
import com.kingsrook.qbits.authentik.policy.PolicyGenerator;
import com.kingsrook.qbits.authentik.policy.PolicyParser;
import com.kingsrook.qbits.authentik.policy.PolicyPermissions;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Pins the scope-mapping example of docs/POLICY-FORMAT.md on Authentik
 ** 2026.8.3: the blueprint applies, and the mapping (run through Authentik's
 ** property-mapping test endpoint) emits a claim that the qbit's parser turns
 ** into the union of the user's groups' policies, including inherited parents.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(46)
class PolicyClaimMappingIT
{
   private static TestApi admin;
   private static String  mappingPk;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeAll
   static void beforeAll() throws Exception
   {
      AuthentikTestStack stack = AuthentikTestStack.get();
      admin = stack.admin();
      try(InputStream in = PolicyClaimMappingIT.class.getResourceAsStream("/blueprints/qqq-policy-claim.yaml"))
      {
         stack.createContentBlueprint("qqq-policy-claim", new String(in.readAllBytes(), StandardCharsets.UTF_8));
      }
      mappingPk = admin.first("/propertymappings/provider/scope/?name=qqq-policy-claim").getString("pk");
   }



   /*******************************************************************************
    ** Run the mapping for a user; the claim as Authentik would put it in a token.
    *******************************************************************************/
   private static JSONObject claimsFor(int userPk)
   {
      TestApi.Response response = admin.post("/propertymappings/all/" + mappingPk + "/test/", new JSONObject().put("user", userPk));
      assertThat(response.status()).as(response.body()).isEqualTo(200);
      JSONObject result = response.json();
      assertThat(result.getBoolean("successful")).as(result.toString()).isTrue();
      return (new JSONObject(result.getString("result")));
   }



   /*******************************************************************************
    ** A group with a canonical policy for these permissions.
    *******************************************************************************/
   private static String group(String name, String parentPk, Object policy) throws Exception
   {
      JSONObject group = new JSONObject().put("name", name).put("attributes", new JSONObject().put("qqq.io/policy", policy));
      if(parentPk != null)
      {
         group.put("parents", new JSONArray().put(parentPk));
      }
      admin.post("/core/groups/", group);
      return (admin.groupPk(name));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static int user(String username, String groupPk)
   {
      admin.post("/core/users/", new JSONObject().put("username", username).put("name", username).put("type", "internal").put("path", "users"));
      int pk = admin.userPk(username);
      if(groupPk != null)
      {
         admin.post("/core/groups/" + groupPk + "/add_user/", new JSONObject().put("pk", pk));
      }
      return (pk);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void claimIsTheUnionOfInheritedGroupPolicies() throws Exception
   {
      PolicyFormat format = PolicyFormat.DEFAULT;
      String parent = group("policy-parent", null, PolicyGenerator.toCompact(PolicyGenerator.generate(List.of("contentApp.hasAccess"), format)));
      String child  = group("policy-child", parent, PolicyGenerator.toCompact(PolicyGenerator.generate(List.of("cms_page.read", "cms_page.edit"), format)));
      group("policy-object", null, PolicyGenerator.generate(List.of("objectAttr.read"), format));
      group("policy-other-spec", null, PolicyGenerator.toCompact(PolicyGenerator.generate(List.of("ignored.read"), new PolicyFormat("other", "1.0.0", "x", "y"))));

      int member = user("policy.member", child);
      admin.post("/core/groups/" + admin.groupPk("policy-object") + "/add_user/", new JSONObject().put("pk", member));
      admin.post("/core/groups/" + admin.groupPk("policy-other-spec") + "/add_user/", new JSONObject().put("pk", member));

      JSONObject claims = claimsFor(member);
      assertThat(claims.has("qqq_policy")).isTrue();
      assertThat(PolicyPermissions.fromClaims(claims, format))
         .as("parent (inherited), child, an object-valued attribute; another spec is skipped")
         .containsExactlyInAnyOrder("contentApp.hasAccess", "cms_page.read", "cms_page.edit", "objectAttr.read");
   }



   /*******************************************************************************
    ** No policies: the claim is still a valid, empty document.
    *******************************************************************************/
   @Test
   void userWithoutPoliciesGetsAnEmptyDocument() throws Exception
   {
      JSONObject claims = claimsFor(user("policy.nobody", null));
      assertThat(PolicyParser.parseStrict(claims.get("qqq_policy"), PolicyFormat.DEFAULT).permissions()).isEmpty();
   }
}
