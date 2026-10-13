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

package com.kingsrook.qbits.authentik.policy;


import java.util.List;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.authentik.policy.PolicyParserTest.document;
import static com.kingsrook.qbits.authentik.policy.PolicyParserTest.statement;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Group policies in the group graph and the effective-permission resolver:
 ** inherited from parents, fail closed per group, checked against the catalog.
 *******************************************************************************/
class PolicyGraphTest
{

   /*******************************************************************************
    **
    *******************************************************************************/
   private static JSONObject group(String pk, List<String> parents, Object policy, String attribute)
   {
      JSONObject attributes = new JSONObject();
      if(policy != null)
      {
         attributes.put(attribute, policy);
      }
      return (new JSONObject().put("pk", pk).put("name", pk).put("is_superuser", false).put("parents", new JSONArray(parents)).put("attributes", attributes).put("users", new JSONArray()));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void policiesAreInheritedAndFailClosedPerGroup()
   {
      String parentPolicy = document(statement("Allow", List.of("hasAccess"), List.of("contentApp"))).toString();
      JSONObject childPolicy = document(statement("Allow", List.of("read", "edit"), List.of("cms_page")));
      String broken = "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":[\"read\"],\"Resource\":[\"x\"]}]}";

      GroupGraph graph = GroupGraph.fromGroups(List.of(
         group("parent", List.of(), parentPolicy, "qqq.io/policy"),
         group("child", List.of("parent"), childPolicy, "qqq.io/policy"),
         group("broken", List.of("parent"), broken, "qqq.io/policy"),
         group("empty", List.of(), "", "qqq.io/policy")));

      assertThat(graph.byPk("child").policyPermissions()).containsExactlyInAnyOrder("cms_page.read", "cms_page.edit");
      assertThat(graph.byPk("broken").policyPermissions()).isEmpty();
      assertThat(graph.byPk("broken").malformed()).anyMatch(m -> m.startsWith("qqq.io/policy: ") && m.contains("Deny"));
      assertThat(graph.byPk("empty").malformed()).isEmpty();

      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph, null);
      EffectivePermissionResolver.Resolution child = resolver.resolveGroups(List.of("child"));
      assertThat(child.sessionPermissions()).containsExactlyInAnyOrder("contentApp.hasAccess", "cms_page.read", "cms_page.edit");
      assertThat(child.grantedBy().get("contentApp.hasAccess")).containsExactly("parent");

      assertThat(resolver.resolveGroups(List.of("broken")).sessionPermissions()).as("the broken group grants nothing; its parent still does").containsExactly("contentApp.hasAccess");
   }



   /*******************************************************************************
    ** Grants outside the app's permission catalog are reported, not granted.
    *******************************************************************************/
   @Test
   void catalogFiltersPolicyGrants()
   {
      GroupGraph graph = GroupGraph.fromGroups(List.of(group("g", List.of(), document(statement("Allow", List.of("read"), List.of("cms_page", "gone_table"))).toString(), "qqq.io/policy")));
      EffectivePermissionResolver.Resolution resolution = new EffectivePermissionResolver(graph, List.of("cms_page.read")).resolveGroups(List.of("g"));
      assertThat(resolution.sessionPermissions()).containsExactly("cms_page.read");
      assertThat(resolution.unknown()).containsExactly("gone_table.read");
   }



   /*******************************************************************************
    ** A host's own attribute and spec.
    *******************************************************************************/
   @Test
   void customFormat()
   {
      PolicyFormat custom = new PolicyFormat("acme-iam", "1.0.0", "policies", "policies");
      String       doc    = document(statement("Allow", List.of("read"), List.of("order"))).put("PolicySpec", "acme-iam").toString();
      GroupGraph   graph  = GroupGraph.fromGroups(List.of(group("g", List.of(), doc, "policies")), custom);
      assertThat(graph.byPk("g").policyPermissions()).containsExactly("order.read");
      assertThat(GroupGraph.fromGroups(List.of(group("g", List.of(), doc, "policies"))).byPk("g").policyPermissions()).as("default attribute is qqq.io/policy").isEmpty();
   }
}
