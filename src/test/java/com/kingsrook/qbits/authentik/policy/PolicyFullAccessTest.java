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
import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.TableFeaturePermission;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.TableFeaturePermissionsMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Full access stays symbolic in documents and expands against live metadata.
 *******************************************************************************/
class PolicyFullAccessTest
{
   private static final PolicyFormat FORMAT = PolicyFormat.DEFAULT;



   /*******************************************************************************
    ** The exact full-access statement in a valid document envelope.
    *******************************************************************************/
   private static JSONObject document()
   {
      return (PolicyParserTest.document(PolicyParserTest.statement("Allow", List.of("*"), List.of("*"))));
   }



   /*******************************************************************************
    ** Mixed documents still validate every statement before dropping redundancy.
    *******************************************************************************/
   @Test
   void parserAcceptsOnlyExplicitFullAccess() throws Exception
   {
      JSONObject document = document();
      assertThat(PolicyParser.parseStrict(document, FORMAT).permissions()).containsExactly(PolicyPermissions.FULL_ACCESS);
      document.getJSONArray("Statement").put(PolicyParserTest.statement("Allow", List.of("read"), List.of("cms_page")));
      assertThat(PolicyParser.parseStrict(document, FORMAT).permissions()).containsExactly(PolicyPermissions.FULL_ACCESS);
      document.getJSONArray("Statement").put(PolicyParserTest.statement("Deny", List.of("read"), List.of("cms_page")));
      assertThat(PolicyParser.parse(document, FORMAT)).isEmpty();
      for(List<String> actions : List.of(List.of("read"), List.of("*", "read"), List.<String>of()))
      {
         JSONObject invalid = PolicyParserTest.document(PolicyParserTest.statement("Allow", actions, List.of("*")));
         assertThatThrownBy(() -> PolicyParser.parseStrict(invalid, FORMAT)).hasMessageContaining("requires Action");
         assertThat(PolicyParser.parse(invalid, FORMAT)).isEmpty();
      }
      JSONObject badResource = PolicyParserTest.document(PolicyParserTest.statement("Allow", List.of("*"), List.of("*", "bad.resource")));
      assertThat(PolicyParser.parse(badResource, FORMAT)).isEmpty();
      JSONObject mixedResources = PolicyParserTest.document(PolicyParserTest.statement("Allow", List.of("*"), List.of("*", "cms_page")));
      assertThat(PolicyParser.parse(mixedResources, FORMAT)).containsExactly(PolicyPermissions.FULL_ACCESS);
   }



   /*******************************************************************************
    ** The marker alone creates the wildcard; enumerated grants never do.
    *******************************************************************************/
   @Test
   void canonicalFormAndRoundTrip() throws Exception
   {
      JSONObject mixed = document();
      mixed.getJSONArray("Statement").put(PolicyParserTest.statement("Allow", List.of("*"), List.of("cms_page")));
      String expected = PolicyGenerator.toCompact(document());
      assertThat(PolicyGenerator.toCompact(PolicyGenerator.canonical(mixed, FORMAT))).isEqualTo(expected);
      JSONObject generated = PolicyGenerator.generate(Set.of(PolicyPermissions.FULL_ACCESS, "cms_page.read"), FORMAT);
      assertThat(PolicyGenerator.toCompact(generated)).isEqualTo(expected);
      assertThat(PolicyParser.parseStrict(PolicyGenerator.toPretty(generated), FORMAT).permissions()).containsExactly(PolicyPermissions.FULL_ACCESS);
      Set<String> fiveActions = PolicyParser.parse(PolicyParserTest.document(PolicyParserTest.statement("Allow", List.of("*"), List.of("cms_page"))), FORMAT);
      assertThat(PolicyGenerator.toCompact(PolicyGenerator.generate(fiveActions, FORMAT))).doesNotContain("[\"*\"]");
      assertThat(PolicyCatalog.of(PolicyCatalogTest.instance()).unknownPermissions(Set.of(PolicyPermissions.FULL_ACCESS))).isEmpty();
   }



   /*******************************************************************************
    ** An already parsed graph and catalog cover later features and processes.
    ** The member's grants must be a superset of the actual core API's output.
    *******************************************************************************/
   @Test
   void resolverAndClaimsExpandCurrentAndFutureInstancePermissions()
   {
      QInstance instance = PolicyCatalogTest.instance();
      PolicyCatalog catalog = PolicyCatalog.of(instance);
      JSONObject parent = new JSONObject().put("pk", "parent").put("name", "Owners")
         .put("attributes", new JSONObject().put(FORMAT.attribute(), document()));
      JSONObject child = new JSONObject().put("pk", "child").put("name", "Staff").put("parents", List.of("parent")).put("users", List.of(7));
      GroupGraph graph = GroupGraph.fromGroups(List.of(parent, child), FORMAT, catalog);
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph, catalog.permissionNames(), instance);
      assertThat(resolver.resolveUser(7).sessionPermissions()).doesNotContain("cms_page.analyze", "futureProcess.hasAccess");

      TableFeaturePermissionsMetaData.ofOrWithNew(instance).withPermission(new TableFeaturePermission().withSuffix("analyze").withLabel("Analyze")
         .withAppliesTo((qi, table) -> table.getName().equals("cms_page")));
      instance.addProcess(new QProcessMetaData().withName("futureProcess")
         .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION)));
      Set<String> permissions = resolver.resolveUser(7).sessionPermissions();
      assertThat(permissions).containsAll(PermissionsHelper.getAllAvailablePermissionNames(instance))
         .contains("cms_page.analyze", "futureProcess.hasAccess", "legacy.write", "cms.publish.hasAccess", "publishPage.hasAccess",
            "content.hasAccess", "pageReport.hasAccess", "pageStats.hasAccess")
         .doesNotContain(PolicyPermissions.FULL_ACCESS);
      for(IdentityPermission permission : IdentityPermission.values())
      {
         assertThat(permissions).contains(permission.getSessionPermission());
      }
      assertThat(resolver.resolveUser(7).grantedBy().get("futureProcess.hasAccess")).containsExactly("Owners");
      assertThat(resolver.resolveGroups(List.of("child"), "parent").sessionPermissions()).isEmpty();
      assertThat(graph.byPk("parent").policyPermissions()).containsExactly(PolicyPermissions.FULL_ACCESS);

      JSONObject claims = new JSONObject().put(FORMAT.claim(), document());
      assertThat(PolicyPermissions.fromClaims(claims, FORMAT, catalog)).isEqualTo(permissions);
      QSession session = new QSession();
      new AuthentikPolicyClaimMapper().customizeSession(instance, session, Map.of(PolicyPermissions.ID_TOKEN_CONTEXT_KEY, claims));
      assertThat(session.getPermissions()).isEqualTo(permissions);
   }



   /*******************************************************************************
    ** QContext-based consumers see a replacement instance without a new graph.
    *******************************************************************************/
   @Test
   void contextReloadAndCatalogOnlyResolution()
   {
      GroupGraph graph = GroupGraph.fromGroups(List.of(new JSONObject().put("pk", "owners").put("name", "Owners")
         .put("attributes", new JSONObject().put(FORMAT.attribute(), document()))), FORMAT);
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph, Set.of("host.extra"));
      QInstance original = new QInstance().withInstanceDefaultAuthentication(new QAuthenticationMetaData().withName("mock").withType(QAuthenticationType.MOCK));
      QInstance sample = PolicyCatalogTest.instance();
      original.addBackend(sample.getBackend("memory"));
      original.addTable(sample.getTable("cms_page"));
      QContext.init(original, new QSession());
      try
      {
         AuthentikRuntime runtime = new AuthentikRuntime(new AuthentikQBitConfig());
         assertThat(runtime.getPermissionCatalog()).contains("cms_page.read");
         assertThat(resolver.resolveGroups(List.of("owners")).sessionPermissions()).contains("cms_page.read", "host.extra");
         QInstance replacement = new QInstance().withInstanceDefaultAuthentication(new QAuthenticationMetaData().withName("mock").withType(QAuthenticationType.MOCK));
         replacement.addBackend(sample.getBackend("memory"));
         replacement.addTable(sample.getTable("orphan"));
         QContext.init(replacement, new QSession());
         assertThat(runtime.getPermissionCatalog()).contains("orphan.read").doesNotContain("cms_page.read");
         assertThat(resolver.resolveGroups(List.of("owners")).sessionPermissions()).contains("host.extra").doesNotContain("cms_page.read");
         assertThat(PolicyPermissions.fromClaims(new JSONObject().put(FORMAT.claim(), document()), FORMAT))
            .contains(IdentityPermission.USERS_READ.getSessionPermission()).doesNotContain(PolicyPermissions.FULL_ACCESS);
      }
      finally
      {
         QContext.clear();
      }
      assertThat(PolicyPermissions.allPermissions(null, null)).hasSize(IdentityPermission.values().length);
   }
}
