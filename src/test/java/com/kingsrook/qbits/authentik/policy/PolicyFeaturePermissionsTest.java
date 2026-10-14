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


import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.permissions.AccessComparison;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.TableFeaturePermission;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.TableFeaturePermissionsMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Table features are discovered through core's registered metadata and catalog.
 *******************************************************************************/
class PolicyFeaturePermissionsTest
{
   private static final PolicyFormat FORMAT = PolicyFormat.DEFAULT;



   /*******************************************************************************
    ** Use an overridden permission base name to catch matching by table name.
    *******************************************************************************/
   private static QInstance instance()
   {
      QInstance instance = PolicyCatalogTest.instance();
      instance.addTable(new QTableMetaData().withName("person_records").withLabel("People").withBackendName("memory")
         .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.READ_INSERT_EDIT_DELETE_PERMISSIONS).withPermissionBaseName("person")));
      instance.addTable(new QTableMetaData().withName("person_extra").withLabel("Extra People").withBackendName("memory")
         .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION)));
      TableFeaturePermissionsMetaData features = TableFeaturePermissionsMetaData.ofOrWithNew(instance);
      features.withPermission(feature("comment", "Comment", "person_records", "legacy"))
         .withPermission(feature("analyze", "Old label", "person_records"))
         .withPermission(feature("analyze", "Analyze", "person_records", "gate", "open_table"))
         .withPermission(feature("tag", "Tag", "shared_one", "shared_two"))
         .withPermission(feature("share", "Share", "person_extra"))
         .withPermission(feature("", "Empty", "person_records"));
      return (instance);
   }



   /*******************************************************************************
    ** Register a feature only for the named tables; core supplies permission names.
    *******************************************************************************/
   private static TableFeaturePermission feature(String suffix, String label, String... tables)
   {
      return (new TableFeaturePermission().withSuffix(suffix).withLabel(label)
         .withAppliesTo((instance, table) -> List.of(tables).contains(table.getName())));
   }



   /*******************************************************************************
    ** A statement granting these actions on these resources.
    *******************************************************************************/
   private static JSONObject document(List<String> actions, String... resources)
   {
      return (PolicyParserTest.document(PolicyParserTest.statement("Allow", actions, List.of(resources))));
   }



   /*******************************************************************************
    ** Labels, overridden/shared bases, permission levels and additive widget JSON.
    *******************************************************************************/
   @Test
   void catalogListsFeaturesSeparately()
   {
      QInstance instance = instance();
      assertThat(PermissionsHelper.getAllAvailablePermissions(instance)).filteredOn(permission -> permission.getName().equals("shared_base.tag")).hasSize(2);
      PolicyCatalog catalog = PolicyCatalog.of(instance);
      assertThat(catalog.get("person").actions()).containsExactly(PolicyAction.READ, PolicyAction.INSERT, PolicyAction.EDIT, PolicyAction.DELETE);
      assertThat(catalog.get("person").features()).containsExactly(new PolicyCatalog.Feature("analyze", "Analyze"), new PolicyCatalog.Feature("comment", "Comment"));
      assertThat(catalog.get("gate").features()).containsExactly(new PolicyCatalog.Feature("analyze", "Analyze"));
      assertThat(catalog.get("legacy").features()).containsExactly(new PolicyCatalog.Feature("comment", "Comment"), new PolicyCatalog.Feature("write", "WRITE"));
      assertThat(catalog.get("shared_base").features()).containsExactly(new PolicyCatalog.Feature("tag", "Tag"));
      assertThat(catalog.get("open_table")).isNull();
      assertThat(catalog.permissionNames()).contains("person.analyze", "person.comment", "gate.analyze", "legacy.comment", "legacy.write", "shared_base.tag")
         .doesNotContain("person.share", "person_records.analyze");
      assertThat(catalog.unknownPermissions(Set.of("person.analyze", "person.mystery"))).containsExactly("person.mystery");

      List<JSONObject> resources = new ArrayList<>();
      catalog.toJson().forEach(group -> ((JSONObject) group).getJSONArray("resources").forEach(resource -> resources.add((JSONObject) resource)));
      JSONObject person = resources.stream().filter(resource -> resource.getString("name").equals("person")).findFirst().orElseThrow();
      assertThat(person.getJSONArray("actions").toList()).containsExactly("read", "insert", "edit", "delete");
      assertThat(person.getJSONArray("features").toList()).containsExactly(Map.of("name", "analyze", "label", "Analyze"), Map.of("name", "comment", "label", "Comment"));
      assertThat(resources.stream().filter(resource -> resource.getString("kind").equals("TABLE"))).allMatch(resource -> resource.has("features"));
      assertThat(resources.stream().filter(resource -> resource.getString("kind").equals("APP"))).noneMatch(resource -> resource.has("features"));
   }



   /*******************************************************************************
    ** Feature-only tables are still grantable when CRUD capabilities are absent.
    *******************************************************************************/
   @Test
   void featuresDoNotRequireStandardActions()
   {
      QInstance instance = instance();
      instance.getTable("person_records").withoutCapabilities(Capability.TABLE_QUERY, Capability.TABLE_GET, Capability.TABLE_INSERT, Capability.TABLE_UPDATE, Capability.TABLE_DELETE);
      PolicyCatalog.Resource resource = PolicyCatalog.of(instance).get("person");
      assertThat(resource.actions()).isEmpty();
      assertThat(resource.features()).hasSize(2);
   }



   /*******************************************************************************
    ** Every resource must register a feature; one bad pair voids the document.
    *******************************************************************************/
   @Test
   void parserValidatesFeaturesPerResource() throws Exception
   {
      PolicyCatalog catalog = PolicyCatalog.of(instance());
      assertThat(PolicyParser.parseStrict(document(List.of("read", "analyze"), "person"), FORMAT, catalog).permissions())
         .containsExactly("person.analyze", "person.read");
      assertThat(PolicyParser.parse(document(List.of("analyze"), "person", "gate"), FORMAT, catalog)).containsExactly("gate.analyze", "person.analyze");
      assertThat(PolicyParser.parse(document(List.of("comment", "write"), "legacy"), FORMAT, catalog)).containsExactly("legacy.comment", "legacy.write");
      assertThatThrownBy(() -> PolicyParser.parseStrict(document(List.of("mystery"), "person"), FORMAT, catalog))
         .hasMessage("Statement 1: unknown action \"mystery\"");
      assertThat(PolicyParser.parse(document(List.of("analyze"), "person", "legacy"), FORMAT, catalog)).isEmpty();
      assertThat(PolicyParser.parse(document(List.of("analyze"), "gone"), FORMAT, catalog)).isEmpty();
      assertThat(PolicyParser.parse(document(List.of("analyze")), FORMAT, catalog)).isEmpty();
      assertThat(PolicyParser.parse(document(List.of("Analyze"), "person"), FORMAT, catalog)).isEmpty();
      assertThat(PolicyParser.parse(document(List.of("analyze"), "person"), FORMAT)).isEmpty();
   }



   /*******************************************************************************
    ** Existing wildcard grants remain the five standard actions forever.
    *******************************************************************************/
   @Test
   void wildcardDoesNotGrantFeatures()
   {
      PolicyCatalog catalog = PolicyCatalog.of(instance());
      assertThat(PolicyParser.parse(document(List.of("*"), "person"), FORMAT, catalog))
         .containsExactlyInAnyOrder("person.hasAccess", "person.read", "person.insert", "person.edit", "person.delete");
      assertThat(PolicyParser.parse(document(List.of("*", "analyze"), "person"), FORMAT, catalog)).hasSize(6).contains("person.analyze").doesNotContain("person.comment");
   }



   /*******************************************************************************
    ** Standard ordering stays byte-identical; sorted features follow it.
    *******************************************************************************/
   @Test
   void generatorRoundTripsFeatures() throws Exception
   {
      PolicyCatalog catalog = PolicyCatalog.of(instance());
      List<String> permissions = List.of("person.comment", "person.read", "person.analyze", "gate.analyze");
      JSONObject generated = PolicyGenerator.generate(permissions, FORMAT, catalog);
      String compact = PolicyGenerator.toCompact(generated);
      assertThat(compact).isEqualTo("{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":["
         + "{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"person\"]},"
         + "{\"Effect\":\"Allow\",\"Action\":[\"analyze\"],\"Resource\":[\"gate\",\"person\"]},"
         + "{\"Effect\":\"Allow\",\"Action\":[\"comment\"],\"Resource\":[\"person\"]}]}");
      assertThat(PolicyParser.parseStrict(compact, FORMAT, catalog).permissions()).containsExactlyInAnyOrderElementsOf(permissions);
      assertThat(PolicyParser.parseStrict(PolicyGenerator.toPretty(generated), FORMAT, catalog).permissions()).containsExactlyInAnyOrderElementsOf(permissions);
      assertThat(PolicyGenerator.toCompact(PolicyGenerator.canonical(PolicyGenerator.toPretty(generated), FORMAT, catalog))).isEqualTo(compact);
      assertThat(PolicyStore.fingerprint(compact, FORMAT, catalog)).isEqualTo(PolicyStore.fingerprint(PolicyGenerator.toPretty(generated), FORMAT, catalog));
      assertThatThrownBy(() -> PolicyGenerator.generate(List.of("person.mystery"), FORMAT, catalog)).hasMessageContaining("unknown action \"mystery\"");
      assertThatThrownBy(() -> PolicyGenerator.generate(List.of("legacy.analyze"), FORMAT, catalog)).hasMessageContaining("unknown action \"analyze\"");
      List<String> standard = List.of("person.read", "person.edit", "gate.hasAccess");
      assertThat(PolicyGenerator.toCompact(PolicyGenerator.generate(standard, FORMAT, catalog))).isEqualTo(PolicyGenerator.toCompact(PolicyGenerator.generate(standard, FORMAT)));
   }



   /*******************************************************************************
    ** The real mapper discovers registered core features and adds their exact names.
    *******************************************************************************/
   @Test
   void claimMapperUsesCoreCatalog()
   {
      QInstance instance = instance();
      QSession session = new QSession();
      session.setPermissions(Set.of("existing.read"));
      JSONObject claims = new JSONObject().put(FORMAT.claim(), document(List.of("analyze"), "person"));
      new AuthentikPolicyClaimMapper().customizeSession(instance, session, Map.of(PolicyPermissions.ID_TOKEN_CONTEXT_KEY, claims));
      assertThat(session.getPermissions()).containsExactlyInAnyOrder("existing.read", "person.analyze");
      assertThat(PolicyPermissions.fromClaims(claims, FORMAT, PolicyCatalog.of(instance))).containsExactly("person.analyze");
   }



   /*******************************************************************************
    ** Inherited feature grants reach resolution, attribution and access comparison.
    *******************************************************************************/
   @Test
   void comparisonIncludesInheritedFeatures() throws Exception
   {
      PolicyCatalog catalog = PolicyCatalog.of(instance());
      JSONObject parent = new JSONObject().put("pk", "parent").put("name", "Analysts")
         .put("attributes", new JSONObject().put(FORMAT.attribute(), document(List.of("analyze"), "person")));
      JSONObject child = new JSONObject().put("pk", "child").put("name", "Staff").put("parents", new JSONArray(List.of("parent")))
         .put("users", new JSONArray(List.of(1)));
      GroupGraph graph = GroupGraph.fromGroups(List.of(parent, child), FORMAT, catalog);
      EffectivePermissionResolver.Resolution resolution = new EffectivePermissionResolver(graph, catalog.permissionNames()).resolveUser(1);
      assertThat(resolution.sessionPermissions()).containsExactly("person.analyze");
      assertThat(resolution.grantedBy().get("person.analyze")).containsExactly("Analysts");
      assertThat(resolution.unknown()).isEmpty();

      AuthentikActionUtil util = Mockito.mock(AuthentikActionUtil.class);
      Mockito.when(util.groupGraphWithMembers()).thenReturn(graph);
      Mockito.when(util.allUsers()).thenReturn(List.of(new JSONObject().put("pk", 1).put("username", "person").put("type", "internal")));
      AuthentikQBitConfig config = new AuthentikQBitConfig().withCutoverGuardGroups(List.of("Staff"));
      AccessComparison.Row added = AccessComparison.run(config, util, catalog.permissionNames()).get(0);
      assertThat(added.after()).containsExactly("person.analyze");
      assertThat(added.added()).containsExactly("person.analyze");
      config.withHostPermissionSource((email, groups) -> Set.of("person.analyze"));
      AccessComparison.Row unchanged = AccessComparison.run(config, util, catalog.permissionNames()).get(0);
      assertThat(unchanged.before()).isEqualTo(unchanged.after());
      assertThat(unchanged.removed()).isEmpty();
      assertThat(AccessComparison.guardFailures(List.of(unchanged))).isEmpty();
   }
}
