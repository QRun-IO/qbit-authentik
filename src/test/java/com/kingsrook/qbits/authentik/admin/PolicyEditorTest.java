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


import java.io.Serializable;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.policy.PolicyEditorWidget;
import com.kingsrook.qbits.authentik.policy.PolicyFormat;
import com.kingsrook.qbits.authentik.policy.PolicyGenerator;
import com.kingsrook.qbits.authentik.policy.PolicyParser;
import com.kingsrook.qbits.authentik.policy.PolicyPermissions;
import com.kingsrook.qbits.authentik.permissions.AccessComparison;
import com.kingsrook.qbits.authentik.permissions.AuthentikGroupPermissionMapper;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.dashboard.RenderWidgetAction;
import com.kingsrook.qqq.backend.core.actions.permissions.AvailablePermission;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.actions.processes.RunProcessAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLine;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessOutput;
import com.kingsrook.qqq.backend.core.model.actions.processes.Status;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QComponentType;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QFrontendStepMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.StreamedETLWithFrontendProcess;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** The policy editor (DESIGN.md section 12.4): saving a policy to Authentik,
 ** the guardrails, the authentik_policy history row, the process and widget.
 *******************************************************************************/
class PolicyEditorTest
{
   private static final String FULL_ACCESS = "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"*\"],\"Resource\":[\"*\"]}]}";
   private static final String PAGE_READ_EDIT = "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\",\"edit\"],\"Resource\":[\"cms_page\"]}]}";

   private AdminTestSupport t;



   /*******************************************************************************
    ** Full access requires every current grant, even when some were already in
    ** the target policy. An operator holding all grants may save it explicitly.
    *******************************************************************************/
   @Test
   void fullAccessSubsetRuleAndEditorFlag() throws Exception
   {
      String group = "kof-website-analysts";
      assertThat(PolicyEditorWidget.load(t.config, t.authentik.pk(group)).getFullAccess()).isFalse();
      assertThat(save(group, FULL_ACCESS).message()).contains("do not hold yourself", "cms_page.delete");
      assertThat(t.changes()).isEmpty();
      Set<String> all = PolicyPermissions.allPermissions(t.qInstance, t.admin().getUtil().getRuntime().getPermissionCatalog());
      Set<String> almostAll = new TreeSet<>(all);
      almostAll.remove("cms_page.delete");
      t.config.withHostPermissionSource((email, groups) -> almostAll);
      assertThat(save(group, FULL_ACCESS).message()).contains("do not hold yourself", "cms_page.delete");
      t.config.withHostPermissionSource((email, groups) -> all);
      AdminPlan plan = t.admin().plan(AdminRequest.of(AdminAction.SAVE_POLICY, t.authentik.pk(group), "because")
         .with(AuthentikAdmin.POLICY_DOCUMENT, FULL_ACCESS));
      assertThat(plan.isRunnable()).as(plan.getMessage()).isTrue();
      assertThat(plan.getAfter()).isEqualTo(PolicyPermissions.FULL_ACCESS_LABEL);
      assertThat(save(group, FULL_ACCESS).ok()).isTrue();
      assertThat(t.authentik.groupByName(group).getJSONObject("attributes").getString("qqq.io/policy")).isEqualTo(FULL_ACCESS);
      PolicyEditorWidget.Data widget = PolicyEditorWidget.load(t.config, t.authentik.pk(group));
      assertThat(widget.getFullAccess()).isTrue();
      assertThat(new JSONObject(widget).getBoolean("fullAccess")).isTrue();
      assertThat(policyRows().get(0).getValueInteger("permissionCount")).isEqualTo(all.size());
      assertThat(widget.getDocumentProblem()).isNull();
      assertThat(widget.getDocument()).doesNotContain(PolicyPermissions.FULL_ACCESS);
      t.config.withHostPermissionSource((email, groups) -> Set.of());
      assertThat(save(group, FULL_ACCESS).message()).contains("do not hold yourself");
      assertThat(save(group, PAGE_READ_EDIT).ok()).isTrue();
      assertThat(PolicyEditorWidget.load(t.config, t.authentik.pk(group)).getFullAccess()).isFalse();
   }



   /*******************************************************************************
    ** A full-access operator can grant full access. Both mapper paths, comparison
    ** and preview bases expand it, including grants outside the editor matrix.
    *******************************************************************************/
   @Test
   void fullAccessGraphClaimsComparisonAndMemberPreview() throws Exception
   {
      t.authentik.groupByName("identity-admins").getJSONObject("attributes").put("qqq.io/policy", FULL_ACCESS);
      assertThat(save("kof-website-analysts", FULL_ACCESS).ok()).isTrue();
      t.authentik.user(10, "full-member", "full@example.test", "internal", true, "kof-website-analysts", "kof-website-publishers");
      Set<String> all = PolicyPermissions.allPermissions(t.qInstance, t.admin().getUtil().getRuntime().getPermissionCatalog());
      AuthentikGroupPermissionMapper mapper = new AuthentikGroupPermissionMapper();
      assertThat(mapper.resolve(t.qInstance, List.of("kof-website-analysts"), "10", "full@example.test", true))
         .containsAll(all).containsAll(PermissionsHelper.getAllAvailablePermissionNames(t.qInstance)).doesNotContain(PolicyPermissions.FULL_ACCESS);
      t.config.withMapperEnabled(true).withMapperOverride(true);
      QSession session = new QSession();
      JSONObject claims = new JSONObject().put("groups", List.of()).put("sub", "10").put("qqq_policy", new JSONObject(FULL_ACCESS));
      mapper.customizeSession(t.qInstance, session, Map.of("jwtPayloadJsonObject", claims));
      assertThat(session.getPermissions()).containsAll(all).doesNotContain(PolicyPermissions.FULL_ACCESS);
      assertThat(AccessComparison.run(t.config, t.admin().getUtil(), t.admin().getUtil().getRuntime().getPermissionCatalog()))
         .anyMatch(row -> row.username().equals("full-member") && row.after().containsAll(all));
      Map<String, Object> member = PolicyEditorWidget.load(t.config, t.authentik.pk("kof-website-publishers")).getMembers().stream()
         .filter(row -> row.get("username").equals("full-member")).findFirst().orElseThrow();
      assertThat((List<String>) member.get("basePermissions")).containsAll(all).doesNotContain(PolicyPermissions.FULL_ACCESS);
      Map<String, Object> excluded = PolicyEditorWidget.load(t.config, t.authentik.pk("kof-website-analysts")).getMembers().stream()
         .filter(row -> row.get("username").equals("full-member")).findFirst().orElseThrow();
      assertThat((List<String>) excluded.get("basePermissions")).doesNotContain("cms_page.delete");
   }



   /*******************************************************************************
    ** Removing a full-access policy must not remove the last qualifying admin.
    *******************************************************************************/
   @Test
   void fullAccessPolicyProtectsLastAdmin() throws Exception
   {
      JSONObject attributes = t.authentik.groupByName("identity-admins").getJSONObject("attributes");
      attributes.put("qqq.io/permissions", List.of()).remove("qqq.io/policy");
      t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").put("qqq.io/policy", FULL_ACCESS);
      t.authentik.user(10, "last-admin", "last@example.test", "internal", true, "kof-website-analysts");
      assertThat(save("kof-website-analysts", "").message()).contains("leave nobody");
      assertThat(t.changes()).isEmpty();
   }



   /*******************************************************************************
    ** The operator's own group carries a policy, so the subset rule lets them
    ** grant cms_page read/edit and content access (but not delete).
    *******************************************************************************/
   @BeforeEach
   void setUp() throws Exception
   {
      t = AdminTestSupport.create(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP, AuthentikFeature.POLICIES));
      t.authentik.groupByName("identity-admins").getJSONObject("attributes").put("qqq.io/policy",
         PolicyGenerator.toCompact(PolicyGenerator.generate(List.of("cms_page.read", "cms_page.edit", "content.hasAccess", "publishPage.hasAccess"), PolicyFormat.DEFAULT)));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AuthentikAdmin.AdminResult save(String group, String document) throws QException
   {
      return (t.admin().execute(AdminRequest.of(AdminAction.SAVE_POLICY, t.authentik.pk(group), "because").with(AuthentikAdmin.POLICY_DOCUMENT, document)));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<QRecord> policyRows() throws QException
   {
      QueryInput input = new QueryInput();
      input.setTableName(t.config.applyTablePrefix(AuthentikLocalTables.POLICY));
      return (new QueryAction().execute(input).getRecords());
   }



   /*******************************************************************************
    ** Save, reload, resolve and compare a feature using simulated core metadata.
    ** The subset rule still requires the operator to hold the explicit grant.
    *******************************************************************************/
   @Test
   void featurePolicyFlowsThroughEditorAndMapper() throws Exception
   {
      List<AvailablePermission> available = new ArrayList<>(PermissionsHelper.getAllAvailablePermissions(t.qInstance));
      available.add(new AvailablePermission().withName("cms_page.analyze").withObjectType("Table").withObjectName("Pages").withPermissionType("Analyze"));
      try(MockedStatic<PermissionsHelper> helper = Mockito.mockStatic(PermissionsHelper.class, Mockito.CALLS_REAL_METHODS))
      {
         helper.when(() -> PermissionsHelper.getAllAvailablePermissions(t.qInstance)).thenReturn(available);
         String document = PAGE_READ_EDIT.replace("\"read\",\"edit\"", "\"analyze\"");
         assertThat(save("kof-website-publishers", document).message()).contains("do not hold yourself");
         t.authentik.groupByName("identity-admins").getJSONObject("attributes").put("qqq.io/policy", document);
         t.admin().getUtil().getRuntime().invalidateCache();
         AuthentikAdmin.AdminResult saved = save("kof-website-publishers", document);
         assertThat(saved.ok()).as(saved.message()).isTrue();
         assertThat(policyRows().get(0).getValueInteger("permissionCount")).isEqualTo(1);
         PolicyEditorWidget.Data widget = PolicyEditorWidget.load(t.config, t.authentik.pk("kof-website-publishers"));
         assertThat(widget.getDocument()).contains("\"Action\": [\"analyze\"]");
         assertThat(widget.getDocumentProblem()).isNull();
         assertThat(widget.getChangedInAuthentik()).isFalse();
         assertThat(save("kof-website-publishers", document).noChange()).isTrue();
         assertThat(t.admin().getUtil().groupGraph().byName("kof-website-publishers").policyPermissions()).containsExactly("cms_page.analyze");
         assertThat(AccessComparison.run(t.config, t.admin().getUtil(), t.admin().getUtil().getRuntime().getPermissionCatalog()))
            .anyMatch(row -> row.username().equals("operator") && row.after().contains("cms_page.analyze"));

         QSession session = new QSession();
         JSONObject claims = new JSONObject().put("groups", List.of("kof-website-publishers")).put("sub", "1")
            .put("qqq_policy", new JSONObject(document));
         new AuthentikGroupPermissionMapper().customizeSession(t.qInstance, session, Map.of("jwtPayloadJsonObject", claims));
         assertThat(session.getPermissions()).contains("cms_page.analyze");
      }
   }



   /*******************************************************************************
    ** Save writes the canonical compact string into the CURRENT attributes, and
    ** an authentik_policy row with the pretty document.
    *******************************************************************************/
   @Test
   void saveWritesCanonicalDocumentAndHistoryRow() throws Exception
   {
      t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").put("note", "set in the Authentik UI");

      AuthentikAdmin.AdminResult result = save("kof-website-analysts", PAGE_READ_EDIT);
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(result.message()).isEqualTo("Policy saved to Authentik.");

      JSONObject attributes = t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes");
      assertThat(attributes.getString("note")).isEqualTo("set in the Authentik UI");
      assertThat(attributes.getString("qqq.io/policy")).isEqualTo(PolicyGenerator.toCompact(PolicyGenerator.canonical(PAGE_READ_EDIT, PolicyFormat.DEFAULT)));
      assertThat(PolicyParser.parse(attributes.get("qqq.io/policy"), PolicyFormat.DEFAULT)).containsExactlyInAnyOrder("cms_page.read", "cms_page.edit");

      List<QRecord> rows = policyRows();
      assertThat(rows).hasSize(1);
      assertThat(rows.get(0).getValueString("groupName")).isEqualTo("kof-website-analysts");
      assertThat(rows.get(0).getValueInteger("permissionCount")).isEqualTo(2);
      assertThat(rows.get(0).getValueString("policyJson")).contains("\"Action\": [\"read\"]");
      assertThat(rows.get(0).getValueString("savedBy")).isEqualTo(com.kingsrook.qbits.authentik.AuthentikTestSupport.OPERATOR);

      //////////////////////////////////////////////////////////////
      // the effective permissions of the group now include them //
      //////////////////////////////////////////////////////////////
      t.admin().getUtil().getRuntime().invalidateCache();
      assertThat(t.admin().getUtil().groupGraph().byName("kof-website-analysts").policyPermissions()).containsExactlyInAnyOrder("cms_page.read", "cms_page.edit");

      ///////////////////////////////////////////////////////////////////
      // saving it again is no change; removing it drops the attribute //
      ///////////////////////////////////////////////////////////////////
      assertThat(save("kof-website-analysts", PAGE_READ_EDIT).noChange()).isTrue();
      AuthentikAdmin.AdminResult removed = save("kof-website-analysts", "");
      assertThat(removed.message()).contains("removed");
      assertThat(t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").has("qqq.io/policy")).isFalse();
      assertThat(policyRows()).hasSize(1);
      assertThat(policyRows().get(0).getValueInteger("permissionCount")).isEqualTo(0);
   }



   /*******************************************************************************
    ** The guardrails: invalid documents, unknown resources, the subset rule,
    ** superuser groups and a stale fingerprint are refused, and nothing is sent.
    *******************************************************************************/
   @Test
   void refusals() throws Exception
   {
      assertThat(save("kof-website-analysts", "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":[\"read\"],\"Resource\":[\"cms_page\"]}]}").message())
         .contains("not valid").contains("Deny");
      assertThat(save("kof-website-analysts", "{\"PolicySpec\":\"other\",\"PolicyVersion\":\"1.0.0\"}").message()).contains("PolicySpec");
      assertThat(save("kof-website-analysts", PAGE_READ_EDIT.replace("cms_page", "no_such_table")).message()).contains("not permissions of this app").contains("no_such_table.read");
      assertThat(save("kof-website-analysts", PAGE_READ_EDIT.replace("\"edit\"", "\"delete\"")).message()).contains("do not hold yourself").contains("cms_page.delete");
      assertThat(save("authentik Admins", PAGE_READ_EDIT).message()).contains("Superuser groups");

      AuthentikAdmin.AdminResult stale = t.admin().execute(AdminRequest.of(AdminAction.SAVE_POLICY, t.authentik.pk("kof-website-analysts"), "because")
         .with(AuthentikAdmin.POLICY_DOCUMENT, PAGE_READ_EDIT).with("expectedFingerprint", "not-the-fingerprint"));
      assertThat(stale.message()).contains("changed");

      assertThat(t.changes()).isEmpty();
      assertThat(policyRows()).isEmpty();
   }



   /*******************************************************************************
    ** Unknown resources already in the stored policy are kept (with a note); a
    ** stored document that is invalid is replaced.
    *******************************************************************************/
   @Test
   void keptUnknownsAndInvalidStoredDocuments() throws Exception
   {
      String withGone = "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"gone_table\"]}]}";
      t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").put("qqq.io/policy", withGone);
      AdminPlan plan = t.admin().plan(AdminRequest.of(AdminAction.SAVE_POLICY, t.authentik.pk("kof-website-analysts"), "because")
         .with(AuthentikAdmin.POLICY_DOCUMENT, "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"gone_table\",\"cms_page\"]}]}"));
      assertThat(plan.isRunnable()).as(plan.getMessage()).isTrue();
      assertThat(plan.getNotes()).anyMatch(n -> n.startsWith("Adds: cms_page.read")).anyMatch(n -> n.contains("Kept although") && n.contains("gone_table.read"));

      t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").put("qqq.io/policy", "garbage");
      AdminPlan replace = t.admin().plan(AdminRequest.of(AdminAction.SAVE_POLICY, t.authentik.pk("kof-website-analysts"), "because").with(AuthentikAdmin.POLICY_DOCUMENT, ""));
      assertThat(replace.isRunnable()).isTrue();
      assertThat(replace.getNotes()).anyMatch(n -> n.contains("was not valid"));
   }



   /*******************************************************************************
    ** Permission gating: without authentik.policies.manage, or without the
    ** POLICIES feature, there is no save (and no metadata).
    *******************************************************************************/
   @Test
   void gating() throws Exception
   {
      t.loginAs(com.kingsrook.qbits.authentik.AuthentikTestSupport.OPERATOR, IdentityPermission.USERS_READ, IdentityPermission.GROUPS_MANAGE, IdentityPermission.PERMISSIONS_MANAGE);
      assertThat(save("kof-website-analysts", PAGE_READ_EDIT).ok()).isFalse();
      assertThat(t.changes()).isEmpty();

      AdminTestSupport off = AdminTestSupport.create();
      assertThat(off.qInstance.getProcess("authentikEditPolicy")).isNull();
      assertThat(off.qInstance.getWidget("authentikPolicyEditor")).isNull();
      assertThat(off.qInstance.getTable("authentik_policy")).isNull();
      AuthentikAdmin.AdminResult refused = off.admin().execute(AdminRequest.of(AdminAction.SAVE_POLICY, off.authentik.pk("kof-website-analysts"), "because").with(AuthentikAdmin.POLICY_DOCUMENT, PAGE_READ_EDIT));
      assertThat(refused.ok()).isFalse();
   }



   /*******************************************************************************
    ** A second person approves policy saves when policyTwoPersonApproval is on.
    *******************************************************************************/
   @Test
   void twoPersonApproval() throws Exception
   {
      t.config.withPolicyTwoPersonApproval(true);
      AuthentikAdmin.AdminResult result = save("kof-website-analysts", PAGE_READ_EDIT);
      assertThat(result.pending()).isTrue();
      assertThat(t.changes()).isEmpty();
   }



   /*******************************************************************************
    ** The record action: prepare fills the group and fingerprint, the step shows
    ** the editor widget, Review is a dry run, Result saves.
    *******************************************************************************/
   @Test
   void editPolicyProcess() throws Exception
   {
      String groupPk = t.authentik.pk("kof-website-analysts");
      QFrontendStepMetaData details = (QFrontendStepMetaData) t.qInstance.getProcess("authentikEditPolicy").getStep("details");
      assertThat(details.getComponents()).anyMatch(c -> c.getType() == QComponentType.WIDGET && "authentikPolicyEditor".equals(c.getValues().get("widgetName")));
      assertThat(t.qInstance.getProcess("authentikEditPolicy").getTableName()).isEqualTo(t.config.applyTablePrefix(AuthentikTables.GROUP));
      assertThat(t.qInstance.getProcess("authentikEditPolicyRecord").getTableName()).isEqualTo("authentik_policy");

      RunProcessInput input = new RunProcessInput();
      input.setProcessName("authentikEditPolicy");
      input.addValue("recordIds", groupPk);
      RunProcessOutput output = new RunProcessAction().execute(input);
      assertThat(output.getValues().get("groupPk")).isEqualTo(groupPk);
      assertThat(output.getValues().get("expectedFingerprint")).isNotNull();

      input.setProcessUUID(output.getProcessUUID());
      Map<String, Serializable> form = Map.of("reason", "editors read pages", AuthentikAdmin.POLICY_DOCUMENT, PAGE_READ_EDIT);
      form.forEach(input::addValue);
      input.setStartAfterStep("details");
      output = new RunProcessAction().execute(input);
      assertThat(output.getException()).isEmpty();
      @SuppressWarnings("unchecked")
      List<ProcessSummaryLine> review = (List<ProcessSummaryLine>) output.getValues().get(StreamedETLWithFrontendProcess.FIELD_VALIDATION_SUMMARY);
      assertThat(review).anyMatch(l -> l.getStatus() == Status.OK && l.getMessage().contains("policy will be saved"));
      assertThat(review).anyMatch(l -> l.getMessage().contains("Adds: cms_page.edit, cms_page.read"));
      assertThat(t.changes()).as("review is a dry run").isEmpty();

      input.setStartAfterStep("review");
      output = new RunProcessAction().execute(input);
      assertThat(output.getException()).isEmpty();
      assertThat(PolicyParser.parse(t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").get("qqq.io/policy"), PolicyFormat.DEFAULT))
         .containsExactlyInAnyOrder("cms_page.read", "cms_page.edit");

      ////////////////////////////////////////////////////////
      // the same action from the policy record (its group) //
      ////////////////////////////////////////////////////////
      RunProcessInput again = new RunProcessInput();
      again.setProcessName("authentikEditPolicyRecord");
      again.addValue("recordIds", String.valueOf(policyRows().get(0).getValue("id")));
      RunProcessOutput prepared = new RunProcessAction().execute(again);
      assertThat(prepared.getValues().get("groupPk")).isEqualTo(groupPk);
   }



   /*******************************************************************************
    ** The widget: catalog plus the group's live document; a change made in
    ** Authentik after the last QQQ save is flagged; invalid stored documents are
    ** reported.
    *******************************************************************************/
   @Test
   void widgetData() throws Exception
   {
      String groupPk = t.authentik.pk("kof-website-analysts");
      PolicyEditorWidget.Data empty = PolicyEditorWidget.load(t.config, groupPk);
      assertThat(empty.getType()).isEqualTo("AUTHENTIK_POLICY_EDITOR");
      assertThat(empty.getSpec()).isEqualTo("qqq-iam");
      assertThat(empty.getDocument()).isNull();
      assertThat(empty.getGroupLabel()).isEqualTo("kof-website-analysts");
      assertThat(empty.getOutputFieldName()).isEqualTo("policyDocument");
      assertThat(new JSONObject(Map.of("c", empty.getCatalog())).toString()).contains("\"cms_page\"").contains("\"publishPage\"");

      save("kof-website-analysts", PAGE_READ_EDIT);
      PolicyEditorWidget.Data saved = PolicyEditorWidget.load(t.config, groupPk);
      assertThat(saved.getDocument()).contains("\"cms_page\"");
      assertThat(saved.getChangedInAuthentik()).isFalse();

      t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").put("qqq.io/policy", PAGE_READ_EDIT.replace("\"edit\"", "\"insert\""));
      t.admin().getUtil().getRuntime().invalidateCache();
      assertThat(PolicyEditorWidget.load(t.config, groupPk).getChangedInAuthentik()).isTrue();

      t.authentik.groupByName("kof-website-analysts").getJSONObject("attributes").put("qqq.io/policy", "garbage");
      t.admin().getUtil().getRuntime().invalidateCache();
      PolicyEditorWidget.Data broken = PolicyEditorWidget.load(t.config, groupPk);
      assertThat(broken.getDocumentProblem()).contains("not a JSON object");
      assertThat(broken.getDocument()).isNull();
      assertThat(broken.getFullAccess()).isFalse();

      assertThat(PolicyEditorWidget.load(t.config, null).getGroupLabel()).isNull();
      assertThatThrownBy(() -> PolicyEditorWidget.load(t.config, "../x")).hasMessageContaining("Not a group id");

      RenderWidgetInput input = new RenderWidgetInput();
      input.setWidgetMetaData(t.qInstance.getWidget("authentikPolicyEditor"));
      input.setQueryParams(new java.util.HashMap<>(Map.of("groupPk", groupPk)));
      RenderWidgetOutput output = new RenderWidgetAction().execute(input);
      assertThat(output.getWidgetData().getType()).isEqualTo("AUTHENTIK_POLICY_EDITOR");
   }



   /*******************************************************************************
    ** Direct and descendant members get all other grants, including inherited
    ** policies, wildcard attributes and static permissions of direct groups.
    *******************************************************************************/
   @Test
   void memberPreviewPreservesOtherGrants() throws Exception
   {
      String group = "kof-website-analysts";
      t.authentik.groupByName(group).getJSONObject("attributes").put("qqq.io/policy", PAGE_READ_EDIT);
      t.authentik.group("child", false, List.of(), List.of(), group)
         .group("grandchild", false, List.of(), List.of(), "child")
         .group("other-parent", false, List.of(), List.of())
         .group("other", false, List.of("cms_page.*"), List.of(), "other-parent")
         .user(10, "zoe", "zoe@example.test", "internal", true, group, "child", "other")
         .user(11, "amy", "amy@example.test", "external", true, "child", "other-parent")
         .user(12, "ben", "ben@example.test", "internal", true, "grandchild")
         .user(13, "inactive", "inactive@example.test", "internal", false, group);
      t.authentik.groupByName("other-parent").getJSONObject("attributes").put("qqq.io/policy", PAGE_READ_EDIT.replace("\"read\",\"edit\"", "\"insert\""));
      t.config.withStaticGroupPermissions(Map.of("child", List.of("static.floor"), group, List.of("direct.floor")));

      PolicyEditorWidget.Data data = PolicyEditorWidget.load(t.config, t.authentik.pk(group));
      assertThat(data.getMembers()).extracting(m -> m.get("username")).containsExactly("amy", "ben", "zoe");
      assertThat(data.getMembersTruncated()).isFalse();
      assertThat(data.getMembers().get(0)).containsExactlyInAnyOrderEntriesOf(Map.of(
         "username", "amy", "label", "amy Name (amy)", "viaGroups", List.of("child"),
         "basePermissions", List.of("cms_page.insert", "kof22.analytics.hasAccess", "static.floor")));
      assertThat(data.getMembers().get(1)).containsEntry("viaGroups", List.of("grandchild"))
         .containsEntry("basePermissions", List.of("kof22.analytics.hasAccess"));
      assertThat(data.getMembers().get(2)).containsEntry("viaGroups", List.of("child", group))
         .containsEntry("basePermissions", List.of("cms_page.delete", "cms_page.edit", "cms_page.insert", "cms_page.read", "direct.floor", "kof22.analytics.hasAccess", "static.floor"));
   }



   /*******************************************************************************
    ** The cap is applied after eligibility and username ordering, and duplicate
    ** memberships do not consume multiple slots. Exactly 200 is not truncated.
    *******************************************************************************/
   @Test
   void memberPreviewCapsEligiblePeople() throws Exception
   {
      String group = "kof-website-analysts";
      t.authentik.group("child", false, List.of(), List.of(), group);
      for(int i = 199; i >= 0; i--)
      {
         String username = "person%03d".formatted(i);
         t.authentik.user(100 + i, username, username + "@example.test", "internal", true, group, "child");
      }
      t.authentik.user(400, "aaa-inactive", "inactive@example.test", "internal", false, group);
      PolicyEditorWidget.Data exact = PolicyEditorWidget.load(t.config, t.authentik.pk(group));
      assertThat(exact.getMembers()).hasSize(200);
      assertThat(exact.getMembersTruncated()).isFalse();

      t.authentik.user(401, "aaa-active", "active@example.test", "internal", true, "child");
      t.admin().getUtil().getRuntime().invalidateCache();
      FixtureActionUtil.REQUESTS.clear();
      PolicyEditorWidget.Data capped = PolicyEditorWidget.load(t.config, t.authentik.pk(group));
      assertThat(capped.getMembers()).hasSize(200);
      assertThat(capped.getMembersTruncated()).isTrue();
      assertThat(capped.getMembers()).extracting(m -> (String) m.get("username")).isSorted().doesNotContain("person199", "aaa-inactive");
      assertThat(capped.getMembers().get(0)).containsEntry("username", "aaa-active");
      List<String> queries = FixtureActionUtil.REQUESTS.stream().filter(r -> r.getURI().getPath().equals("/api/v3/core/users/"))
         .map(r -> r.getURI().getQuery()).toList();
      assertThat(queries).hasSize(3).allSatisfy(query -> assertThat(query)
         .contains("ordering=username", "is_active=true", "groups_by_pk=" + t.authentik.pk(group), "groups_by_pk=" + t.authentik.pk("child")));
   }



   /*******************************************************************************
    ** Scope restrictions apply even to inherited members; no extra user-read
    ** permission is needed beyond the editor permission.
    *******************************************************************************/
   @Test
   void memberPreviewRespectsScopeAndEditorPermission() throws Exception
   {
      String group = "kof-website-analysts";
      t.authentik.group("child", false, List.of(), List.of(), group)
         .group("scope", false, List.of(), List.of())
         .user(10, "allowed", "allowed@example.test", "internal", true, "child", "scope")
         .user(11, "wrong-path", "path@example.test", "internal", true, group, "scope")
         .user(12, "wrong-group", "group@example.test", "internal", true, group);
      t.authentik.users.get(11).put("path", "outside");
      t.config.withUserScopePathStartsWith("users").withUserScopeGroupNames(List.of("scope"));
      t.loginAs(AuthentikTestSupport.OPERATOR, IdentityPermission.POLICIES_MANAGE);
      assertThat(PolicyEditorWidget.load(t.config, t.authentik.pk(group)).getMembers())
         .extracting(m -> m.get("username")).containsExactly("allowed");

      t.loginAs(AuthentikTestSupport.OPERATOR, IdentityPermission.USERS_READ);
      FixtureActionUtil.REQUESTS.clear();
      assertThatThrownBy(() -> PolicyEditorWidget.load(t.config, t.authentik.pk(group))).hasMessageContaining("authentik.policies.manage");
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
      assertThatThrownBy(() -> t.admin().getUtil().policyPreviewUsers(List.of(t.authentik.pk(group)), 201)).hasMessageContaining("authentik.policies.manage");
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
   }



   /*******************************************************************************
    ** Bootstrap subjects retain identity grants by immutable pk or uuid; a
    ** superuser flag alone never grants QQQ permissions or leaks private fields.
    *******************************************************************************/
   @Test
   void memberPreviewIncludesBootstrapWithoutSuperuserEscalation() throws Exception
   {
      String group = "kof-website-analysts";
      t.authentik.user(10, "bootstrap-pk", "pk@example.test", "internal", true, group)
         .user(11, "bootstrap-uuid", "uuid@example.test", "internal", true, group)
         .user(12, "superuser", "superuser@example.test", "internal", true, group, "authentik Admins");
      t.authentik.users.get(11).put("uuid", "immutable-subject");
      t.config.withBootstrapOperatorSubjects("10,immutable-subject");
      List<Map<String, Object>> members = PolicyEditorWidget.load(t.config, t.authentik.pk(group)).getMembers();
      for(Map<String, Object> member : members.subList(0, 2))
      {
         assertThat((List<?>) member.get("basePermissions")).hasSize(IdentityPermission.values().length + 1);
         for(IdentityPermission permission : IdentityPermission.values())
         {
            assertThat(((List<?>) member.get("basePermissions")).contains(permission.getSessionPermission())).isTrue();
         }
      }
      assertThat(members.get(2)).containsEntry("basePermissions", List.of("kof22.analytics.hasAccess"));
      assertThat(members.get(2)).containsOnlyKeys("username", "label", "viaGroups", "basePermissions");
   }



   /*******************************************************************************
    ** The added fields serialize like the existing widget fields, including an
    ** empty member list when no group is selected and the configured mapper flag.
    *******************************************************************************/
   @Test
   void memberPreviewPayloadAndMapperFlag() throws Exception
   {
      t.config.withMapperEnabled(false);
      FixtureActionUtil.REQUESTS.clear();
      PolicyEditorWidget.Data empty = PolicyEditorWidget.load(t.config, null);
      assertThat(empty.getMembers()).isEmpty();
      assertThat(empty.getMembersTruncated()).isFalse();
      assertThat(empty.getMapperEnabled()).isFalse();
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
      t.config.withMapperEnabled(true);
      PolicyEditorWidget.Data data = PolicyEditorWidget.load(t.config, t.authentik.pk("kof-website-publishers"));
      JSONObject json = new JSONObject(data);
      assertThat(json.getBoolean("mapperEnabled")).isTrue();
      assertThat(json.getBoolean("membersTruncated")).isFalse();
      assertThat(json.getJSONArray("members").getJSONObject(0).keySet()).containsExactlyInAnyOrder("username", "label", "viaGroups", "basePermissions");
   }
}
