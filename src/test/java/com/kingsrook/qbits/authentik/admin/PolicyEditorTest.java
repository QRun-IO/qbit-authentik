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
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.policy.PolicyEditorWidget;
import com.kingsrook.qbits.authentik.policy.PolicyFormat;
import com.kingsrook.qbits.authentik.policy.PolicyGenerator;
import com.kingsrook.qbits.authentik.policy.PolicyParser;
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
   private static final String PAGE_READ_EDIT = "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\",\"edit\"],\"Resource\":[\"cms_page\"]}]}";

   private AdminTestSupport t;



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

      assertThat(PolicyEditorWidget.load(t.config, null).getGroupLabel()).isNull();
      assertThatThrownBy(() -> PolicyEditorWidget.load(t.config, "../x")).hasMessageContaining("Not a group id");

      RenderWidgetInput input = new RenderWidgetInput();
      input.setWidgetMetaData(t.qInstance.getWidget("authentikPolicyEditor"));
      input.setQueryParams(new java.util.HashMap<>(Map.of("groupPk", groupPk)));
      RenderWidgetOutput output = new RenderWidgetAction().execute(input);
      assertThat(output.getWidgetData().getType()).isEqualTo("AUTHENTIK_POLICY_EDITOR");
   }
}
