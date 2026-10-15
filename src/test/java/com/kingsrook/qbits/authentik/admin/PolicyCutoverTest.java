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


import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.permissions.AccessComparison;
import com.kingsrook.qbits.authentik.permissions.AuthentikGroupPermissionMapper;
import com.kingsrook.qbits.authentik.permissions.AuthentikHostPermissionSource;
import com.kingsrook.qbits.authentik.policy.PolicyCutoverWidgets;
import com.kingsrook.qbits.authentik.policy.PolicyFormat;
import com.kingsrook.qbits.authentik.policy.PolicyParser;
import com.kingsrook.qqq.backend.core.actions.dashboard.RenderWidgetAction;
import com.kingsrook.qqq.backend.core.actions.processes.RunProcessAction;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLine;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessOutput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.RawHTML;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.TableData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.StreamedETLWithFrontendProcess;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** The cut-over to policies (DESIGN.md section 12.8): enforcement status, the
 ** compare report, the guard (and its fallback to today's access), and
 ** Generate Policy From Current Access.
 *******************************************************************************/
class PolicyCutoverTest
{
   /** Today's grant: publishers read pages and publish; analysts see analytics. */
   static final AuthentikHostPermissionSource SOURCE = new AuthentikHostPermissionSource()
   {
      @Override
      public Set<String> userPermissions(String email, Collection<String> groupNames)
      {
         Set<String> rs = new TreeSet<>();
         if(groupNames.contains("kof-website-publishers") || groupNames.contains("identity-admins"))
         {
            rs.addAll(List.of("cms_page.read", "cms_page.edit", "cms.publish.hasAccess", "nothing.here.hasAccess"));
         }
         if(groupNames.contains("kof-website-analysts") || groupNames.contains("identity-admins"))
         {
            rs.addAll(List.of("kof22.analytics.hasAccess", "nothing.here.hasAccess"));
         }
         return (rs);
      }
   };

   private AdminTestSupport t;
   private AuthentikRuntime runtime;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeEach
   void setUp() throws Exception
   {
      t = AdminTestSupport.create(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP, AuthentikFeature.POLICIES));
      t.config.withHostPermissionSource(SOURCE).withCutoverGuardGroups(List.of("kof-website-publishers"));
      runtime = AuthentikRuntime.forBackend(t.config.getApiBackendName());
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AccessComparison.State state() throws Exception
   {
      runtime.setMapperState(null);
      return (AccessComparison.state(runtime, AuthentikActionUtil.forBackend(t.config.getApiBackendName())));
   }



   /*******************************************************************************
    ** OFF until the host turns the mapper on; then the guard decides; the
    ** owner can override.
    *******************************************************************************/
   @Test
   void statusAndGuard() throws Exception
   {
      assertThat(state().status()).isEqualTo(AccessComparison.Status.OFF);
      assertThat(state().message()).isEqualTo("Policies are saved but NOT enforced at sign-in on this instance (mapper off).");

      t.config.withMapperEnabled(true);
      AccessComparison.State blocked = state();
      assertThat(blocked.status()).isEqualTo(AccessComparison.Status.BLOCKED);
      assertThat(blocked.message()).contains("1 member(s) of kof-website-publishers").contains("operator");

      t.config.withMapperOverride(true);
      assertThat(state().status()).isEqualTo(AccessComparison.Status.OVERRIDDEN);
      t.config.withMapperOverride(false);

      ////////////////////////////////////////////////////////////////////
      // the static fallback for the guarded group covers today's grant //
      ////////////////////////////////////////////////////////////////////
      t.config.withStaticGroupPermissions(Map.of("identity-admins", List.copyOf(SOURCE.userPermissions(null, List.of("identity-admins")))));
      assertThat(state().status()).isEqualTo(AccessComparison.Status.ACTIVE);
      assertThat(state().enforced()).isTrue();
   }



   /*******************************************************************************
    ** Compare Access: today against the mapper, per active person.
    *******************************************************************************/
   @Test
   void compareReport() throws Exception
   {
      List<AccessComparison.Row> rows = AccessComparison.run(t.config, AuthentikActionUtil.forBackend(t.config.getApiBackendName()), runtime.getPermissionCatalog());
      AccessComparison.Row operator = rows.stream().filter(r -> r.username().equals("operator")).findFirst().orElseThrow();
      assertThat(operator.guarded()).isTrue();
      assertThat(operator.removed()).contains("cms_page.read", "cms_page.edit", "kof22.analytics.hasAccess").doesNotContain("cms.publish.hasAccess");
      assertThat(operator.added()).contains("authentik.users.read.hasAccess");
      assertThat(rows).noneMatch(r -> r.username().equals("dormant") || r.username().equals("svc-publisher"));
      assertThat(AccessComparison.guardFailures(rows)).extracting(AccessComparison.Row::username).containsExactly("operator");

      RenderWidgetInput input = new RenderWidgetInput();
      input.setWidgetMetaData(t.qInstance.getWidget("authentikCompareAccess"));
      TableData table = (TableData) new RenderWidgetAction().execute(input).getWidgetData();
      assertThat(table.getRows()).anyMatch(r -> String.valueOf(r.get("user")).equals("operator (guarded)") && String.valueOf(r.get("removed")).contains("cms_page.edit"));
      assertThat(table.getFooterHTML()).contains("guard FAILS for 1");
      assertThat(t.qInstance.getApp("authentikAdmin").getWidgets()).contains("authentikCompareAccess");
   }



   /*******************************************************************************
    ** The banner widget, on the group and policy screens and the Edit Policy
    ** step, and the home's health row.
    *******************************************************************************/
   @Test
   void enforcementBanner() throws Exception
   {
      RenderWidgetInput input = new RenderWidgetInput();
      input.setWidgetMetaData(t.qInstance.getWidget("authentikPolicyEnforcement"));
      String html = ((RawHTML) new RenderWidgetAction().execute(input).getWidgetData()).getHtml();
      assertThat(html).contains("Not enforced.").contains("NOT enforced at sign-in on this instance (mapper off)").contains("data-status=\"OFF\"");

      assertThat(t.qInstance.getTable("authentik_group").getSections()).anyMatch(s -> "authentikPolicyEnforcement".equals(s.getWidgetName()));
      assertThat(t.qInstance.getTable("authentik_policy").getSections().get(0).getWidgetName()).isEqualTo("authentikPolicyEnforcement");
      assertThat(PolicyCutoverWidgets.bannerHtml(new AccessComparison.State(AccessComparison.Status.ACTIVE, "ok <b>", java.time.Instant.now()))).contains("Enforced.").contains("ok &lt;b&gt;");

      String home = com.kingsrook.qbits.authentik.app.AuthentikHomeView.render(com.kingsrook.qbits.authentik.app.AuthentikHomeData.load(t.config));
      assertThat(home).contains("System Health").doesNotContain("Policies at sign-in");
   }



   /*******************************************************************************
    ** While the guard blocks, a sign-in through the mapper gets today's access
    ** (and the floor); once it passes, the policies.
    *******************************************************************************/
   @Test
   void mapperFallsBackWhileBlocked() throws Exception
   {
      t.config.withMapperEnabled(true);
      Map<String, Object> context = new HashMap<>();
      context.put(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY, new JSONObject().put("email", "sam@example.test").put("groups", new JSONArray().put("kof-website-publishers")));

      runtime.setMapperState(null);
      QSession blocked = new QSession();
      new AuthentikGroupPermissionMapper().customizeSession(t.qInstance, blocked, context);
      assertThat(blocked.getPermissions()).contains("cms_page.read", "cms_page.edit", "cms.publish.hasAccess");

      t.config.withStaticGroupPermissions(Map.of("kof-website-publishers", List.of("cms_page.read", "cms_page.edit", "cms.publish.hasAccess")));
      t.config.withCutoverGuardGroups(List.of());
      t.authentik.groupByName("kof-website-publishers").getJSONObject("attributes").put("qqq.io/policy",
         "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"delete\"],\"Resource\":[\"cms_page\"]}]}");
      t.config.withStaticGroupPermissions(Map.of());
      runtime.invalidateCache();
      runtime.setMapperState(null);
      QSession active = new QSession();
      new AuthentikGroupPermissionMapper().customizeSession(t.qInstance, active, context);
      assertThat(active.getPermissions()).contains("cms_page.delete", "cms.publish.hasAccess").doesNotContain("cms_page.edit");
   }



   /*******************************************************************************
    ** Generate Policy From Current Access: the expressible part becomes the
    ** policy, named permissions go to qqq.io/permissions, unknown ones are
    ** skipped; Review shows the document before anything is saved.
    *******************************************************************************/
   @Test
   void generatePolicy() throws Exception
   {
      String analysts = t.authentik.pk("kof-website-analysts");
      RunProcessInput input = new RunProcessInput();
      input.setProcessName("authentikGeneratePolicy");
      input.addValue("recordIds", t.authentik.pk("kof-website-publishers"));
      RunProcessOutput output = new RunProcessAction().execute(input);
      input.setProcessUUID(output.getProcessUUID());
      input.addValue("reason", "seed from today's access");
      input.setStartAfterStep("details");
      output = new RunProcessAction().execute(input);
      assertThat(output.getException()).isEmpty();
      @SuppressWarnings("unchecked")
      List<ProcessSummaryLine> review = (List<ProcessSummaryLine>) output.getValues().get(StreamedETLWithFrontendProcess.FIELD_VALIDATION_SUMMARY);
      assertThat(review).anyMatch(l -> l.getMessage().contains("Generated from current access: {\"PolicySpec\":\"qqq-iam\""));
      assertThat(review).anyMatch(l -> l.getMessage().contains("Skipped (this app does not define them): nothing.here.hasAccess"));
      assertThat(t.changes()).isEmpty();

      AuthentikAdmin.AdminResult result = t.admin().execute(t.admin().withGeneratedPolicy(AdminRequest.of(AdminAction.SAVE_POLICY, t.authentik.pk("kof-website-publishers"), "seed")));
      assertThat(result.ok()).as(result.message()).isTrue();
      JSONObject attributes = t.authentik.groupByName("kof-website-publishers").getJSONObject("attributes");
      assertThat(PolicyParser.parse(attributes.get("qqq.io/policy"), PolicyFormat.DEFAULT)).containsExactlyInAnyOrder("cms_page.read", "cms_page.edit");
      assertThat(attributes.getJSONArray("qqq.io/permissions").toList()).contains("cms.publish.hasAccess");

      assertThat(t.admin().execute(t.admin().withGeneratedPolicy(AdminRequest.of(AdminAction.SAVE_POLICY, t.authentik.pk("kof-website-publishers"), "again"))).noChange()).isTrue();

      t.config.withHostPermissionSource(null);
      assertThat(t.admin().execute(t.admin().withGeneratedPolicy(AdminRequest.of(AdminAction.SAVE_POLICY, analysts, "x"))).message()).contains("no host permission source");
   }
}
