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

package com.kingsrook.qbits.authentik.drift;


import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.client.FixtureRouter;
import com.kingsrook.qbits.authentik.metadata.AuthentikDriftReportWidgetRenderer;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.TableData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Drift report on the recorded 2026.8.3 contract-test instance, and the
 ** scenarios it must catch.
 *******************************************************************************/
class AuthentikDriftReportTest
{
   private QInstance           qInstance;
   private AuthentikQBitConfig config;
   private FixtureRouter       router;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeEach
   void beforeEach() throws QException
   {
      FixtureActionUtil.reset();
      config = AuthentikTestSupport.unitConfig().withApplicationsInScope(List.of("kof22-website-prod")).withGroupCacheTtlSeconds(0);
      qInstance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.useActionUtil(qInstance, config, FixtureActionUtil.class);
      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.values());
      router = new FixtureRouter().install();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @AfterEach
   void afterEach()
   {
      QContext.clear();
      FixtureActionUtil.reset();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<DriftFinding> run() throws QException
   {
      router.refreshGraph();
      return (new AuthentikDriftReport(AuthentikActionUtil.forBackend(config.getApiBackendName()), config).run());
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static DriftFinding find(List<DriftFinding> findings, String check, DriftFinding.Severity severity)
   {
      return (findings.stream().filter(f -> f.check().equals(check) && f.severity() == severity).findFirst().orElse(null));
   }



   /*******************************************************************************
    ** The recorded instance, as the contract test saw it.
    *******************************************************************************/
   @Test
   void recordedInstance() throws QException
   {
      List<DriftFinding> findings = run();
      assertThat(find(findings, "version", DriftFinding.Severity.OK)).isNotNull();
      assertThat(find(findings, "blueprints", DriftFinding.Severity.OK)).isNotNull();
      assertThat(find(findings, "service account", DriftFinding.Severity.OK)).isNotNull();
      assertThat(find(findings, "break-glass", DriftFinding.Severity.OK)).isNotNull();
      assertThat(findings).anyMatch(f -> f.check().equals("group attributes") && f.message().contains("no.such.permission"));
      assertThat(find(findings, "service-account activity", DriftFinding.Severity.ERROR)).as("the lockout probes on break-glass").isNotNull();
      assertThat(findings.get(0).severity()).isEqualTo(DriftFinding.Severity.ERROR);
   }



   /*******************************************************************************
    ** Unsafe states.
    *******************************************************************************/
   @Test
   void unsafeStates() throws QException
   {
      JSONObject serviceAccount = router.users.stream().filter(u -> u.getString("username").equals("qqq-kof22-admin-idadmin")).findFirst().orElseThrow();
      serviceAccount.put("is_superuser", true).put("type", "internal").put("is_active", false).put("attributes", new JSONObject())
         .put("groups_obj", new JSONArray().put(new JSONObject().put("pk", "x").put("name", "authentik Admins")));
      router.tokens.add(new JSONObject(router.tokens.get(0).toString()).put("identifier", "second"));
      router.blueprints.get(0).put("status", "error");
      router.users.forEach(u -> u.put("attributes", new JSONObject()));
      router.groups.forEach(g -> g.put("users_obj", new JSONArray()).put("users", new JSONArray()));
      router.events.clear();

      List<DriftFinding> findings = run();
      assertThat(findings).anyMatch(f -> f.check().equals("service account") && f.severity() == DriftFinding.Severity.ERROR && f.message().contains("SUPERUSER"));
      assertThat(findings).anyMatch(f -> f.check().equals("service account") && f.message().contains("type is internal"));
      assertThat(findings).anyMatch(f -> f.check().equals("service account") && f.message().contains("inactive"));
      assertThat(findings).anyMatch(f -> f.check().equals("service account") && f.message().contains("qqq.io/protected"));
      assertThat(findings).anyMatch(f -> f.check().equals("service account") && f.message().contains("2 API tokens"));
      assertThat(find(findings, "blueprints", DriftFinding.Severity.ERROR)).isNotNull();
      assertThat(find(findings, "break-glass", DriftFinding.Severity.ERROR)).isNotNull();
      assertThat(find(findings, "identity admins", DriftFinding.Severity.ERROR)).isNotNull();
      assertThat(find(findings, "service-account activity", DriftFinding.Severity.OK)).isNotNull();
   }



   /*******************************************************************************
    ** Missing service account, version mismatch, a check that cannot run.
    *******************************************************************************/
   @Test
   void missingAndUnreachable() throws QException
   {
      router.users.removeIf(u -> u.getString("username").equals("qqq-kof22-admin-idadmin"));
      config.withExpectedServerVersion("2099.1");
      router.blueprints.clear();
      FixtureActionUtil.handler = request -> request.getURI().getPath().endsWith("/managed/blueprints/")
         ? FixtureActionUtil.response(403, "{\"detail\":\"You do not have permission to perform this action.\"}")
         : router.apply(request);

      List<DriftFinding> findings = run();
      assertThat(find(findings, "service account", DriftFinding.Severity.ERROR)).isNotNull();
      assertThat(find(findings, "version", DriftFinding.Severity.WARNING)).isNotNull();
      assertThat(findings).anyMatch(f -> f.check().equals("blueprints") && f.message().startsWith("Check could not run"));
   }



   /*******************************************************************************
    ** The widget renders the findings, and needs authentik.admin.
    *******************************************************************************/
   @Test
   void widgetRendersAndChecksPermission() throws QException
   {
      RenderWidgetInput input = new RenderWidgetInput();
      input.setWidgetMetaData(qInstance.getWidget(config.applyPrefix("driftReport")));
      TableData table = (TableData) new AuthentikDriftReportWidgetRenderer().render(input).getWidgetData();
      assertThat(table.getColumns()).hasSize(4);
      assertThat(table.getRows()).isNotEmpty();
      assertThat(table.getRows().get(0).get("severity")).isEqualTo("ERROR");

      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.USERS_READ);
      assertThatThrownBy(() -> new AuthentikDriftReportWidgetRenderer().render(input)).isInstanceOf(QPermissionDeniedException.class);
   }

}
