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


import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.policy.PolicyPermissions;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.CapturedContext;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.serviceidentity.QServicePrincipalMetaData;
import com.kingsrook.qqq.backend.core.serviceidentity.ServiceIdentities;
import com.kingsrook.qqq.backend.core.serviceidentity.ServiceIdentitiesMetaData;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Host maintenance uses the audited Save Policy path as the maintenance service
 ** principal (a local principal here: the test instance uses MOCK auth).
 *******************************************************************************/
class AuthentikMaintenanceTest
{
   private static final String GROUP = "kof-website-analysts";
   private static final String OPERATOR = "run-once:KOF22_RUN_ONCE";
   private static final String REASON = "  owner request 2026-10-14: full-access policy for kof22-admins  ";
   private static final String PRINCIPAL_ID = "service:maintenance";
   private static final String AUDIT_REASON = OPERATOR + ": " + REASON;

   private AdminTestSupport t;
   private String fullAccess;



   /*******************************************************************************
    ** A real qbit instance backed by the in-memory Authentik API and audit store.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws Exception
   {
      t = AdminTestSupport.create(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.GROUPS, AuthentikFeature.POLICIES));
      fullAccess = AuthentikMaintenance.fullAccessDocument(t.config);
      Set<String> all = new java.util.TreeSet<>(PolicyPermissions.allPermissions(t.qInstance, t.admin().getUtil().getRuntime().getPermissionCatalog()));
      all.add(IdentityPermission.POLICIES_MANAGE.getSessionPermission());
      ServiceIdentitiesMetaData.declare(t.qInstance, new QServicePrincipalMetaData().withName("maintenance").withLocalPermissions(all.toArray(new String[0])));
   }



   /*******************************************************************************
    ** A system job runs as the maintenance principal (its own grants, nothing
    ** minted here). The audit precedes PATCH, the operator is the principal,
    ** the reason names the job, and an equivalent document is a no-op.
    *******************************************************************************/
   @Test
   void appliesFullAccessAuditedAndIdempotently() throws Exception
   {
      QContext.setQSession(new QSystemUserSession());
      QContext.getActionStack().push(new QueryInput());
      QContext.enterAuthorizedActionScope();
      CapturedContext caller = QContext.capture();
      Set<String> all = PolicyPermissions.allPermissions(t.qInstance, t.admin().getUtil().getRuntime().getPermissionCatalog());
      t.authentik.user(10, "collision", OPERATOR, "internal", true);
      t.config.withBootstrapOperatorSubjects("10");
      FixtureActionUtil.handler = request ->
      {
         QSession session = QContext.getQSession();
         assertThat(session).isNotInstanceOf(QSystemUserSession.class);
         assertThat(ServiceIdentities.isMintedServiceSession(session)).isTrue();
         assertThat(session.getUser().getIdReference()).isEqualTo(PRINCIPAL_ID);
         assertThat(session.getPermissions()).containsAll(all).doesNotContain(PolicyPermissions.FULL_ACCESS);
         assertThat(QContext.getActionStack()).isNotSameAs(caller.actionStack());
         assertThat(QContext.getAuthorizedActionScopeDepth()).isZero();
         if(request.getMethod().equals("PATCH"))
         {
            try
            {
               assertThat(rows(AuthentikLocalTables.ADMIN_ACTION)).singleElement().satisfies(row ->
                  assertThat(row.getValueString("status")).isEqualTo("RUNNING"));
            }
            catch(QException e)
            {
               throw (new AssertionError(e));
            }
         }
         return (t.authentik.handle(request));
      };

      AuthentikAdmin.AdminResult result = apply(GROUP, fullAccess);
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(result.noChange()).isFalse();
      assertThat(result.pending()).isFalse();
      assertThat(QContext.capture()).isEqualTo(caller);
      assertThat(t.authentik.groupByName(GROUP).getJSONObject("attributes").getString(t.config.getPolicyAttribute())).isEqualTo(fullAccess);
      assertThat(rows(AuthentikLocalTables.ADMIN_ACTION)).singleElement().satisfies(row ->
      {
         assertThat(row.getValueString("operator")).isEqualTo(PRINCIPAL_ID);
         assertThat(row.getValueString("reason")).isEqualTo(AUDIT_REASON);
         assertThat(row.getValueString("status")).isEqualTo("SUCCEEDED");
      });
      assertThat(t.authentik.events).singleElement().satisfies(event ->
      {
         assertThat(event.getString("action")).isEqualTo("custom_qqq_admin_action");
         assertThat(event.getJSONObject("context").getString("operator")).isEqualTo(PRINCIPAL_ID);
         assertThat(event.getJSONObject("context").getString("reason")).isEqualTo(AUDIT_REASON);
      });
      assertThat(result.eventPk()).isNotBlank();
      int writes = t.writes().size();
      assertThat(apply(GROUP, new JSONObject(fullAccess).toString(2)).noChange()).isTrue();
      assertThat(t.writes()).hasSize(writes);
      assertThat(rows(AuthentikLocalTables.ADMIN_ACTION)).hasSize(1);
      assertThat(QContext.capture()).isEqualTo(caller);
      assertThat(FixtureActionUtil.REQUESTS).noneMatch(request -> request.getURI().getPath().contains("/core/users/"));
   }



   /*******************************************************************************
    ** Ordinary policies need only their grants and policies.manage (held by the
    ** principal, not added here), and honor
    ** the configured spec/version. The maintenance: prefix is accepted too.
    *******************************************************************************/
   @Test
   void appliesNamedPolicyWithLimitedSession() throws Exception
   {
      ServiceIdentitiesMetaData.declare(t.qInstance, new QServicePrincipalMetaData().withName("policy-maintenance")
         .withLocalPermissions("cms_page.read", IdentityPermission.POLICIES_MANAGE.getSessionPermission()));
      t.config.withMaintenancePrincipal("policy-maintenance");
      t.config.withPolicySpec("host-iam");
      String document = AuthentikMaintenance.fullAccessDocument(t.config).replace("\"Action\":[\"*\"]", "\"Action\":[\"read\"]")
         .replace("\"Resource\":[\"*\"]", "\"Resource\":[\"cms_page\"]");
      FixtureActionUtil.handler = request ->
      {
         assertThat(QContext.getQSession().getPermissions()).containsExactlyInAnyOrder("cms_page.read", IdentityPermission.POLICIES_MANAGE.getSessionPermission());
         return (t.authentik.handle(request));
      };
      AuthentikAdmin.AdminResult result = AuthentikMaintenance.applyPolicy(t.config.getApiBackendName(), GROUP, document, "maintenance:policy", REASON);
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(t.authentik.groupByName(GROUP).getJSONObject("attributes").getString(t.config.getPolicyAttribute())).contains("host-iam", "cms_page");
   }



   /*******************************************************************************
    ** Superuser ancestry remains protected, including when the policy matches.
    *******************************************************************************/
   @Test
   void refusesSuperuserDescendant() throws Exception
   {
      t.authentik.group("protected-child", false, List.of(), List.of(), "authentik Admins");
      t.authentik.groupByName("protected-child").getJSONObject("attributes").put(t.config.getPolicyAttribute(), fullAccess);
      CapturedContext caller = QContext.capture();
      AuthentikAdmin.AdminResult result = apply("protected-child", fullAccess);
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("Superuser groups");
      assertThat(t.writes()).isEmpty();
      assertThat(QContext.capture()).isEqualTo(caller);
   }



   /*******************************************************************************
    ** Exact names must resolve uniquely; neither missing nor ambiguous is safe.
    *******************************************************************************/
   @Test
   void refusesMissingAndAmbiguousGroups() throws Exception
   {
      CapturedContext caller = QContext.capture();
      assertThatThrownBy(() -> apply("kof-website", fullAccess)).hasMessageContaining("exactly one");
      t.authentik.group("duplicate", false, List.of(), List.of());
      t.authentik.groupByName("duplicate").put("name", GROUP);
      assertThatThrownBy(() -> apply(GROUP, fullAccess)).hasMessageContaining("exactly one");
      assertThat(t.writes()).isEmpty();
      assertThat(QContext.capture()).isEqualTo(caller);
   }



   /*******************************************************************************
    ** Invalid inputs fail without contacting Authentik or altering the caller.
    *******************************************************************************/
   @Test
   void validatesInputs() throws Exception
   {
      CapturedContext caller = QContext.capture();
      for(String name : new String[] { null, "", "operator@example.test", "run-once:", "maintenance: " })
      {
         assertThatThrownBy(() -> AuthentikMaintenance.applyPolicy(t.config.getApiBackendName(), GROUP, fullAccess, name, REASON))
            .hasMessageContaining("operator name");
      }
      assertThatThrownBy(() -> AuthentikMaintenance.applyPolicy(t.config.getApiBackendName(), GROUP, fullAccess, OPERATOR, " "))
         .hasMessageContaining("reason");
      assertThatThrownBy(() -> apply(" ", fullAccess)).hasMessageContaining("group name");
      assertThatThrownBy(() -> apply(GROUP, "{bad json")).hasMessageContaining("policy is not valid");
      assertThat(t.writes()).isEmpty();
      assertThat(QContext.capture()).isEqualTo(caller);
   }



   /*******************************************************************************
    ** The kill switch and feature gate are applied even to maintenance jobs.
    *******************************************************************************/
   @Test
   void refusesReadOnlyAndDisabledPolicies() throws Exception
   {
      CapturedContext caller = QContext.capture();
      t.config.withReadOnly(true);
      assertThatThrownBy(() -> apply(GROUP, fullAccess)).hasMessageContaining("read-only");
      t.config.withReadOnly(false).withFeatures(EnumSet.of(AuthentikFeature.READ));
      assertThatThrownBy(() -> apply(GROUP, fullAccess)).hasMessageContaining("POLICIES");
      assertThat(t.writes()).isEmpty();
      assertThat(QContext.capture()).isEqualTo(caller);
   }



   /*******************************************************************************
    ** Approval remains a second person's decision; maintenance only queues it.
    *******************************************************************************/
   @Test
   void queuesTwoPersonApproval() throws Exception
   {
      t.config.withPolicyTwoPersonApproval(true);
      CapturedContext caller = QContext.capture();
      AuthentikAdmin.AdminResult result = apply(GROUP, fullAccess);
      assertThat(result.ok()).isTrue();
      assertThat(result.pending()).isTrue();
      assertThat(t.writes()).isEmpty();
      assertThat(rows(AuthentikLocalTables.ADMIN_ACTION)).singleElement().satisfies(row ->
         assertThat(row.getValueString("status")).isEqualTo("PENDING_APPROVAL"));
      assertThat(rows(AuthentikLocalTables.APPROVAL_REQUEST)).singleElement().satisfies(row ->
      {
         assertThat(row.getValueString("requester")).isEqualTo(PRINCIPAL_ID);
         assertThat(row.getValueString("reason")).isEqualTo(AUDIT_REASON);
      });
      assertThat(QContext.capture()).isEqualTo(caller);
   }



   /*******************************************************************************
    ** A change after the name lookup is caught when execute plans against live data.
    *******************************************************************************/
   @Test
   void refusesStaleGroup() throws Exception
   {
      FixtureActionUtil.handler = request ->
      {
         if(request.getURI().getPath().equals("/api/v3/core/groups/"))
         {
            var response = t.authentik.handle(request);
            t.authentik.groupByName(GROUP).getJSONObject("attributes").put("qqq.io/changed", true);
            return (response);
         }
         return (t.authentik.handle(request));
      };
      AuthentikAdmin.AdminResult result = apply(GROUP, fullAccess);
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("was changed");
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Failed audit persistence prevents the write and still restores the caller.
    *******************************************************************************/
   @Test
   void auditFailurePreventsWrite() throws Exception
   {
      CapturedContext caller = QContext.capture();
      t.qInstance.getTables().remove(t.config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION));
      assertThatThrownBy(() -> apply(GROUP, fullAccess)).isInstanceOf(QException.class);
      assertThat(t.writes()).isEmpty();
      assertThat(QContext.capture()).isEqualTo(caller);
   }



   /*******************************************************************************
    ** Direct system writes are still refused, even with a previously minted permit.
    *******************************************************************************/
   @Test
   void systemSessionStillCannotWrite() throws Exception
   {
      var util = t.admin().getUtil();
      var authorization = util.getRuntime().getGuard().authorize(AdminAction.SAVE_POLICY);
      QSystemUserSession system = new QSystemUserSession();
      system.setUser(QContext.getQSession().getUser());
      QContext.setQSession(system);
      assertThatThrownBy(() -> util.getRuntime().getGuard().authorize(AdminAction.SAVE_POLICY)).hasMessageContaining("System sessions");
      assertThatThrownBy(() -> util.getRuntime().getGuard().checkWrite(AuthentikTables.get(AuthentikTables.GROUP), "update")).hasMessageContaining("System sessions");
      assertThatThrownBy(() -> util.write(authorization, "PATCH", "/core/groups/" + t.authentik.pk(GROUP) + "/", new JSONObject()))
         .hasMessageContaining("System sessions");
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.SAVE_POLICY, t.authentik.pk(GROUP), REASON)
         .with(AuthentikAdmin.POLICY_DOCUMENT, fullAccess)).ok()).isFalse();
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Without a declared principal, or with one that lacks the grants, nothing
    ** is written: maintenance never creates authority.
    *******************************************************************************/
   @Test
   void needsAPrincipalHoldingTheGrants() throws Exception
   {
      CapturedContext caller = QContext.capture();
      t.config.withMaintenancePrincipal("undeclared");
      assertThatThrownBy(() -> apply(GROUP, fullAccess)).hasMessageContaining("not declared");
      assertThat(QContext.capture()).isEqualTo(caller);

      ServiceIdentitiesMetaData.declare(t.qInstance, new QServicePrincipalMetaData().withName("weak")
         .withLocalPermissions(IdentityPermission.POLICIES_MANAGE.getSessionPermission()));
      t.config.withMaintenancePrincipal("weak");
      AuthentikAdmin.AdminResult result;
      try
      {
         result = apply(GROUP, fullAccess);
         assertThat(result.ok()).isFalse();
      }
      catch(QException e)
      {
         assertThat(e).isNotNull();
      }
      assertThat(t.writes()).isEmpty();
      assertThat(QContext.capture()).isEqualTo(caller);
   }



   /*******************************************************************************
    ** Maintenance never changes a service principal's role group.
    *******************************************************************************/
   @Test
   void refusesServicePrincipalGroups() throws Exception
   {
      t.authentik.group("service:kof22-scheduler", false, List.of(), List.of());
      assertThatThrownBy(() -> apply("service:kof22-scheduler", fullAccess)).hasMessageContaining("Service principal groups");
      assertThat(AuthentikMaintenance.isServicePrincipalGroup(new JSONObject().put("name", "x")
         .put("parents_obj", new org.json.JSONArray().put(new JSONObject().put("name", "qqq-service-accounts"))))).isTrue();
      assertThat(t.writes()).isEmpty();
   }



   /*******************************************************************************
    ** Apply using the production public API.
    *******************************************************************************/
   private AuthentikAdmin.AdminResult apply(String group, String document) throws QException
   {
      return (AuthentikMaintenance.applyPolicy(t.config.getApiBackendName(), group, document, OPERATOR, REASON));
   }



   /*******************************************************************************
    ** Inspect the real local audit and approval tables.
    *******************************************************************************/
   private List<QRecord> rows(String table) throws QException
   {
      QueryInput input = new QueryInput();
      input.setTableName(t.config.applyTablePrefix(table));
      return (new QueryAction().execute(input).getRecords());
   }
}
