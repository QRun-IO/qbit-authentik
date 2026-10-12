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


import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import com.kingsrook.qbits.authentik.drift.AuthentikDriftReport;
import com.kingsrook.qbits.authentik.drift.DriftFinding;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.tables.CountAction;
import com.kingsrook.qqq.backend.core.actions.tables.GetAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Phase 1 read MVP against Authentik 2026.8.3, as the service account with
 ** the phase 0/1 role: memberships (virtual table), sessions and events
 ** (identity.audit.read), effective permissions and inherited superuser on
 ** groups, and the drift report. Runs after SuperuserFloorIT, whose lockout
 ** probes are exactly what the drift report must flag. Records fixtures.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(70)
class Phase1ReadContractIT
{
   private static AuthentikTestStack stack;

   private QInstance           qInstance;
   private AuthentikQBitConfig config;



   /*******************************************************************************
    ** A member of a child of identity-admins (inherited identity.*), and a real
    ** session for akadmin.
    *******************************************************************************/
   @BeforeAll
   static void beforeAll() throws Exception
   {
      stack = AuthentikTestStack.get();
      TestApi admin = stack.admin();
      admin.post("/core/groups/", new JSONObject().put("name", "phase1-child-of-identity-admins").put("parents", new JSONArray().put(admin.groupPk("identity-admins"))));
      admin.post("/core/users/", new JSONObject().put("username", "phase1.member").put("name", "Phase One").put("email", "phase1@example.test").put("type", "internal").put("path", "users"));
      admin.post("/core/groups/" + admin.groupPk("phase1-child-of-identity-admins") + "/add_user/", new JSONObject().put("pk", admin.userPk("phase1.member")));
      admin.post("/core/groups/", new JSONObject().put("name", "phase1-bad-attributes").put("attributes",
         new JSONObject().put("qqq.io/permissions", new JSONArray().put("no.such.permission")).put("qqq.io/app-access", new JSONArray().put("not-in-scope-app"))));

      assertThat(FlowLogin.login(stack.baseUrl(), "akadmin", AuthentikTestStack.BOOTSTRAP_PASSWORD)).isEqualTo("xak-flow-redirect");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeEach
   void beforeEach() throws QException
   {
      config = new AuthentikQBitConfig()
         .withBaseUrl(stack.baseUrl())
         .withApiToken(stack.serviceAccountToken())
         .withAppKey("kof22-admin")
         .withApplicationsInScope(List.of(AuthentikTestStack.APP_SLUG))
         .withListCacheTtlSeconds(0)
         .withGroupCacheTtlSeconds(0);
      qInstance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.useActionUtil(qInstance, config, QbitReadContractIT.RecordingActionUtil.class);
      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.USERS_READ);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @AfterEach
   void afterEach()
   {
      QContext.clear();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<QRecord> query(String table, QQueryFilter filter) throws QException
   {
      QueryInput input = new QueryInput(config.applyPrefix(table));
      input.setFilter(filter);
      return (new QueryAction().execute(input).getRecords());
   }



   /*******************************************************************************
    ** Memberships by group, by user, by key, and a full sweep.
    *******************************************************************************/
   @Test
   void memberships() throws QException
   {
      TestApi admin   = stack.admin();
      String  groupPk = admin.groupPk("phase1-child-of-identity-admins");
      int     userPk  = admin.userPk("phase1.member");

      List<QRecord> byGroup = query("groupMember", new QQueryFilter(new QFilterCriteria("groupName", QCriteriaOperator.EQUALS, "phase1-child-of-identity-admins")));
      assertThat(byGroup).extracting(r -> r.getValueString("username")).containsExactly("phase1.member");
      assertThat(byGroup.get(0).getValueString("id")).isEqualTo(groupPk + ":" + userPk);
      assertThat(byGroup.get(0).getValueString("email")).isEqualTo("phase1@example.test");
      FixtureRecorder.record("group-with-users", QbitReadContractIT.RecordingActionUtil.LAST_BODIES.get("GET /api/v3/core/groups/"));

      List<QRecord> byUser = query("groupMember", new QQueryFilter(new QFilterCriteria("userPk", QCriteriaOperator.EQUALS, userPk)));
      assertThat(byUser).extracting(r -> r.getValueString("groupName")).containsExactly("phase1-child-of-identity-admins");

      assertThat(query("groupMember", new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, AuthentikTestStack.BREAK_GLASS))))
         .extracting(r -> r.getValueString("groupName")).containsExactly(AuthentikTestStack.SUPERUSER_GROUP);

      QRecord byKey = new GetAction().executeForRecord(new GetInput(config.applyPrefix("groupMember")).withPrimaryKey(groupPk + ":" + userPk));
      assertThat(byKey.getValueString("username")).isEqualTo("phase1.member");

      int all = new CountAction().execute(new CountInput(config.applyPrefix("groupMember"))).getCount();
      assertThat(all).isGreaterThanOrEqualTo(3);
      FixtureRecorder.record("groups-list-with-users", QbitReadContractIT.RecordingActionUtil.LAST_BODIES.get("GET /api/v3/core/groups/"));
   }



   /*******************************************************************************
    ** Groups: inherited superuser and effective permissions (incl. parents);
    ** users: effective permissions through a child group.
    *******************************************************************************/
   @Test
   void effectivePermissionsAndInheritedSuperuser() throws QException
   {
      QRecord child = query("group", new QQueryFilter(new QFilterCriteria("name", QCriteriaOperator.EQUALS, "phase1-child-of-identity-admins"))).get(0);
      assertThat(child.getValueString("permissions")).isNull();
      assertThat(child.getValueString("effectivePermissions")).contains("identity.memberships.manage.hasAccess", "identity.users.read.hasAccess");
      assertThat(child.getValueBoolean("isSuperuserInherited")).isFalse();

      QRecord admins = query("group", new QQueryFilter(new QFilterCriteria("name", QCriteriaOperator.EQUALS, AuthentikTestStack.SUPERUSER_GROUP))).get(0);
      assertThat(admins.getValueBoolean("isSuperuserInherited")).isTrue();

      QRecord member = query("user", new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, "phase1.member"))).get(0);
      assertThat(member.getValueString("effectivePermissions")).contains("identity.permissions.manage.hasAccess");
   }



   /*******************************************************************************
    ** Sessions and events: audit.read only.
    *******************************************************************************/
   @Test
   void sessionsAndEvents() throws QException
   {
      assertThatThrownBy(() -> query("session", new QQueryFilter())).isInstanceOf(QPermissionDeniedException.class);
      assertThatThrownBy(() -> query("event", new QQueryFilter())).isInstanceOf(QPermissionDeniedException.class);

      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.USERS_READ, IdentityPermission.AUDIT_READ);
      List<QRecord> sessions = query("session", new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, "akadmin")));
      assertThat(sessions).isNotEmpty();
      assertThat(sessions.get(0).getValueString("lastIp")).isNotBlank();
      FixtureRecorder.record("sessions-list", QbitReadContractIT.RecordingActionUtil.LAST_BODIES.get("GET /api/v3/core/authenticated_sessions/"));

      List<QRecord> logins = query("event", new QQueryFilter(new QFilterCriteria("action", QCriteriaOperator.EQUALS, "login"), new QFilterCriteria("username", QCriteriaOperator.EQUALS, "akadmin")).withLimit(5));
      assertThat(logins).isNotEmpty();
      assertThat(logins.get(0).getValueString("action")).isEqualTo("login");

      List<QRecord> modelEvents = query("event", new QQueryFilter(new QFilterCriteria("action", QCriteriaOperator.IN, List.of("model_created", "model_updated")),
         new QFilterCriteria("modelName", QCriteriaOperator.EQUALS, "group")).withLimit(10));
      assertThat(modelEvents).isNotEmpty().allMatch(r -> "group".equals(r.getValueString("modelName")));
      FixtureRecorder.record("events-list", QbitReadContractIT.RecordingActionUtil.LAST_BODIES.get("GET /api/v3/events/events/"));
   }



   /*******************************************************************************
    ** The drift report on the contract instance. Expected: blueprints, service
    ** account and break-glass OK; the bad attributes flagged; and the
    ** service account's lockout probes on break-glass (SuperuserFloorIT)
    ** flagged as an ERROR.
    *******************************************************************************/
   @Test
   void driftReport() throws QException
   {
      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.values());
      List<DriftFinding> findings = new AuthentikDriftReport(AuthentikActionUtil.forBackend(config.getApiBackendName()), config).run();
      findings.forEach(f -> System.out.println("[drift] " + f));

      assertThat(findings).anyMatch(f -> f.check().equals("version") && f.severity() == DriftFinding.Severity.OK);
      assertThat(findings).anyMatch(f -> f.check().equals("break-glass") && f.severity() == DriftFinding.Severity.OK && f.subject().contains(AuthentikTestStack.BREAK_GLASS));
      assertThat(findings).anyMatch(f -> f.check().equals("service account") && f.severity() == DriftFinding.Severity.OK);
      assertThat(findings).anyMatch(f -> f.check().equals("identity admins") && f.subject().contains("phase1.member"));
      assertThat(findings).anyMatch(f -> f.check().equals("group attributes") && f.subject().equals("phase1-bad-attributes") && f.message().contains("no.such.permission"));
      assertThat(findings).anyMatch(f -> f.check().equals("group attributes") && f.subject().equals("phase1-bad-attributes") && f.message().contains("not-in-scope-app"));
      assertThat(findings).anyMatch(f -> f.check().equals("service-account activity") && f.severity() == DriftFinding.Severity.ERROR);
      assertThat(findings.get(0).severity()).isEqualTo(DriftFinding.Severity.ERROR);

      FixtureRecorder.record("blueprints-list", QbitReadContractIT.RecordingActionUtil.LAST_BODIES.get("GET /api/v3/managed/blueprints/"));
      FixtureRecorder.record("tokens-list", QbitReadContractIT.RecordingActionUtil.LAST_BODIES.get("GET /api/v3/core/tokens/"));
      FixtureRecorder.record("events-by-service-account", QbitReadContractIT.RecordingActionUtil.LAST_BODIES.get("GET /api/v3/events/events/"));
   }

}
