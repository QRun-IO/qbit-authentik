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


import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.tables.CountAction;
import com.kingsrook.qqq.backend.core.actions.tables.GetAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.module.api.actions.QHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
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
 ** The qbit's own read path (AuthentikActionUtil through QQQ actions) against
 ** a real Authentik, as the service account with the phase 0/1 role: paging,
 ** count, get, key lookups, filters, scope, protection and sensitive-field
 ** stripping. Records the responses it sees as unit-test fixtures.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(60)
class QbitReadContractIT
{
   private static AuthentikTestStack stack;
   private static int                probeCount = 4;

   private QInstance           qInstance;
   private AuthentikQBitConfig config;
   private String              userTable;
   private String              groupTable;



   /*******************************************************************************
    ** Records the last response body per request path.
    *******************************************************************************/
   public static class RecordingActionUtil extends AuthentikActionUtil
   {
      static final Map<String, String> LAST_BODIES = new ConcurrentHashMap<>();



      /*******************************************************************************
       **
       *******************************************************************************/
      @Override
      protected QHttpResponse send(HttpRequestBase request) throws Exception
      {
         QHttpResponse response = super.send(request);
         LAST_BODIES.put(request.getMethod() + " " + request.getURI().getPath(), response.getContent() == null ? "" : response.getContent());
         return (response);
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeAll
   static void beforeAll()
   {
      stack = AuthentikTestStack.get();
      TestApi admin = stack.admin();
      for(int i = 1; i <= probeCount; i++)
      {
         admin.post("/core/users/", new JSONObject().put("username", "read.probe" + i).put("name", "Read Probe " + i).put("email", "read.probe" + i + "@example.test").put("type", "internal").put("path", "users"));
      }
      admin.post("/core/groups/" + admin.groupPk("kof-website-publishers") + "/add_user/", new JSONObject().put("pk", admin.userPk("read.probe1")));
      admin.patch("/core/users/" + admin.userPk("read.probe4") + "/", new JSONObject().put("is_active", false));
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
         .withListCacheTtlSeconds(0);
      qInstance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.useActionUtil(qInstance, config, RecordingActionUtil.class);
      userTable = config.applyPrefix("user");
      groupTable = config.applyPrefix("group");
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
    ** Paging: aligned pages are disjoint and add up to the count; a
    ** non-aligned skip uses 100-row pages and still lands on the right rows.
    *******************************************************************************/
   @Test
   void pagingAndCount() throws QException
   {
      int total = new CountAction().execute(new CountInput(userTable)).getCount();
      assertThat(total).isGreaterThanOrEqualTo(probeCount + 3);

      List<QRecord> all = query(new QQueryFilter().withOrderBy(new QFilterOrderBy("username")));
      assertThat(all).hasSize(total);
      FixtureRecorder.record("users-list", RecordingActionUtil.LAST_BODIES.get("GET /api/v3/core/users/"));

      List<Serializable> pageOne = keys(query(new QQueryFilter().withOrderBy(new QFilterOrderBy("username")).withLimit(2).withSkip(0)));
      List<Serializable> pageTwo = keys(query(new QQueryFilter().withOrderBy(new QFilterOrderBy("username")).withLimit(2).withSkip(2)));
      assertThat(pageOne).hasSize(2).doesNotContainAnyElementsOf(pageTwo);
      assertThat(pageTwo).containsExactlyElementsOf(keys(all).subList(2, 4));

      List<Serializable> odd = keys(query(new QQueryFilter().withOrderBy(new QFilterOrderBy("username")).withLimit(3).withSkip(1)));
      assertThat(odd).containsExactlyElementsOf(keys(all).subList(1, 4));
   }



   /*******************************************************************************
    ** Filters that map to Authentik query parameters.
    *******************************************************************************/
   @Test
   void filters() throws QException
   {
      assertThat(usernames(query(new QQueryFilter(new QFilterCriteria("isActive", QCriteriaOperator.EQUALS, false))))).contains("read.probe4").doesNotContain("read.probe1");
      assertThat(usernames(query(new QQueryFilter(new QFilterCriteria("type", QCriteriaOperator.IN, List.of("service_account")))))).containsExactly(AuthentikTestStack.SERVICE_ACCOUNT);
      assertThat(usernames(query(new QQueryFilter(new QFilterCriteria("groupNames", QCriteriaOperator.EQUALS, "kof-website-publishers"))))).contains("read.probe1").doesNotContain("read.probe2");
      assertThat(usernames(query(new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.CONTAINS, "read.probe"))))).contains("read.probe1", "read.probe2", "read.probe3", "read.probe4");
      assertThat(usernames(query(new QQueryFilter(new QFilterCriteria("lastLogin", QCriteriaOperator.IS_BLANK))))).contains("read.probe2");
      assertThat(usernames(query(new QQueryFilter(new QFilterCriteria("dateJoined", QCriteriaOperator.GREATER_THAN_OR_EQUALS, "2000-01-01"))))).contains("read.probe3");

      assertThatThrownBy(() -> query(new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, "a"), new QFilterCriteria("email", QCriteriaOperator.EQUALS, "b")).withBooleanOperator(QQueryFilter.BooleanOperator.OR)))
         .isInstanceOf(QUserFacingException.class);
      assertThatThrownBy(() -> query(new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.NOT_EQUALS, "a"))))
         .isInstanceOf(QUserFacingException.class);
   }



   /*******************************************************************************
    ** Get by key, key lookups, scope (internal service accounts are invisible),
    ** and protection markers.
    *******************************************************************************/
   @Test
   void getKeyLookupScopeAndProtection() throws QException
   {
      TestApi admin      = stack.admin();
      int     probe      = admin.userPk("read.probe2");
      int     breakGlass = admin.userPk(AuthentikTestStack.BREAK_GLASS);
      int     sa         = admin.userPk(AuthentikTestStack.SERVICE_ACCOUNT);
      int     outpost    = admin.first("/core/users/?type=internal_service_account").getInt("pk");

      QRecord record = new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey(probe));
      assertThat(record.getValueString("username")).isEqualTo("read.probe2");
      assertThat(record.getValueBoolean("isProtected")).isFalse();
      FixtureRecorder.record("user-get", RecordingActionUtil.LAST_BODIES.get("GET /api/v3/core/users/" + probe + "/"));

      assertThat(new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey(breakGlass)).getValueBoolean("isProtected")).isTrue();
      assertThat(new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey(sa)).getValueBoolean("isProtected")).isTrue();
      assertThat(new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey(outpost))).as("internal service accounts are out of scope").isNull();
      assertThat(new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey(999_999))).isNull();

      List<QRecord> lookup = query(new QQueryFilter(new QFilterCriteria("pk", QCriteriaOperator.IN, List.of(probe, breakGlass, outpost))));
      assertThat(usernames(lookup)).containsExactlyInAnyOrder("read.probe2", AuthentikTestStack.BREAK_GLASS);
   }



   /*******************************************************************************
    ** Sensitive fields need identity.audit.read; reading needs users.read.
    *******************************************************************************/
   @Test
   void permissionsAndSensitiveFields() throws QException
   {
      QRecord plain = query(new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, AuthentikTestStack.BREAK_GLASS))).get(0);
      assertThat(plain.getValues()).doesNotContainKey("attributes");
      assertThat(plain.getValueString("qqqAttributes")).contains("qqq.io/protected");

      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.USERS_READ, IdentityPermission.AUDIT_READ);
      QRecord audit = query(new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, AuthentikTestStack.BREAK_GLASS))).get(0);
      assertThat(audit.getValueString("attributes")).contains("qqq.io/protected");

      AuthentikTestSupport.loginWith(qInstance);
      assertThatThrownBy(() -> query(new QQueryFilter())).isInstanceOf(QPermissionDeniedException.class);
   }



   /*******************************************************************************
    ** Groups: list with parents/children, member filter.
    *******************************************************************************/
   @Test
   void groups() throws QException
   {
      QueryInput input = new QueryInput(groupTable);
      input.setFilter(new QQueryFilter(new QFilterCriteria("memberUsername", QCriteriaOperator.EQUALS, "read.probe1")));
      List<QRecord> groups = new QueryAction().execute(input).getRecords();
      assertThat(groups.stream().map(r -> r.getValueString("name")).toList()).containsExactly("kof-website-publishers");

      input.setFilter(new QQueryFilter(new QFilterCriteria("name", QCriteriaOperator.EQUALS, "identity-admins")));
      QRecord identityAdmins = new QueryAction().execute(input).getRecords().get(0);
      assertThat(identityAdmins.getValueString("permissions")).isEqualTo("identity.*");
      FixtureRecorder.record("groups-list", RecordingActionUtil.LAST_BODIES.get("GET /api/v3/core/groups/"));
   }



   /*******************************************************************************
    ** Error and version responses, for the unit fixtures.
    *******************************************************************************/
   @Test
   void recordErrorAndVersionFixtures()
   {
      TestApi sa = stack.serviceAccount();
      TestApi.Response badDate = sa.get("/core/users/?last_login__lt=not-a-date");
      assertThat(badDate.status()).isEqualTo(400);
      FixtureRecorder.record("error-400-bad-filter", badDate.body());

      TestApi.Response forbidden = sa.post("/core/groups/", new JSONObject().put("name", "x"));
      assertThat(forbidden.status()).isEqualTo(403);
      FixtureRecorder.record("error-403", forbidden.body());

      FixtureRecorder.record("admin-version", sa.getOk("/admin/version/").toString());
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<QRecord> query(QQueryFilter filter) throws QException
   {
      QueryInput input = new QueryInput(userTable);
      input.setFilter(filter);
      return (new QueryAction().execute(input).getRecords());
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static List<Serializable> keys(List<QRecord> records)
   {
      return (records.stream().map(r -> r.getValue("pk")).toList());
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static List<String> usernames(List<QRecord> records)
   {
      List<String> rs = new ArrayList<>();
      records.forEach(r -> rs.add(r.getValueString("username")));
      return (rs);
   }

}
