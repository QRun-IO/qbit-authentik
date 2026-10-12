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

package com.kingsrook.qbits.authentik.client;


import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
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
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Phase 1 tables over the recorded fixtures: the virtual membership table,
 ** sessions, events, and the graph-derived fields on users and groups.
 *******************************************************************************/
class Phase1TablesTest
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
      config = AuthentikTestSupport.unitConfig().withGroupCacheTtlSeconds(0);
      qInstance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.useActionUtil(qInstance, config, FixtureActionUtil.class);
      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.USERS_READ);
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
   private List<QRecord> query(String table, QQueryFilter filter) throws QException
   {
      QueryInput input = new QueryInput(config.applyPrefix(table));
      input.setFilter(filter);
      return (new QueryAction().execute(input).getRecords());
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private JSONObject group(String name)
   {
      return (router.groups.stream().filter(g -> g.getString("name").equals(name)).findFirst().orElseThrow());
   }



   /*******************************************************************************
    ** Memberships: by group name / pk, by user, by key, sweep, ordering, paging.
    *******************************************************************************/
   @Test
   void memberships() throws QException
   {
      JSONObject child   = group("phase1-child-of-identity-admins");
      JSONObject member  = child.getJSONArray("users_obj").getJSONObject(0);
      int        userPk  = member.getInt("pk");
      String     groupPk = child.getString("pk");

      ////////////////////////////////////////////////////////////////////////////
      // the recorded users list predates this user: add it, with its groups   //
      ////////////////////////////////////////////////////////////////////////////
      router.users.add(new JSONObject(member.toString()).put("type", "internal").put("path", "users")
         .put("groups_obj", new org.json.JSONArray().put(new JSONObject().put("pk", groupPk).put("name", child.getString("name")))));

      List<QRecord> byName = query("groupMember", new QQueryFilter(new QFilterCriteria("groupName", QCriteriaOperator.EQUALS, "phase1-child-of-identity-admins")));
      assertThat(byName).extracting(r -> r.getValueString("username")).containsExactly("phase1.member");
      assertThat(byName.get(0).getValueString("id")).isEqualTo(groupPk + ":" + userPk);

      assertThat(query("groupMember", new QQueryFilter(new QFilterCriteria("groupPk", QCriteriaOperator.IN, List.of(groupPk, "missing"))))).hasSize(1);
      assertThat(query("groupMember", new QQueryFilter(new QFilterCriteria("userPk", QCriteriaOperator.EQUALS, userPk)))).extracting(r -> r.getValueString("groupName")).contains("phase1-child-of-identity-admins");
      assertThat(query("groupMember", new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, "phase1.member")))).isNotEmpty();
      assertThat(query("groupMember", new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, "nobody")))).isEmpty();
      assertThat(query("groupMember", new QQueryFilter(new QFilterCriteria("userPk", QCriteriaOperator.EQUALS, 999999)))).isEmpty();

      QRecord byKey = new GetAction().executeForRecord(new GetInput(config.applyPrefix("groupMember")).withPrimaryKey(groupPk + ":" + userPk));
      assertThat(byKey.getValueString("username")).isEqualTo("phase1.member");
      assertThat(new GetAction().executeForRecord(new GetInput(config.applyPrefix("groupMember")).withPrimaryKey("no-colon"))).isNull();

      List<QRecord> all = query("groupMember", new QQueryFilter());
      int           count = new CountAction().execute(new CountInput(config.applyPrefix("groupMember"))).getCount();
      assertThat(all).hasSize(count).isNotEmpty();
      assertThat(all).extracting(r -> r.getValueString("groupName")).isSortedAccordingTo(String.CASE_INSENSITIVE_ORDER);

      List<QRecord> byUserDesc = query("groupMember", new QQueryFilter().withOrderBy(new QFilterOrderBy("username", false)).withLimit(2).withSkip(1));
      assertThat(byUserDesc).hasSize(2);

      assertThatThrownBy(() -> query("groupMember", new QQueryFilter(new QFilterCriteria("email", QCriteriaOperator.EQUALS, "x")))).isInstanceOf(QUserFacingException.class);
   }



   /*******************************************************************************
    ** With a user scope, membership rows are checked member by member.
    *******************************************************************************/
   @Test
   void membershipsHonourUserScope() throws QException
   {
      config.withUserScopePathStartsWith("nowhere/");
      assertThat(query("groupMember", new QQueryFilter(new QFilterCriteria("groupName", QCriteriaOperator.EQUALS, "phase1-child-of-identity-admins")))).isEmpty();
   }



   /*******************************************************************************
    ** Graph-derived fields: effective permissions (inherited) and inherited
    ** superuser.
    *******************************************************************************/
   @Test
   void derivedFields() throws QException
   {
      FixtureActionUtil.handler = request -> request.getURI().getPath().endsWith("/core/groups/")
         ? FixtureActionUtil.response(200, FixtureRouter.page(router.groups).toString())
         : router.apply(request);

      List<QRecord> groups = query("group", new QQueryFilter());
      QRecord       child  = groups.stream().filter(g -> "phase1-child-of-identity-admins".equals(g.getValueString("name"))).findFirst().orElseThrow();
      assertThat(child.getValueString("effectivePermissions")).contains("identity.memberships.manage.hasAccess");
      assertThat(child.getValueBoolean("isSuperuserInherited")).isFalse();
      QRecord admins = groups.stream().filter(g -> "authentik Admins".equals(g.getValueString("name"))).findFirst().orElseThrow();
      assertThat(admins.getValueBoolean("isSuperuserInherited")).isTrue();

      JSONObject member = router.users.stream().filter(u -> u.getString("username").equals("read.probe1")).findFirst().orElseThrow();
      FixtureActionUtil.handler = router;
      QRecord user = new GetAction().executeForRecord(new GetInput(config.applyPrefix("user")).withPrimaryKey(member.getInt("pk")));
      assertThat(user.getValue("effectivePermissions")).isNotNull();
   }



   /*******************************************************************************
    ** Sessions and events need identity.audit.read and map recorded rows.
    *******************************************************************************/
   @Test
   void sessionsAndEvents() throws QException
   {
      assertThatThrownBy(() -> query("session", new QQueryFilter())).isInstanceOf(QPermissionDeniedException.class);

      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.USERS_READ, IdentityPermission.AUDIT_READ);
      FixtureActionUtil.handler = request -> request.getURI().getPath().endsWith("/events/events/")
         ? FixtureActionUtil.response(200, FixtureActionUtil.fixture("events-list"))
         : router.apply(request);

      List<QRecord> sessions = query("session", new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, "akadmin")));
      assertThat(sessions).isNotEmpty();
      assertThat(sessions.get(0).getValueString("uuid")).isNotBlank();
      assertThat(sessions.get(0).getValue("lastUsed")).isInstanceOf(java.time.Instant.class);

      List<QRecord> events = query("event", new QQueryFilter(new QFilterCriteria("modelName", QCriteriaOperator.EQUALS, "group")).withLimit(5));
      assertThat(events).isNotEmpty().allMatch(e -> "group".equals(e.getValueString("modelName")));
      assertThat(events.get(0).getValueString("modelApp")).isEqualTo("authentik_core");
      assertThat(events.get(0).getValue("created")).isInstanceOf(java.time.Instant.class);
   }

}
