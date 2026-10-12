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

package com.kingsrook.qbits.authentik;


import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.authentik.client.AuthentikFilterMapper;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.client.FixtureRouter;
import com.kingsrook.qbits.authentik.drift.AuthentikDriftReport;
import com.kingsrook.qbits.authentik.drift.DriftFinding;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.tables.GetAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Regression tests for the phase 0/1 review findings.
 *******************************************************************************/
class ReviewFixesTest
{
   private final AuthentikFilterMapper mapper = new AuthentikFilterMapper();



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
    ** Search is plain text only (QLSearch could reach sensitive fields).
    *******************************************************************************/
   @Test
   void searchIsPlainTextOnly() throws QException
   {
      for(String term : List.of("attributes.x = \"y\"", "a ~ b", "(x)", "it's", "a and b", "x OR y", "a\\b"))
      {
         assertThatThrownBy(() -> mapper.map(AuthentikTables.get(AuthentikTables.USER), new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.CONTAINS, term)), true))
            .as(term).isInstanceOf(QUserFacingException.class).hasMessageContaining("plain text");
      }
      assertThat(mapper.map(AuthentikTables.get(AuthentikTables.USER), new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.CONTAINS, "read.probe-1")), false).params().get(0).getValue())
         .isEqualTo("read.probe-1");
   }



   /*******************************************************************************
    ** Sorting by the key falls back to the default; booleans are strict; a
    ** criterion without a field is refused.
    *******************************************************************************/
   @Test
   void orderingBooleansAndNullFields() throws QException
   {
      assertThat(mapper.map(AuthentikTables.get(AuthentikTables.USER), new QQueryFilter().withOrderBy(new QFilterOrderBy("pk", false)), false).params().get(0).getValue()).isEqualTo("username");
      assertThatThrownBy(() -> mapper.map(AuthentikTables.get(AuthentikTables.USER), new QQueryFilter(new QFilterCriteria("isActive", QCriteriaOperator.EQUALS, "maybe")), false))
         .isInstanceOf(QUserFacingException.class);
      assertThatThrownBy(() -> mapper.map(AuthentikTables.get(AuthentikTables.USER), new QQueryFilter(new QFilterCriteria(null, QCriteriaOperator.EQUALS, "x")), false))
         .isInstanceOf(QUserFacingException.class);
   }



   /*******************************************************************************
    ** Config: https unless loopback or explicitly allowed; groupScope refused.
    *******************************************************************************/
   @Test
   void configChecks()
   {
      List<String> errors = new ArrayList<>();
      AuthentikTestSupport.unitConfig().withBaseUrl("http://auth.example.test").validate(new QInstance(), errors);
      assertThat(errors).anyMatch(e -> e.contains("https"));

      for(String ok : List.of("http://localhost:9000", "http://127.0.0.1:9000"))
      {
         List<String> none = new ArrayList<>();
         AuthentikTestSupport.unitConfig().withBaseUrl(ok).validate(new QInstance(), none);
         assertThat(none).as(ok).isEmpty();
      }
      List<String> allowed = new ArrayList<>();
      AuthentikTestSupport.unitConfig().withBaseUrl("http://auth.internal").withAllowInsecureHttp(true).validate(new QInstance(), allowed);
      assertThat(allowed).isEmpty();

      List<String> scope = new ArrayList<>();
      AuthentikTestSupport.unitConfig().withGroupScopeNamePrefix("kof").validate(new QInstance(), scope);
      assertThat(scope).anyMatch(e -> e.contains("groupScopeNamePrefix"));
   }



   /*******************************************************************************
    ** Malformed qqq.io/* attributes are kept as findings, not silently dropped.
    *******************************************************************************/
   @Test
   void malformedAttributes()
   {
      GroupGraph graph = GroupGraph.fromGroups(List.of(new JSONObject().put("pk", "g").put("name", "g").put("parents", new JSONArray())
         .put("attributes", new JSONObject().put("qqq.io/permissions", new JSONArray().put("cms.edit").put(5).put(new JSONObject())).put("qqq.io/app-access", 12))));
      assertThat(graph.byPk("g").permissions()).containsExactly("cms.edit");
      assertThat(graph.byPk("g").malformed()).hasSize(3);
   }



   /*******************************************************************************
    ** Through the action util: limit 0, ".." keys, scope widening refused,
    ** malformed attributes reported by the drift report.
    *******************************************************************************/
   @Test
   void actionUtilAndDrift() throws QException
   {
      FixtureActionUtil.reset();
      AuthentikQBitConfig config = AuthentikTestSupport.unitConfig().withGroupCacheTtlSeconds(0).withUserScopePathStartsWith("users");
      QInstance qInstance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.useActionUtil(qInstance, config, FixtureActionUtil.class);
      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.values());
      FixtureRouter router = new FixtureRouter().install();

      QueryInput zero = new QueryInput(config.applyPrefix("user"));
      zero.setFilter(new QQueryFilter().withLimit(0));
      assertThat(new QueryAction().execute(zero).getRecords()).isEmpty();

      assertThat(new GetAction().executeForRecord(new GetInput(config.applyPrefix("group")).withPrimaryKey(".."))).isNull();
      assertThat(FixtureActionUtil.REQUESTS.stream().noneMatch(r -> r.getURI().getPath().contains(".."))).isTrue();

      QueryInput widen = new QueryInput(config.applyPrefix("user"));
      widen.setFilter(new QQueryFilter(new QFilterCriteria("type", QCriteriaOperator.EQUALS, "internal_service_account")));
      assertThatThrownBy(() -> new QueryAction().execute(widen)).hasMessageContaining("outside the users");
      QueryInput otherPath = new QueryInput(config.applyPrefix("user"));
      otherPath.setFilter(new QQueryFilter(new QFilterCriteria("path", QCriteriaOperator.STARTS_WITH, "service-accounts")));
      assertThatThrownBy(() -> new QueryAction().execute(otherPath)).hasMessageContaining("outside the users");

      router.groups.get(0).put("attributes", new JSONObject().put("qqq.io/permissions", 42));
      router.refreshGraph();
      List<DriftFinding> findings = new AuthentikDriftReport(com.kingsrook.qbits.authentik.client.AuthentikActionUtil.forBackend(config.getApiBackendName()), config).run();
      assertThat(findings).anyMatch(f -> f.check().equals("group attributes") && f.message().startsWith("Malformed entry"));
   }

}
