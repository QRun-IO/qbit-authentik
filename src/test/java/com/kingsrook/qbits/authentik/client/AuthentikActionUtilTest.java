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


import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.tables.CountAction;
import com.kingsrook.qqq.backend.core.actions.tables.DeleteAction;
import com.kingsrook.qqq.backend.core.actions.tables.GetAction;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import org.apache.http.client.methods.HttpRequestBase;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Unit tests for AuthentikActionUtil over recorded 2026.8.3 fixtures
 ** (src/test/resources/fixtures/2026.8.3, captured by the contract tests).
 *******************************************************************************/
class AuthentikActionUtilTest
{
   private QInstance           qInstance;
   private AuthentikQBitConfig config;
   private String              userTable;
   private String              groupTable;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeEach
   void beforeEach() throws QException
   {
      FixtureActionUtil.reset();
      config = AuthentikTestSupport.unitConfig();
      qInstance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.useActionUtil(qInstance, config, FixtureActionUtil.class);
      userTable = config.applyTablePrefix("user");
      groupTable = config.applyTablePrefix("group");
      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.USERS_READ);
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
    ** The recorded users page, sliced into Authentik-shaped pages.
    *******************************************************************************/
   private static JSONArray recordedUsers()
   {
      return (new JSONObject(FixtureActionUtil.fixture("users-list")).getJSONArray("results"));
   }



   /*******************************************************************************
    ** Serve /core/users/ with real paging semantics over the recorded users.
    *******************************************************************************/
   private static void serveUsersPaged()
   {
      JSONArray all = recordedUsers();
      FixtureActionUtil.handler = request ->
      {
         int page     = Integer.parseInt(param(request, "page", "1"));
         int pageSize = Integer.parseInt(param(request, "page_size", "20"));
         int from     = (page - 1) * pageSize;
         JSONArray slice = new JSONArray();
         for(int i = from; i < Math.min(all.length(), from + pageSize); i++)
         {
            slice.put(all.get(i));
         }
         int totalPages = (int) Math.ceil(all.length() / (double) pageSize);
         JSONObject body = new JSONObject()
            .put("pagination", new JSONObject().put("count", all.length()).put("current", page).put("total_pages", totalPages))
            .put("results", slice);
         return (FixtureActionUtil.response(200, body.toString()));
      };
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String param(HttpRequestBase request, String name, String defaultValue)
   {
      String query = request.getURI().getRawQuery();
      if(query != null)
      {
         for(String pair : query.split("&"))
         {
            String[] parts = pair.split("=", 2);
            if(parts[0].equals(name))
            {
               return (URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
            }
         }
      }
      return (defaultValue);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static List<String> params(HttpRequestBase request, String name)
   {
      String query = request.getURI().getRawQuery();
      return (query == null ? List.of() : java.util.Arrays.stream(query.split("&")).filter(p -> p.startsWith(name + "=")).map(p -> URLDecoder.decode(p.substring(name.length() + 1), StandardCharsets.UTF_8)).toList());
   }



   /*******************************************************************************
    ** The last /core/users/ list request (the once-per-JVM version check may
    ** come after it).
    *******************************************************************************/
   private static HttpRequestBase lastUsersRequest()
   {
      List<HttpRequestBase> users = FixtureActionUtil.REQUESTS.stream().filter(r -> r.getURI().getPath().endsWith("/core/users/")).toList();
      return (users.get(users.size() - 1));
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
    ** Requests carry the bearer token, the default scope types, and
    ** include_groups; pages are page/page_size based.
    *******************************************************************************/
   @Test
   void queryBuildsAuthentikRequests() throws QException
   {
      serveUsersPaged();
      List<QRecord> records = query(new QQueryFilter().withLimit(2).withSkip(2));
      assertThat(records).hasSize(2);

      HttpRequestBase request = FixtureActionUtil.REQUESTS.stream().filter(r -> r.getURI().getPath().endsWith("/core/users/")).findFirst().orElseThrow();
      assertThat(request.getFirstHeader("Authorization").getValue()).isEqualTo("Bearer " + AuthentikTestSupport.TEST_TOKEN);
      assertThat(request.getURI().toString()).startsWith("https://authentik.example.test/api/v3/core/users/?");
      assertThat(params(request, "type")).containsExactly("internal", "external", "service_account");
      assertThat(param(request, "include_groups", null)).isEqualTo("true");
      assertThat(param(request, "page", null)).isEqualTo("2");
      assertThat(param(request, "page_size", null)).isEqualTo("2");
      assertThat(param(request, "ordering", null)).isEqualTo("username");
   }



   /*******************************************************************************
    ** Non-aligned skip: 100-row pages from the right page and offset; an
    ** unlimited query walks every page.
    *******************************************************************************/
   @Test
   void unalignedSkipAndUnlimitedQueries() throws QException
   {
      serveUsersPaged();
      JSONArray all = recordedUsers();

      List<QRecord> odd = query(new QQueryFilter().withLimit(3).withSkip(1));
      assertThat(odd).extracting(r -> r.getValueString("username")).containsExactly(
         all.getJSONObject(1).getString("username"), all.getJSONObject(2).getString("username"), all.getJSONObject(3).getString("username"));
      assertThat(param(lastUsersRequest(), "page_size", null)).isEqualTo("100");

      assertThat(query(new QQueryFilter())).hasSize(all.length());
   }



   /*******************************************************************************
    ** Count reads pagination.count from a page_size=1 request.
    *******************************************************************************/
   @Test
   void countUsesPaginationCount() throws QException
   {
      serveUsersPaged();
      assertThat(new CountAction().execute(new CountInput(userTable)).getCount()).isEqualTo(recordedUsers().length());
      assertThat(param(lastUsersRequest(), "page_size", null)).isEqualTo("1");
   }



   /*******************************************************************************
    ** Record mapping from the recorded user (computed and joined fields).
    *******************************************************************************/
   @Test
   void getMapsRecordedUser() throws QException
   {
      JSONObject user = new JSONObject(FixtureActionUtil.fixture("user-get"));
      FixtureActionUtil.handler = r -> FixtureActionUtil.response(200, user.toString());

      QRecord record = new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey(user.getInt("pk")));
      assertThat(record.getValueInteger("pk")).isEqualTo(user.getInt("pk"));
      assertThat(record.getValueString("username")).isEqualTo(user.getString("username"));
      assertThat(record.getValueBoolean("isActive")).isEqualTo(user.getBoolean("is_active"));
      assertThat(record.getValue("dateJoined")).isInstanceOf(java.time.Instant.class);
      assertThat(record.getValueBoolean("isProtected")).isFalse();
      assertThat(record.getValues()).doesNotContainKey("attributes").doesNotContainKey("passwordChangeDate");
      assertThat(FixtureActionUtil.REQUESTS.get(0).getURI().getPath()).isEqualTo("/api/v3/core/users/" + user.getInt("pk") + "/");
   }



   /*******************************************************************************
    ** 404 and out-of-scope records come back as "no record".
    *******************************************************************************/
   @Test
   void getMissingAndOutOfScope() throws QException
   {
      assertThat(new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey(424242))).isNull();

      JSONObject outpost = new JSONObject(FixtureActionUtil.fixture("user-get")).put("type", "internal_service_account");
      FixtureActionUtil.handler = r -> FixtureActionUtil.response(200, outpost.toString());
      assertThat(new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey(1))).isNull();

      assertThat(new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey("../../admin"))).isNull();
   }



   /*******************************************************************************
    ** Protection: superusers, qqq.io/protected, configured names, the service
    ** account.
    *******************************************************************************/
   @Test
   void protectionMarkers() throws QException
   {
      JSONObject base = new JSONObject(FixtureActionUtil.fixture("user-get"));
      for(JSONObject variant : List.of(
         new JSONObject(base.toString()).put("is_superuser", true),
         new JSONObject(base.toString()).put("attributes", new JSONObject().put("qqq.io/protected", "true")),
         new JSONObject(base.toString()).put("username", "qqq-kof22-admin-idadmin")))
      {
         FixtureActionUtil.handler = r -> FixtureActionUtil.response(200, variant.toString());
         QRecord record = new GetAction().executeForRecord(new GetInput(userTable).withPrimaryKey(1));
         assertThat(record.getValueBoolean("isProtected")).isTrue();
         assertThat(record.getDisplayValue("isProtected")).startsWith("Protected: ");
      }
   }



   /*******************************************************************************
    ** Key lookups fetch each id; sensitive fields appear with audit.read.
    *******************************************************************************/
   @Test
   void keyLookupAndSensitiveFields() throws QException
   {
      JSONObject user = new JSONObject(FixtureActionUtil.fixture("user-get"));
      FixtureActionUtil.handler = r -> r.getURI().getPath().endsWith("/" + user.getInt("pk") + "/") ? FixtureActionUtil.response(200, user.toString()) : FixtureActionUtil.response(404, "{}");

      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.USERS_READ, IdentityPermission.AUDIT_READ);
      List<QRecord> records = query(new QQueryFilter(new QFilterCriteria("pk", QCriteriaOperator.IN, List.of(user.getInt("pk"), 999))));
      assertThat(records).hasSize(1);
      assertThat(records.get(0).getValues()).containsKey("attributes");
      assertThat(new CountAction().execute(new CountInput(userTable).withFilter(new QQueryFilter(new QFilterCriteria("pk", QCriteriaOperator.IN, List.of(user.getInt("pk"), 999))))).getCount()).isEqualTo(1);
   }



   /*******************************************************************************
    ** Groups from the recorded list: joined names and qqq.io attributes.
    *******************************************************************************/
   @Test
   void groupsFromRecordedList() throws QException
   {
      String body = FixtureActionUtil.fixture("groups-list");
      FixtureActionUtil.handler = r -> FixtureActionUtil.response(200, body);
      QueryInput input = new QueryInput(groupTable);
      List<QRecord> groups = new QueryAction().execute(input).getRecords();
      QRecord identityAdmins = groups.stream().filter(g -> "identity-admins".equals(g.getValueString("name"))).findFirst().orElseThrow();
      assertThat(identityAdmins.getValueString("permissions")).isEqualTo("authentik.*");
      assertThat(identityAdmins.getValueString("appAccess")).isEqualTo("kof22-website-prod");
      assertThat(identityAdmins.getValueBoolean("isSuperuser")).isFalse();
      assertThat(param(FixtureActionUtil.REQUESTS.get(0), "include_users", null)).isEqualTo("false");
   }



   /*******************************************************************************
    ** Permissions: none, system session, writes.
    *******************************************************************************/
   @Test
   void guardDecisions() throws QException
   {
      serveUsersPaged();
      AuthentikTestSupport.loginWith(qInstance);
      assertThatThrownBy(() -> query(new QQueryFilter())).isInstanceOf(QPermissionDeniedException.class);
      assertThatThrownBy(() -> new CountAction().execute(new CountInput(userTable))).isInstanceOf(QPermissionDeniedException.class);
      assertThatThrownBy(() -> new GetAction().execute(new GetInput(userTable).withPrimaryKey(1))).isInstanceOf(QPermissionDeniedException.class);

      QContext.init(qInstance, new QSystemUserSession());
      assertThat(query(new QQueryFilter().withLimit(1))).hasSize(1);
      assertThatThrownBy(() -> new InsertAction().execute(new InsertInput(userTable).withRecord(new QRecord().withValue("username", "x"))))
         .hasMessageContaining("System sessions");

      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.values());
      assertThatThrownBy(() -> new InsertAction().execute(new InsertInput(userTable).withRecord(new QRecord().withValue("username", "x")))).hasMessageContaining("cannot be changed");
      assertThatThrownBy(() -> new UpdateAction().execute(new UpdateInput(userTable).withRecord(new QRecord().withValue("pk", 1)))).hasMessageContaining("cannot be changed");
      assertThatThrownBy(() -> new DeleteAction().execute(new DeleteInput(userTable).withPrimaryKey(1))).hasMessageContaining("cannot be changed");

      config.withReadOnly(true);
      assertThatThrownBy(() -> new DeleteAction().execute(new DeleteInput(userTable).withPrimaryKey(1))).hasMessageContaining("read-only");
   }



   /*******************************************************************************
    ** Recorded error bodies map to user-facing / permission exceptions, with
    ** the token never in a message.
    *******************************************************************************/
   @Test
   void errorMapping() throws QException
   {
      String badFilter = FixtureActionUtil.fixture("error-400-bad-filter");
      FixtureActionUtil.handler = r -> FixtureActionUtil.response(400, badFilter);
      assertThatThrownBy(() -> query(new QQueryFilter())).isInstanceOf(QUserFacingException.class).hasMessageContaining("last_login__lt");

      String forbidden = FixtureActionUtil.fixture("error-403");
      FixtureActionUtil.handler = r -> FixtureActionUtil.response(403, forbidden);
      assertThatThrownBy(() -> query(new QQueryFilter())).isInstanceOf(QPermissionDeniedException.class).hasMessageContaining("403");

      FixtureActionUtil.handler = r -> FixtureActionUtil.response(401, "{\"detail\":\"Token invalid " + AuthentikTestSupport.TEST_TOKEN + "\"}");
      assertThatThrownBy(() -> query(new QQueryFilter())).hasMessageContaining("401").satisfies(e -> assertThat(e.getMessage()).doesNotContain(AuthentikTestSupport.TEST_TOKEN));

      FixtureActionUtil.handler = r -> FixtureActionUtil.response(418, "not json " + AuthentikTestSupport.TEST_TOKEN);
      assertThatThrownBy(() -> query(new QQueryFilter())).hasMessageContaining("418").satisfies(e -> assertThat(e.getMessage()).doesNotContain(AuthentikTestSupport.TEST_TOKEN));

      FixtureActionUtil.handler = r -> FixtureActionUtil.response(200, "<html>");
      assertThatThrownBy(() -> query(new QQueryFilter())).hasMessageContaining("non-JSON");
   }



   /*******************************************************************************
    ** 429 honours Retry-After; GET 5xx and transport errors are retried.
    *******************************************************************************/
   @Test
   void retries() throws QException
   {
      AtomicInteger calls = new AtomicInteger();
      String        body  = FixtureActionUtil.fixture("users-list");
      FixtureActionUtil.handler = r -> switch(calls.incrementAndGet())
      {
         case 1 -> FixtureActionUtil.response(429, "{}", FixtureActionUtil.retryAfter(0));
         case 2 -> FixtureActionUtil.response(502, "bad gateway");
         default -> FixtureActionUtil.response(200, body);
      };
      assertThat(query(new QQueryFilter().withLimit(1))).hasSize(1);
      assertThat(calls.get()).isEqualTo(3);

      calls.set(0);
      FixtureActionUtil.handler = r ->
      {
         calls.incrementAndGet();
         throw (new IllegalStateException("connection reset; Bearer " + AuthentikTestSupport.TEST_TOKEN));
      };
      assertThatThrownBy(() -> query(new QQueryFilter())).hasMessageContaining("Could not reach Authentik").satisfies(e -> assertThat(e.getMessage()).doesNotContain(AuthentikTestSupport.TEST_TOKEN));
      assertThat(calls.get()).isEqualTo(3);
   }



   /*******************************************************************************
    ** Missing token fails before any request.
    *******************************************************************************/
   @Test
   void missingTokenFailsFast() throws QException
   {
      config.withApiToken("${env.QBIT_AUTHENTIK_TEST_UNSET_VARIABLE}");
      assertThatThrownBy(() -> query(new QQueryFilter())).hasMessageContaining("token is not configured");
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
   }



   /*******************************************************************************
    ** The response cache serves repeated identical reads.
    *******************************************************************************/
   @Test
   void responseCache() throws QException
   {
      config.withListCacheTtlSeconds(30);
      qInstance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.useActionUtil(qInstance, config, FixtureActionUtil.class);
      AuthentikTestSupport.loginWith(qInstance, IdentityPermission.USERS_READ);
      serveUsersPaged();

      query(new QQueryFilter().withLimit(2));
      int afterFirst = FixtureActionUtil.REQUESTS.size();
      query(new QQueryFilter().withLimit(2));
      assertThat(FixtureActionUtil.REQUESTS.size()).isEqualTo(afterFirst);

      com.kingsrook.qbits.authentik.AuthentikRuntime.forBackend(config.getApiBackendName()).invalidateCache();
      query(new QQueryFilter().withLimit(2));
      assertThat(FixtureActionUtil.REQUESTS.size()).isGreaterThan(afterFirst);
   }



   /*******************************************************************************
    ** Error-detail flattening and path stripping.
    *******************************************************************************/
   @Test
   void helpers()
   {
      assertThat(AuthentikActionUtil.errorDetail("{\"detail\":\"Nope.\"}")).isEqualTo("Nope.");
      assertThat(AuthentikActionUtil.errorDetail("{\"name\":[\"a\",\"b\"],\"non_field_errors\":[\"c\"]}")).contains("name: a b").contains("c");
      assertThat(AuthentikActionUtil.errorDetail(null)).isEqualTo("(no details)");
      assertThat(AuthentikActionUtil.errorDetail("x".repeat(300))).endsWith("...");
      assertThat(AuthentikActionUtil.pathOf("https://h/api/v3/core/users/?search=alice%40x")).isEqualTo("/api/v3/core/users/");
      assertThat(AuthentikActionUtil.pathOf("not a uri ?q=1")).isEqualTo("not a uri ");
   }

}
