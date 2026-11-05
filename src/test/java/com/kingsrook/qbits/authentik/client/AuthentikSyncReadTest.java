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

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.module.api.model.metadata.APIBackendMetaData;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Reconciliation must never treat a truncated directory as deleted records.
 *******************************************************************************/
class AuthentikSyncReadTest
{
   private AuthentikQBitConfig config;
   private QInstance instance;
   private FixtureActionUtil client;

   /*******************************************************************************
    ** Exercise the production HTTP path with controlled paginated responses.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws Exception
   {
      FixtureActionUtil.reset();
      config = AuthentikTestSupport.unitConfig();
      instance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.loginWith(instance, IdentityPermission.USERS_READ);
      client = new FixtureActionUtil();
      client.setBackendMetaData((APIBackendMetaData) instance.getBackend(config.getApiBackendName()));
   }

   /*******************************************************************************
    ** Do not leave fixture handlers or permission context for other tests.
    *******************************************************************************/
   @AfterEach
   void tearDown()
   {
      FixtureActionUtil.reset();
      QContext.clear();
   }

   /*******************************************************************************
    ** Username-only hints require exact server filtering and complete results.
    ***************************************************************************/
   @Test
   void exactUsernameHintsRejectIgnoredOrAmbiguousFilters() throws Exception
   {
      FixtureActionUtil.handler = request ->
      {
         assertThat(request.getURI().getQuery()).contains("username=sam");
         return (FixtureActionUtil.response(200, page(1, 1, 1, user(1).put("username", "sam")).toString()));
      };
      assertThat(client.syncUserByUsername("sam", () -> { }).getInt("pk")).isEqualTo(1);
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, page(1, 1, 1, user(1).put("username", "someone-else")).toString());
      assertThatThrownBy(() -> client.syncUserByUsername("sam", () -> { })).isInstanceOf(QException.class);
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, page(1, 1, 2, user(1).put("username", "sam"), user(2).put("username", "sam")).toString());
      assertThatThrownBy(() -> client.syncUserByUsername("sam", () -> { })).isInstanceOf(QException.class);
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, page(1, 1, 0).toString());
      assertThat(client.syncUserByUsername("sam", () -> { })).isNull();
      AuthentikTestSupport.loginWith(instance);
      assertThatThrownBy(() -> client.syncUserByUsername("sam", () -> { })).isInstanceOf(QPermissionDeniedException.class);
   }

   /*******************************************************************************
    ** A synthetic user that belongs to the default scope.
    *******************************************************************************/
   private JSONObject user(int pk)
   {
      return (new JSONObject().put("pk", pk).put("username", "user" + pk).put("type", "internal").put("path", "users/core"));
   }

   /*******************************************************************************
    ** Authentik's pinned pagination shape.
    *******************************************************************************/
   private JSONObject page(int current, int pages, int count, JSONObject... rows)
   {
      return (new JSONObject().put("pagination", new JSONObject().put("current", current).put("total_pages", pages).put("count", count))
         .put("results", new JSONArray(List.of(rows))));
   }

   /*******************************************************************************
    ** Server-side scope/type/watermark parameters stay in the outgoing request.
    *******************************************************************************/
   @Test
   void completeScopedUsersAndGroupsAreRead() throws Exception
   {
      config.withUserScopePathStartsWith("users/");
      AtomicInteger requests = new AtomicInteger();
      FixtureActionUtil.handler = request ->
      {
         assertThat(request.getURI().getQuery()).contains("path_startswith=users/", "type=internal", "type=external", "type=service_account",
            "last_updated__gt=2026-11-04T00:00:00Z", "include_groups=true", "ordering=pk");
         int number = requests.incrementAndGet();
         return (FixtureActionUtil.response(200, page(number, 2, 2, user(number)).toString()));
      };
      assertThat(client.syncUsers(Instant.parse("2026-11-04T00:00:00Z"), 2)).extracting(u -> u.getInt("pk")).containsExactly(1, 2);
      FixtureActionUtil.groupGraphHandler = request -> FixtureActionUtil.response(200, page(1, 1, 1, new JSONObject().put("pk", "group-1")).toString());
      assertThat(client.syncGroups(1)).extracting(g -> g.getString("pk")).containsExactly("group-1");
   }

   /*******************************************************************************
    ** Missing/contradictory pagination, duplicate IDs, mid-sweep count changes
    ** and ceilings are all failures, never partial successful snapshots.
    *******************************************************************************/
   @Test
   void refusesEveryObservableIncompleteSnapshot()
   {
      for(JSONObject bad : List.of(new JSONObject().put("results", new JSONArray()), page(1, 1, 2, user(1)),
         page(1, 1, 2, user(1), user(1)), page(1, 1, 1001, user(1)), page(1, 2, 2), page(2, 2, 1, user(1))))
      {
         FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, bad.toString());
         assertThatThrownBy(() -> client.syncUsers(null, 1000)).isInstanceOf(QException.class);
      }
      AtomicInteger requests = new AtomicInteger();
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200,
         (requests.incrementAndGet() == 1 ? page(1, 2, 2, user(1)) : page(2, 2, 3, user(2), user(3))).toString());
      assertThatThrownBy(() -> client.syncUsers(null, 1000)).isInstanceOf(QException.class).hasMessageContaining("changing directory");
   }

   /*******************************************************************************
    ** The guard runs before network activity; a server scope violation aborts.
    *******************************************************************************/
   @Test
   void permissionAndScopeFailuresCannotPublishSnapshots() throws Exception
   {
      AuthentikTestSupport.loginWith(instance);
      assertThatThrownBy(() -> client.syncUsers(null, 10)).isInstanceOf(QPermissionDeniedException.class);
      assertThatThrownBy(() -> client.syncGroups(10)).isInstanceOf(QPermissionDeniedException.class);
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
      AuthentikTestSupport.loginWith(instance, IdentityPermission.USERS_READ);
      config.withUserScopePathStartsWith("restricted/");
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, page(1, 1, 1, user(1)).toString());
      assertThatThrownBy(() -> client.syncUsers(null, 10)).isInstanceOf(QException.class).hasMessageContaining("outside the configured scope");
      assertThatThrownBy(() -> client.syncUsers(null, 0)).isInstanceOf(QException.class);
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, page(1, 1, 0).toString());
      assertThat(client.syncUsers(null, 10)).isEmpty();
   }

   /*******************************************************************************
    ** A cached UI response cannot hide a revocation from the synchronization.
    *******************************************************************************/
   @Test
   void synchronizationAlwaysReadsLivePages() throws Exception
   {
      config.withListCacheTtlSeconds(60);
      AuthentikRuntime.register(new AuthentikRuntime(config));
      AtomicInteger requests = new AtomicInteger();
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, page(1, 1, 1, user(requests.incrementAndGet())).toString());
      assertThat(client.syncUsers(null, 10).get(0).getInt("pk")).isEqualTo(1);
      assertThat(client.syncUsers(null, 10).get(0).getInt("pk")).isEqualTo(2);
   }

   /*******************************************************************************
    ** A list omission is not deletion evidence, even if the object moved out
    ** of scope or the detail response is malformed. No include flags on GET.
    *******************************************************************************/
   @Test
   void deletionCandidatesRequireLiveNotFoundResponses() throws Exception
   {
      String group = "bba53718-9d83-4c94-8d85-44cc19bfab6b";
      AtomicInteger requests = new AtomicInteger();
      FixtureActionUtil.handler = request ->
      {
         assertThat(request.getURI().getQuery()).isNull();
         requests.incrementAndGet();
         return (FixtureActionUtil.response(404, "{}"));
      };
      client.confirmSyncDeletions(List.of("1", "1"), List.of(group));
      assertThat(requests.get()).isEqualTo(2);
      for(int status : List.of(200, 403))
      {
         FixtureActionUtil.handler = request -> FixtureActionUtil.response(status, "{}");
         assertThatThrownBy(() -> client.confirmSyncDeletions(List.of("1"), List.of())).isInstanceOf(QException.class);
         assertThatThrownBy(() -> client.confirmSyncDeletions(List.of(), List.of(group))).isInstanceOf(QException.class);
      }
   }

   /*******************************************************************************
    ** A previously cached 404 must not conceal a subsequently visible object.
    *******************************************************************************/
   @Test
   void deletionRecheckBypassesDetailCache() throws Exception
   {
      config.withListCacheTtlSeconds(60);
      AuthentikRuntime.register(new AuthentikRuntime(config));
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(404, "{}");
      assertThat(client.getApiJsonOrNull("/core/users/1/")).isNull();
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, user(1).toString());
      assertThatThrownBy(() -> client.confirmSyncDeletions(List.of("1"), List.of()))
         .isInstanceOf(QException.class).hasMessageContaining("Directory changed");
   }

   /*******************************************************************************
    ** Check permission and all candidate IDs before making any remote requests.
    *******************************************************************************/
   @Test
   void deletionChecksRejectUnsafeCandidatesBeforeNetwork() throws Exception
   {
      AuthentikTestSupport.loginWith(instance);
      assertThatThrownBy(() -> client.confirmSyncDeletions(List.of("1"), List.of())).isInstanceOf(QPermissionDeniedException.class);
      AuthentikTestSupport.loginWith(instance, IdentityPermission.USERS_READ);
      assertThatThrownBy(() -> client.confirmSyncDeletions(List.of("1"), List.of("../users/1"))).isInstanceOf(QException.class);
      assertThatThrownBy(() -> client.confirmSyncDeletions(List.of("1?query=x"), List.of())).isInstanceOf(QException.class);
      assertThatThrownBy(() -> client.confirmSyncDeletions(null, List.of())).isInstanceOf(QException.class);
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
   }

   /*******************************************************************************
    ** Leaving the host's configured scope removes a mirror without deleting
    ** the upstream user. UUID avoids races with rename/reused usernames.
    *******************************************************************************/
   @Test
   void userRemovalChecksImmutableIdentityWithServerScope() throws Exception
   {
      String uuid = "153a6272-94ad-425d-8d6a-24db15364611";
      config.withUserScopePathStartsWith("host/").withUserScopeGroupNames(List.of("Host users"));
      java.util.concurrent.atomic.AtomicBoolean visible = new java.util.concurrent.atomic.AtomicBoolean(false);
      FixtureActionUtil.handler = request ->
      {
         if(request.getURI().getPath().endsWith("/1/"))
         {
            return (FixtureActionUtil.response(200, user(1).put("uuid", uuid).toString()));
         }
         assertThat(request.getURI().getQuery()).contains("uuid=" + uuid, "path_startswith=host/", "groups_by_name=Host", "type=internal")
            .doesNotContain("username=");
         return (FixtureActionUtil.response(200, (visible.get() ? page(1, 1, 1, user(1)) : page(1, 1, 0)).toString()));
      };
      client.confirmSyncDeletions(List.of("1"), List.of());
      visible.set(true);
      assertThatThrownBy(() -> client.confirmSyncDeletions(List.of("1"), List.of()))
         .isInstanceOf(QException.class).hasMessageContaining("Directory changed");
   }

   /*******************************************************************************
    ** Newly discovered members must match both identities and configured scope.
    ** A server ignoring a UUID filter cannot substitute another user's profile.
    *******************************************************************************/
   @Test
   void discoveredUserRequiresMatchingScopedIdentity() throws Exception
   {
      String uuid = "153a6272-94ad-425d-8d6a-24db15364611";
      JSONObject returned = user(1).put("uuid", uuid);
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, request.getURI().getPath().endsWith("/1/")
         ? user(1).put("uuid", uuid).toString() : page(1, 1, 1, returned).toString());
      assertThat(client.syncUser("1").getInt("pk")).isEqualTo(1);
      returned.put("pk", 2);
      assertThatThrownBy(() -> client.syncUser("1")).isInstanceOf(QException.class);
      returned.put("pk", 1).put("uuid", "incorrect");
      assertThatThrownBy(() -> client.syncUser("1")).isInstanceOf(QException.class);
      returned.put("uuid", uuid);
      config.withUserScopePathStartsWith("another/");
      assertThatThrownBy(() -> client.syncUser("1")).isInstanceOf(QException.class);
      AuthentikTestSupport.loginWith(instance);
      assertThatThrownBy(() -> client.syncUser("1")).isInstanceOf(QPermissionDeniedException.class);
   }

   /*******************************************************************************
    ** Large scans renew on both sides of each request. Cancellation after a
    ** response discards it and never continues to another page or returns it.
    *******************************************************************************/
   @Test
   void pageCheckpointsRenewAndCancelWithoutPartialResults() throws Exception
   {
      AtomicInteger requests = new AtomicInteger();
      AtomicInteger checks = new AtomicInteger();
      FixtureActionUtil.handler = request ->
      {
         int current = requests.incrementAndGet();
         return (FixtureActionUtil.response(200, page(current, 2, 2, user(current)).toString()));
      };
      assertThat(client.syncUsers(null, 10, checks::incrementAndGet)).hasSize(2);
      assertThat(checks.get()).isEqualTo(4);
      requests.set(0);
      checks.set(0);
      assertThatThrownBy(() -> client.syncUsers(null, 10, () ->
      {
         if(checks.incrementAndGet() == 2)
         {
            throw (new QException("ownership lost"));
         }
      })).isInstanceOf(QException.class).hasMessage("ownership lost");
      assertThat(requests.get()).isEqualTo(1);
      requests.set(0);
      assertThatThrownBy(() -> client.syncUsers(null, 10, () -> { throw new QException("cancelled before read"); }))
         .isInstanceOf(QException.class);
      assertThat(requests.get()).isZero();
      checks.set(0);
      AuthentikTestSupport.loginWith(instance);
      assertThatThrownBy(() -> client.syncUsers(null, 10, checks::incrementAndGet)).isInstanceOf(QPermissionDeniedException.class);
      assertThat(checks.get()).isZero();
   }

   /*******************************************************************************
    ** Group pages and deletion/detail reads use the same checkpoint boundary.
    *******************************************************************************/
   @Test
   void groupAndDeletionScansRenewBetweenRequests() throws Exception
   {
      AtomicInteger checks = new AtomicInteger();
      FixtureActionUtil.groupGraphHandler = request -> FixtureActionUtil.response(200, page(1, 1, 0).toString());
      assertThat(client.syncGroups(10, checks::incrementAndGet)).isEmpty();
      assertThat(checks.get()).isEqualTo(2);
      checks.set(0);
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(404, "{}");
      client.confirmSyncDeletions(List.of("1", "2"), List.of("bba53718-9d83-4c94-8d85-44cc19bfab6b"), checks::incrementAndGet);
      assertThat(checks.get()).isEqualTo(6);
      checks.set(0);
      assertThat(client.syncUser("1", checks::incrementAndGet)).isNull();
      assertThat(checks.get()).isEqualTo(2);
   }

   /*******************************************************************************
    ** Count only confirmed MFA devices; request the rolling window server-side.
    ** Source secrets and event bodies are never returned in the metrics record.
    *******************************************************************************/
   @Test
   void metricsUseLiveConfirmedDevicesAndServerSideWindow() throws Exception
   {
      QContext.init(instance, new com.kingsrook.qqq.backend.core.model.session.QSystemUserSession(instance));
      config.withListCacheTtlSeconds(60);
      AuthentikRuntime.register(new AuthentikRuntime(config));
      AtomicInteger failed = new AtomicInteger(7);
      AtomicInteger checks = new AtomicInteger();
      FixtureActionUtil.handler = request ->
      {
         if(request.getURI().getPath().endsWith("/authenticators/admin/all/"))
         {
            assertThat(request.getURI().getQuery()).isEqualTo("user=1");
            return (FixtureActionUtil.response(200, "[{\"pk\":\"1\",\"meta_model_name\":\"totp\",\"confirmed\":true},"
               + "{\"pk\":\"2\",\"meta_model_name\":\"webauthn\",\"confirmed\":false},"
               + "{\"pk\":\"1\",\"meta_model_name\":\"sms\",\"confirmed\":true}]"));
         }
         assertThat(request.getURI().getQuery()).contains("action=login_failed", "username=user1", "count_steps=hours=24");
         return (FixtureActionUtil.response(200, "{\"count_step\":{\"hours24\":" + failed.get() + "}}"));
      };
      var metrics = client.syncMetrics(user(1), checks::incrementAndGet);
      assertThat(metrics.mfaDeviceCount()).isEqualTo(2);
      assertThat(metrics.failedLogins24h()).isEqualTo(7);
      assertThat(checks.get()).isEqualTo(4);
      failed.set(0);
      assertThat(client.syncMetrics(user(1), () -> { }).failedLogins24h()).isZero();
   }

   /*******************************************************************************
    ** Outages, malformed/missing/negative counts and incomplete device shapes
    ** are unknown. Never make an unavailable metric look like a clean account.
    *******************************************************************************/
   @Test
   void metricsFailuresRemainUnknownAndNeverSwallowOwnershipLoss() throws Exception
   {
      QContext.init(instance, new com.kingsrook.qqq.backend.core.model.session.QSystemUserSession(instance));
      for(String body : List.of("{}", "[]", "{\"count_step\":{\"hours24\":-1}}", "{\"count_step\":{\"hours24\":1.5}}",
         "[{\"pk\":\"1\",\"meta_model_name\":\"totp\"}]"))
      {
         FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, body);
         var metrics = client.syncMetrics(user(1), () -> { });
         assertThat(metrics.failedLogins24h()).isNull();
         if(!body.equals("[]"))
         {
            assertThat(metrics.mfaDeviceCount()).isNull();
         }
      }
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(403, "{}");
      assertThat(client.syncMetrics(user(1), () -> { })).isEqualTo(new AuthentikActionUtil.SyncMetrics(null, null));
      AtomicInteger checks = new AtomicInteger();
      assertThatThrownBy(() -> client.syncMetrics(user(1), () ->
      {
         if(checks.incrementAndGet() == 2)
         {
            throw (new QException("lost ownership"));
         }
      })).isInstanceOf(QException.class).hasMessage("lost ownership");
      FixtureActionUtil.REQUESTS.clear();
      AuthentikTestSupport.loginWith(instance, IdentityPermission.USERS_READ, IdentityPermission.AUDIT_READ);
      assertThatThrownBy(() -> client.syncMetrics(user(1), () -> { })).isInstanceOf(QPermissionDeniedException.class);
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
   }
}
