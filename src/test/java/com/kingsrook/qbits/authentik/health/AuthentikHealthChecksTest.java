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

package com.kingsrook.qbits.authentik.health;


import java.time.Instant;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikQBitProducer;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.client.TokenBucketThrottle;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.health.HealthCategory;
import com.kingsrook.qqq.backend.core.health.HealthCheckInput;
import com.kingsrook.qqq.backend.core.health.HealthCheckKind;
import com.kingsrook.qqq.backend.core.health.HealthCheckOutcome;
import com.kingsrook.qqq.backend.core.health.HealthChecksMetaData;
import com.kingsrook.qqq.backend.core.health.HealthStatus;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.module.api.actions.QHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Offline probes run under the central runner's health-only permissions.
 *******************************************************************************/
class AuthentikHealthChecksTest
{
   private static final String SECRET = "S3NT1NEL-secret";
   private AuthentikQBitConfig config;
   private QInstance instance;



   /*******************************************************************************
    ** Install the existing send seam with poisoned credentials.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws QException
   {
      FixtureActionUtil.reset();
      config = AuthentikTestSupport.unitConfig().withApiToken(SECRET).withTokenBrokerClientId(SECRET)
         .withTokenBrokerClientSecret(SECRET).withGroupCacheTtlSeconds(0);
      instance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.useActionUtil(instance, config, HealthActionUtil.class);
      AuthentikTestSupport.loginWithPermissions(instance, Set.of("health.read", "health.write"));
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, FixtureActionUtil.EMPTY_PAGE);
   }



   /*******************************************************************************
    ** Do not leak static fixture state or thread context between tests.
    *******************************************************************************/
   @AfterEach
   void tearDown()
   {
      QContext.clear();
      FixtureActionUtil.reset();
   }



   /*******************************************************************************
    ** Metadata is registered by production, with no probes during registration.
    *******************************************************************************/
   @Test
   void registration() throws QException
   {
      var checks = HealthChecksMetaData.ofOrWithNew(instance).resolveAll(instance);
      assertThat(checks).extracting(c -> c.getName()).containsExactly("authentik.api", "authentik.api_token", "authentik.mapper", "authentik.token_broker");
      assertThat(checks).allSatisfy(c ->
      {
         assertThat(c.getComponent()).isEqualTo("authentik");
         assertThat(c.getCategory()).isEqualTo(HealthCategory.IDENTITY);
         assertThat(c.getKind()).isEqualTo(HealthCheckKind.DEPENDENCY);
         assertThat(c.getIntervalSeconds()).isEqualTo(c.getName().equals("authentik.api") || c.getName().equals("authentik.token_broker") ? 300 : 21600);
         assertThat(c.getTimeoutMs()).isEqualTo(10000);
      });
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
      assertThat(instance.getWidget("authentikDriftReport")).isNotNull();
      QInstance empty = new QInstance();
      assertThat(new AuthentikQBitProducer().isEnabled()).isFalse();
      assertThatThrownBy(() -> new AuthentikQBitProducer().produce(empty)).isInstanceOf(QException.class);
      assertThat(HealthChecksMetaData.ofOrWithNew(empty).getChecks()).isEmpty();
   }



   /*******************************************************************************
    ** Version responses are allowlisted before entering details.
    *******************************************************************************/
   @Test
   void apiVersions() throws QException
   {
      respond(new JSONObject().put("version_current", "2026.8.3"));
      assertThat(run("api").getDetails().getValues()).containsEntry("serverVersion", "2026.8.3");
      assertThat(run("api").getStatus()).isEqualTo(HealthStatus.UP);
      config.withExpectedServerVersion("2025.10");
      assertThat(run("api").getStatus()).isEqualTo(HealthStatus.DEGRADED);
      config.withExpectedServerVersion(null);
      assertThat(run("api").getStatus()).isEqualTo(HealthStatus.UP);
      respond(new JSONObject().put("version_current", SECRET));
      assertThat(run("api").getStatus()).isEqualTo(HealthStatus.DOWN);
      assertClean(run("api"));
      respond(new JSONObject());
      assertThat(run("api").getStatus()).isEqualTo(HealthStatus.DOWN);
   }



   /*******************************************************************************
    ** Present, approaching, expired, missing and ambiguous token metadata.
    *******************************************************************************/
   @Test
   void apiTokenStates() throws QException
   {
      JSONObject token = new JSONObject().put("intent", "api").put("identifier", SECRET).put("expiring", true);
      token.put("expires", Instant.now().plusSeconds(30 * 86400).toString());
      page(token);
      assertThat(run("api_token").getStatus()).isEqualTo(HealthStatus.UP);
      token.put("expires", Instant.now().plusSeconds(13 * 86400).toString());
      page(token);
      var outcome = run("api_token");
      assertThat(outcome.getStatus()).isEqualTo(HealthStatus.DEGRADED);
      assertThat(outcome.getDetails().getValues()).containsOnlyKeys("daysToExpiry");
      token.put("expires", Instant.now().minusSeconds(60).toString());
      page(token);
      assertThat(run("api_token").getStatus()).isEqualTo(HealthStatus.DOWN);
      token.put("expiring", false);
      page(token);
      assertThat(run("api_token").getStatus()).isEqualTo(HealthStatus.UP);
      token.put("expiring", true).put("expires", SECRET);
      page(token);
      assertThat(run("api_token").getStatus()).isEqualTo(HealthStatus.UNKNOWN);
      page(token, token);
      assertThat(run("api_token").getStatus()).isEqualTo(HealthStatus.UNKNOWN);
      page();
      assertThat(run("api_token").getStatus()).isEqualTo(HealthStatus.DOWN);
      assertThat(FixtureActionUtil.REQUESTS).allSatisfy(request ->
      {
         assertThat(request.getURI().getPath()).endsWith("/core/tokens/");
         assertThat(request.getURI().getQuery()).contains("intent=api", "user__username=");
      });
   }



   /*******************************************************************************
    ** Only the two relevant drift checks run; their subjects stay private.
    *******************************************************************************/
   @Test
   void mapperStates() throws QException
   {
      assertThat(run("mapper").getStatus()).isEqualTo(HealthStatus.UP);
      JSONObject group = new JSONObject().put("pk", "g1").put("name", SECRET)
         .put("attributes", new JSONObject().put("qqq.io/permissions", new JSONArray().put(SECRET)));
      FixtureActionUtil.groupGraphBody = new JSONObject(FixtureActionUtil.EMPTY_PAGE).put("results", new JSONArray().put(group)).toString();
      var outcome = run("mapper");
      assertThat(outcome.getStatus()).isEqualTo(HealthStatus.DEGRADED);
      assertThat(outcome.getDetails().getValues()).containsEntry("findingCodes", "group_attributes.warning");
      page(new JSONObject().put("action", "model_deleted").put("context", new JSONObject()
         .put("model", new JSONObject().put("model_name", "user").put("pk", "1").put("name", SECRET))));
      outcome = run("mapper");
      assertThat(outcome.getStatus()).isEqualTo(HealthStatus.DOWN);
      assertClean(outcome);
      assertThat(FixtureActionUtil.REQUESTS).allSatisfy(request -> assertThat(request.getURI().getPath())
         .doesNotContain("/admin/version/", "/core/tokens/", "/managed/blueprints/"));
   }



   /*******************************************************************************
    ** The broker check uses the grant the broker uses (token exchange) with no
    ** subject: invalid_request proves the credentials; nothing is ever issued.
    *******************************************************************************/
   @Test
   void brokerStates() throws Exception
   {
      refuse("invalid_request");
      assertThat(run("token_broker").getStatus()).isEqualTo(HealthStatus.UP);
      HttpPost request = (HttpPost) FixtureActionUtil.REQUESTS.getLast();
      String body = EntityUtils.toString(request.getEntity());
      assertThat(body).contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange", "client_id=", "client_secret=");
      assertThat(body).doesNotContain("client_credentials", "subject_token");
      assertThat(request.getFirstHeader("Authorization")).isNull();
      assertThat(request.getURI().toString()).isEqualTo(config.getTokenEndpointUrl());

      refuse("invalid_client");
      assertThat(run("token_broker").getStatus()).isEqualTo(HealthStatus.DOWN);
      refuse("invalid_grant");
      assertThat(run("token_broker").getStatus()).isEqualTo(HealthStatus.DOWN);
      respond(new JSONObject().put("access_token", SECRET));
      assertThat(run("token_broker").getStatus()).isEqualTo(HealthStatus.DOWN);

      config.withTokenBrokerClientSecret(null);
      FixtureActionUtil.REQUESTS.clear();
      var outcome = run("token_broker");
      assertThat(outcome.getStatus()).isEqualTo(HealthStatus.UNKNOWN);
      assertThat(outcome.getMessage()).isEqualTo("not configured");
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
   }



   /*******************************************************************************
    ** Serve a token-endpoint refusal with a standard OAuth2 error code.
    *******************************************************************************/
   private void refuse(String errorCode)
   {
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(400, new JSONObject().put("error", errorCode).toString());
   }



   /*******************************************************************************
    ** Both response bodies and thrown errors may echo every configured secret.
    *******************************************************************************/
   @ParameterizedTest
   @ValueSource(strings = { "api", "api_token", "mapper", "token_broker" })
   void failuresNeverExposeSecrets(String name) throws QException
   {
      FixtureActionUtil.groupGraphHandler = request -> FixtureActionUtil.response(401, SECRET);
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(401, SECRET);
      assertThat(run(name).getStatus()).isEqualTo(HealthStatus.DOWN);
      FixtureActionUtil.handler = request ->
      {
         throw new IllegalStateException(SECRET);
      };
      assertThat(run(name).getStatus()).isEqualTo(HealthStatus.DOWN);
   }



   /*******************************************************************************
    ** Expired input performs no I/O, including unconfigured and mapper checks.
    *******************************************************************************/
   @ParameterizedTest
   @ValueSource(strings = { "api", "api_token", "mapper", "token_broker" })
   void expiredDeadline(String name) throws QException
   {
      assertThat(run(name, Instant.now().minusSeconds(1)).getStatus()).isEqualTo(HealthStatus.DOWN);
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
   }



   /*******************************************************************************
    ** Retries and HTTP timeouts use the input budget, never the 30-second default.
    *******************************************************************************/
   @Test
   void boundsRequestsAndRetries() throws QException
   {
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(429, SECRET, FixtureActionUtil.retryAfter(30));
      assertThat(run("api_token", Instant.now().plusSeconds(2)).getStatus()).isEqualTo(HealthStatus.DOWN);
      assertThat(FixtureActionUtil.REQUESTS).hasSize(1);
      var settings = FixtureActionUtil.REQUESTS.getFirst().getConfig();
      assertThat(settings.getSocketTimeout()).isBetween(1, 2000);
      assertThat(settings.getConnectTimeout()).isBetween(1, 2000);
      assertThat(settings.getConnectionRequestTimeout()).isBetween(1, 2000);
   }



   /*******************************************************************************
    ** Unlimited normal client settings cannot override the central deadline.
    *******************************************************************************/
   @Test
   void boundsUnlimitedTimeouts() throws QException
   {
      config.withConnectTimeoutMillis(0).withSocketTimeoutMillis(0);
      run("api_token", Instant.now().plusSeconds(2));
      var settings = FixtureActionUtil.REQUESTS.getFirst().getConfig();
      assertThat(settings.getSocketTimeout()).isBetween(1, 2000);
      assertThat(settings.getConnectTimeout()).isBetween(1, 2000);
   }



   /*******************************************************************************
    ** A saturated throttle refuses a reservation beyond the health deadline.
    *******************************************************************************/
   @Test
   void boundsThrottle() throws QException
   {
      TokenBucketThrottle throttle = new TokenBucketThrottle(1, 1);
      throttle.acquire(Instant.now().plusSeconds(1));
      assertThatThrownBy(() -> throttle.acquire(Instant.now().plusMillis(10))).isInstanceOf(QException.class);
   }



   /*******************************************************************************
    ** Central permission does not grant Authentik mutations or arbitrary users.
    *******************************************************************************/
   @Test
   void requiresHealthPermission() throws QException
   {
      AuthentikTestSupport.loginWithPermissions(instance, Set.of());
      assertThat(run("api").getStatus()).isEqualTo(HealthStatus.DOWN);
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
      assertThatThrownBy(() -> AuthentikActionUtil.forBackend(config.getApiBackendName()).withHealthDeadline(Instant.now().plusSeconds(1)))
         .hasMessageContaining("permission");
   }



   /*******************************************************************************
    ** Run the registered production check, with a short normal budget.
    *******************************************************************************/
   private HealthCheckOutcome run(String name) throws QException
   {
      return (run(name, Instant.now().plusSeconds(5)));
   }



   /*******************************************************************************
    ** HealthRunner.sanitize is package-private; assert the raw outcome is clean.
    *******************************************************************************/
   private HealthCheckOutcome run(String name, Instant deadline) throws QException
   {
      var definition = HealthChecksMetaData.ofOrWithNew(instance).getChecks().stream()
         .filter(c -> c.getName().equals("authentik." + name)).findFirst().orElseThrow();
      var outcome = definition.getCheckInstance().run(new HealthCheckInput().withQInstance(instance).withDeadline(deadline));
      assertClean(outcome);
      return (outcome);
   }



   /*******************************************************************************
    ** No credential can appear even before core sanitization.
    *******************************************************************************/
   private void assertClean(HealthCheckOutcome outcome)
   {
      assertThat(outcome.getMessage() + outcome.getDetails().toJson()).doesNotContain(SECRET, "authentik.example.test", "operator@example.test");
   }



   /*******************************************************************************
    ** Serve a JSON response through the existing fixture handler.
    *******************************************************************************/
   private void respond(JSONObject body)
   {
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(200, body.toString());
   }



   /*******************************************************************************
    ** Serve paginated metadata without any network.
    *******************************************************************************/
   private void page(JSONObject... records)
   {
      respond(new JSONObject(FixtureActionUtil.EMPTY_PAGE).put("results", new JSONArray(List.of(records))));
   }



   /*******************************************************************************
    ** Let version probes use the same configurable fixture handler as other calls.
    *******************************************************************************/
   public static class HealthActionUtil extends FixtureActionUtil
   {
      /***************************************************************************
       ** Preserve the existing group graph seam and capture version requests.
       ***************************************************************************/
      @Override
      protected QHttpResponse send(HttpRequestBase request)
      {
         if(request.getURI().getPath().endsWith("/admin/version/"))
         {
            REQUESTS.add(request);
            return (handler.apply(request));
         }
         return (super.send(request));
      }
   }
}
