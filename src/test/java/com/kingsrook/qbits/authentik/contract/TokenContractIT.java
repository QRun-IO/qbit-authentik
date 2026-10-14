/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.contract;


import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikQBitProducer;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import com.kingsrook.qbits.authentik.admin.AdminAction;
import com.kingsrook.qbits.authentik.admin.AdminRequest;
import com.kingsrook.qbits.authentik.admin.AuthentikAdmin;
import com.kingsrook.qbits.authentik.admin.OneTimeKey;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.processes.TokenKeyDelivery;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QUser;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** DESIGN 13.11 against the pinned server and production token blueprint.
 ** Each test owns its users, groups and tokens; credentials stay in memory.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(45)
class TokenContractIT
{
   private static final String LIFETIME = "goauthentik.io/user/token-maximum-lifetime";
   private static final HttpClient HTTP = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
      .connectTimeout(Duration.ofSeconds(10)).build();
   private static AuthentikTestStack stack;
   private static TestApi admin;
   private final List<Integer> users = new ArrayList<>();
   private final List<String> groups = new ArrayList<>();
   private final List<String> tokens = new ArrayList<>();
   private final List<OneTimeKey> delivered = new ArrayList<>();
   private final List<String> eventIds = new ArrayList<>();
   private String appGroup;
   private AuthentikQBitConfig config;



   /*******************************************************************************
    ** All three blueprints must be successful before any probe.
    *******************************************************************************/
   @BeforeAll
   static void start()
   {
      stack = AuthentikTestStack.get();
      admin = stack.admin();
      assertThat(stack.blueprint(AuthentikTestStack.TOKEN_BLUEPRINT).getString("status")).isEqualTo("successful");
   }



   /*******************************************************************************
    ** Independent app-access membership for every test.
    *******************************************************************************/
   @BeforeEach
   void setup()
   {
      JSONObject created = expect(admin.post("/core/groups/", new JSONObject().put("name", unique("access")).put("attributes",
         new JSONObject().put("qqq.io/app-access", new JSONArray().put(AuthentikTestStack.APP_SLUG)))), 201);
      appGroup = created.getString("pk");
      groups.add(appGroup);
   }



   /*******************************************************************************
    ** Cascading user deletion also removes managed roles and credentials.
    *******************************************************************************/
   @AfterEach
   void cleanup()
   {
      TokenKeyDelivery.set(null);
      QContext.clear();
      for(String identifier : tokens)
      {
         assertThat(admin.delete(tokenPath(identifier)).status()).isIn(204, 404);
      }
      for(Integer pk : users)
      {
         assertThat(admin.delete("/core/users/" + pk + "/").status()).isIn(204, 404);
      }
      for(String pk : groups)
      {
         assertThat(admin.delete("/core/groups/" + pk + "/").status()).isIn(204, 404);
      }
      delivered.clear();
   }



   /*******************************************************************************
    ** Explicit other-owner input does not override caller-owned creation.
    *******************************************************************************/
   @Test
   void nonSuperuserCreateBelongsToCaller()
   {
      int other = user("other");
      String identifier = unique("caller-owned");
      tokens.add(identifier);
      JSONObject created = expect(stack.serviceAccount().post("/core/tokens/", tokenBody(identifier, other, 1)), 201);
      assertOwner(created, admin.userPk(AuthentikTestStack.SERVICE_ACCOUNT));
   }



   /*******************************************************************************
    ** PATCH defaults move intent and owner; explicit fields retain both.
    *******************************************************************************/
   @Test
   void patchDefaultsAreDangerous()
   {
      int owner = user("patch");
      String unsafe = appPassword(owner, 1);
      JSONObject changed = expect(stack.serviceAccount().patch(tokenPath(unsafe), new JSONObject().put("expires", expires(30))), 200);
      assertThat(changed.getString("intent")).isEqualTo("api");
      assertThat(changed.getInt("user")).isEqualTo(admin.userPk(AuthentikTestStack.SERVICE_ACCOUNT));
      String safe = appPassword(owner, 1);
      assertOwner(expect(stack.serviceAccount().patch(tokenPath(safe), new JSONObject()
         .put("intent", "app_password").put("user", owner).put("expires", expires(30))), 200), owner);
   }



   /*******************************************************************************
    ** Remove the brand cap temporarily, restoring it even on assertion failure.
    *******************************************************************************/
   @Test
   void expiryCapUsesBrandThenGroupsThenUser()
   {
      int owner = user("cap");
      TestApi caller = apiAs(owner);
      JSONObject brand = admin.first("/core/brands/?default=true");
      String path = "/core/brands/" + brand.getString("brand_uuid") + "/";
      JSONObject original = brand.getJSONObject("attributes");
      try
      {
         JSONObject without = new JSONObject(original.toString());
         without.remove(LIFETIME);
         expect(admin.patch(path, new JSONObject().put("attributes", without)), 200);
         refusedLifetime(caller, owner, 30);
         expect(admin.patch(path, new JSONObject().put("attributes", new JSONObject(original.toString()).put(LIFETIME, "days=90"))), 200);
         String identifier = unique("brand-cap");
         tokens.add(identifier);
         assertOwner(expect(caller.post("/core/tokens/", tokenBody(identifier, owner, 30)), 201), owner);
         refusedLifetime(caller, owner, 120);
         expect(admin.patch("/core/groups/" + appGroup + "/", new JSONObject().put("attributes", new JSONObject()
            .put("qqq.io/app-access", new JSONArray().put(AuthentikTestStack.APP_SLUG)).put(LIFETIME, "days=10"))), 200);
         refusedLifetime(caller, owner, 30);
         attributes(owner, new JSONObject().put(LIFETIME, "days=365"));
         String overridden = unique("user-cap");
         tokens.add(overridden);
         assertOwner(expect(caller.post("/core/tokens/", tokenBody(overridden, owner, 200)), 201), owner);
      }
      finally
      {
         expect(admin.patch(path, new JSONObject().put("attributes", original)), 200);
      }
   }



   /*******************************************************************************
    ** Broker bearers create, read keys, extend and delete only their own tokens.
    *******************************************************************************/
   @Test
   void brokerSupportsPersonalLifecycleAndIsolatesOwners() throws Exception
   {
      int owner = user("broker");
      TestApi caller = exchanged(owner);
      TestApi other = exchanged(user("isolated"));
      String identifier = unique("broker-created");
      tokens.add(identifier);
      assertOwner(expect(caller.post("/core/tokens/", tokenBody(identifier, owner, 30)), 201), owner);
      String key = expect(caller.get(tokenPath(identifier) + "view_key/"), 200).getString("key");
      assertThat(key.isBlank()).isFalse();
      assertThat(other.get(tokenPath(identifier)).status()).isIn(403, 404);
      assertThat(other.get(tokenPath(identifier) + "view_key/").status()).isIn(403, 404);
      assertThat(other.delete(tokenPath(identifier)).status()).isIn(403, 404);
      assertOwner(expect(caller.patch(tokenPath(identifier), new JSONObject().put("intent", "app_password")
         .put("user", owner).put("expires", expires(40))), 200), owner);
      expect(caller.delete(tokenPath(identifier)), 204);
   }



   /*******************************************************************************
    ** Each privileged class is independently denied by the broker policy.
    *******************************************************************************/
   @Test
   void brokerDeniesProtectedOwners(TestReporter reporter) throws Exception
   {
      for(String protection : List.of("identity-admins", "authentik Admins", "attribute"))
      {
         int owner = user("denied");
         if("attribute".equals(protection))
         {
            attributes(owner, new JSONObject().put("qqq.io/protected", true));
         }
         else
         {
            expect(admin.post("/core/groups/" + admin.groupPk(protection) + "/add_user/", new JSONObject().put("pk", owner)), 204);
         }
         TestApi.Response response = exchange(subject(owner));
         assertThat(response.status()).as("broker denial for %s: %s", protection, safeError(response)).isNotEqualTo(200);
         assertThat(response.json().optString("error")).isNotBlank();
         reporter.publishEntry(protection, "HTTP " + response.status() + ": " + safeError(response));
      }
   }



   /*******************************************************************************
    ** service_account needs add_user AND add_token (2026.8.3), and set_key needs
    ** add_token (POST object permission) as well as set_token_key: the role
    ** holds all three (DESIGN.md 13.9), and add_token cannot mint for others.
    *******************************************************************************/
   @Test
   void serviceAccountCreateSetKeyAndExtend() throws Exception
   {
      String name = unique("service");
      JSONObject request = new JSONObject().put("name", name).put("create_group", false).put("expiring", true).put("expires", expires(300));
      JSONObject created = expect(stack.serviceAccount().post("/core/users/service_account/", request), 200);
      int owner = created.getInt("user_pk");
      users.add(owner);
      String identifier = "service-account-" + name + "-password";
      tokens.add(identifier);
      assertThat(created.getString("token").isBlank()).isFalse();
      JSONObject before = admin.getOk(tokenPath(identifier));
      assertOwner(before, owner);
      assertThat(Instant.parse(before.getString("expires"))).isAfter(Instant.now().plus(299, ChronoUnit.DAYS));
      attributes(owner, new JSONObject().put(LIFETIME, "days=365"));
      expect(admin.post("/core/groups/" + appGroup + "/add_user/", new JSONObject().put("pk", owner)), 204);
      String key = UUID.randomUUID().toString() + UUID.randomUUID();
      expect(stack.serviceAccount().post(tokenPath(identifier) + "set_key/", new JSONObject().put("key", key)), 204);
      expect(credentials(name, key, "openid profile email"), 200);
      assertThat(admin.getOk(tokenPath(identifier) + "view_key/").getString("key").equals(key)).isTrue();
      assertOwner(expect(stack.serviceAccount().patch(tokenPath(identifier), new JSONObject().put("intent", "app_password")
         .put("user", owner).put("expires", expires(200))), 200), owner);
   }



   /*******************************************************************************
    ** Profile controls the signed token binding and groups on the access JWT.
    *******************************************************************************/
   @Test
   void clientCredentialsClaimsRequireProfile() throws Exception
   {
      int owner = user("claims");
      String identifier = appPassword(owner, 1);
      String key = admin.getOk(tokenPath(identifier) + "view_key/").getString("key");
      String username = admin.getOk("/core/users/" + owner + "/").getString("username");
      JSONObject full = claims(expect(credentials(username, key, "openid profile email"), 200).getString("access_token"));
      assertThat(full.getString("qqq_token")).isEqualTo(identifier);
      assertThat(full.has("groups")).isTrue();
      JSONObject limited = claims(expect(credentials(username, key, "openid email"), 200).getString("access_token"));
      assertThat(limited.has("qqq_token")).isFalse();
      assertThat(limited.has("groups")).isFalse();
   }



   /*******************************************************************************
    ** Local notifications identify the actual protected-token update event.
    ** Observe the negative case for a full worker-processing interval as well.
    *******************************************************************************/
   @Test
   void detectiveRuleNotifiesOnlyForProtectedOwner() throws Exception
   {
      int protectedOwner = user("alarm");
      expect(admin.post("/core/groups/" + admin.groupPk("identity-admins") + "/add_user/", new JSONObject().put("pk", protectedOwner)), 204);
      String protectedToken = appPassword(protectedOwner, 1);
      JSONObject created = expect(admin.post("/core/users/service_account/", new JSONObject().put("name", unique("ordinary"))
         .put("create_group", false).put("expiring", true).put("expires", expires(30))), 200);
      users.add(created.getInt("user_pk"));
      String ordinaryToken = "service-account-" + created.getString("username") + "-password";
      tokens.add(ordinaryToken);
      String ordinaryEvent = setKeyEvent(ordinaryToken);
      String protectedEvent = setKeyEvent(protectedToken);
      AuthentikTestStack.waitFor(Duration.ofSeconds(60), "protected-token local notification", () ->
         notifications(protectedOwner, protectedEvent).length() > 0);
      Instant deadline = Instant.now().plusSeconds(60);
      do
      {
         assertThat(notifications(protectedOwner, ordinaryEvent).length()).isZero();
         Thread.sleep(2_000);
      }
      while(Instant.now().isBefore(deadline));
   }



   /*******************************************************************************
    ** Real qbit calls, local audit/scope persistence and the response-only SPI.
    *******************************************************************************/
   @Test
   void qbitLifecycleNeverPersistsOneTimeKeys() throws Exception
   {
      int owner = user("qbit");
      String username = admin.getOk("/core/users/" + owner + "/").getString("username");
      configureQbit(owner, subject(owner));
      OneTimeKey first = issued(run(AdminRequest.of(AdminAction.CREATE_TOKEN, "", "contract personal create")
         .with("description", "Contract access").with("expiresInDays", 30)));
      expect(credentials(username, first.value(), "openid profile email"), 200);
      run(AdminRequest.of(AdminAction.EXTEND_TOKEN, first.label(), "contract extend").with("expiresInDays", 40));
      assertOwner(admin.getOk(tokenPath(first.label())), owner);
      OneTimeKey rotated = issued(run(AdminRequest.of(AdminAction.ROTATE_TOKEN, first.label(), "contract rotate")));
      expect(credentials(username, rotated.value(), "openid profile email"), 200);
      assertThat(admin.get(tokenPath(first.label())).status()).isEqualTo(404);
      run(AdminRequest.of(AdminAction.REVOKE_TOKEN, rotated.label(), "contract revoke"));
      assertThat(admin.get(tokenPath(rotated.label())).status()).isEqualTo(404);
      String serviceName = unique("qbit-service");
      try
      {
         AdminRequest createService = AdminRequest.of(AdminAction.CREATE_SERVICE_ACCOUNT, "", "contract service create")
            .with("name", serviceName).with("groups", admin.getOk("/core/groups/" + appGroup + "/").getString("name")).with("expiresInDays", 300);
         OneTimeKey service = issued(run(createService));
         int servicePk = admin.userPk(serviceName);
         JSONObject attributes = admin.getOk("/core/users/" + servicePk + "/").getJSONObject("attributes");
         assertThat(attributes.getString(LIFETIME)).isEqualTo("days=365");
         assertThat(attributes.getBoolean("goauthentik.io/user/token-expires")).isTrue();
         expect(credentials(serviceName, service.value(), "openid profile email"), 200);
         OneTimeKey next = issued(run(AdminRequest.of(AdminAction.ROTATE_TOKEN, service.label(), "contract service rotate")));
         expect(credentials(serviceName, next.value(), "openid profile email"), 200);
         assertThat(credentials(serviceName, service.value(), "openid profile email").status()).isNotEqualTo(200);
         assertOwner(admin.getOk(tokenPath(next.label())), servicePk);
         run(AdminRequest.of(AdminAction.EXTEND_TOKEN, next.label(), "contract service extend").with("expiresInDays", 200));
      }
      finally
      {
         JSONObject service = admin.first("/core/users/?username=" + TestApi.encode(serviceName));
         if(service != null)
         {
            users.add(service.getInt("pk"));
         }
      }
      for(OneTimeKey key : delivered)
      {
         for(String table : List.of("authentik_admin_action", "authentik_token_scope", "authentik_approval_request"))
         {
            String rows = com.kingsrook.qqq.backend.core.utils.JsonUtils.toJson(new QueryAction().execute(new QueryInput().withTableName(table)).getRecords());
            assertThat(rows.contains(key.value())).as("No secret in %s", table).isFalse();
         }
         for(String eventId : eventIds)
         {
            assertThat(admin.getOk("/events/events/" + eventId + "/").toString().contains(key.value()))
               .as("No secret in qbit custom event").isFalse();
         }
      }
      assertThat(delivered).hasSize(4);
      assertThat(eventIds).hasSize(7);
   }



   /*******************************************************************************
    ** A real runtime using the qbit bearer and a normal user's signed subject JWT.
    *******************************************************************************/
   private void configureQbit(int owner, String subject) throws Exception
   {
      MemoryRecordStore.getInstance().reset();
      config = new AuthentikQBitConfig().withBaseUrl(stack.baseUrl()).withApiToken(stack.serviceAccountToken()).withAppKey("kof22-admin")
         .withListCacheTtlSeconds(0).withGroupCacheTtlSeconds(0).withBulkPacingMillis(0).withLocalBackendName("memory")
         .withRecoveryEmailStage("kof22-recovery-email")
         .withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.TOKENS))
         .withTokenBrokerClientId("qqq-kof22-token-broker").withTokenBrokerClientSecret(AuthentikTestStack.TOKEN_BROKER_CLIENT_SECRET)
         .withTokenEndpointUrl(stack.baseUrl() + "/application/o/token/").withSubjectTokenSource(session -> subject)
         .withAppClientId(AuthentikTestStack.APP_SLUG).withAuthentikPublicUrl(stack.baseUrl()).withAppPublicUrl("https://app.example.test");
      QInstance instance = new QInstance();
      instance.withInstanceDefaultAuthentication(new QAuthenticationMetaData().withName("mock").withType(QAuthenticationType.MOCK));
      instance.addBackend(new QBackendMetaData().withName("memory").withBackendType(MemoryBackendModule.class));
      new AuthentikQBitProducer().withQBitConfig(config).produce(instance);
      Set<String> permissions = new HashSet<>();
      for(IdentityPermission permission : IdentityPermission.values())
      {
         permissions.add(permission.getSessionPermission());
      }
      QSession session = new QSession();
      session.setUser(new QUser().withIdReference(admin.getOk("/core/users/" + owner + "/").getString("email")));
      session.setPermissions(permissions);
      QContext.init(instance, session);
      TokenKeyDelivery.set((output, key) -> delivered.add(key));
   }



   /*******************************************************************************
    ** Preserve custom event identifiers without retaining any response secret.
    *******************************************************************************/
   private AuthentikAdmin.AdminResult run(AdminRequest request) throws Exception
   {
      AuthentikAdmin.AdminResult result = new AuthentikAdmin(AuthentikActionUtil.forBackend(config.getApiBackendName())).execute(request);
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(result.eventPk()).isNotBlank();
      eventIds.add(result.eventPk());
      return (result);
   }



   /*******************************************************************************
    ** Exercise the one-time adapter and ensure a second take is empty.
    *******************************************************************************/
   private OneTimeKey issued(AuthentikAdmin.AdminResult result)
   {
      OneTimeKey key = result.takeSecret();
      assertThat(key).isNotNull();
      assertThat(result.takeSecret()).isNull();
      assertThat(TokenKeyDelivery.tryDeliver(new RunBackendStepOutput(), key)).isTrue();
      tokens.add(key.label());
      result.delivered();
      return (key);
   }



   /*******************************************************************************
    ** New ordinary user with independently owned membership and cleanup.
    *******************************************************************************/
   private int user(String prefix)
   {
      String name = unique(prefix);
      JSONObject created = expect(admin.post("/core/users/", new JSONObject().put("username", name).put("name", name)
         .put("email", name + "@example.test").put("type", "internal").put("path", "users")), 201);
      int pk = created.getInt("pk");
      users.add(pk);
      expect(admin.post("/core/groups/" + appGroup + "/add_user/", new JSONObject().put("pk", pk)), 204);
      return (pk);
   }



   /*******************************************************************************
    ** Merge test attributes, preserving service-account flags.
    *******************************************************************************/
   private void attributes(int owner, JSONObject extra)
   {
      String path = "/core/users/" + owner + "/";
      JSONObject attributes = admin.getOk(path).getJSONObject("attributes");
      extra.keySet().forEach(key -> attributes.put(key, extra.get(key)));
      expect(admin.patch(path, new JSONObject().put("attributes", attributes)), 200);
   }



   /*******************************************************************************
    ** Bootstrap setup can create a credential for another user.
    *******************************************************************************/
   private String appPassword(int owner, int days)
   {
      String identifier = unique("password");
      tokens.add(identifier);
      assertOwner(expect(admin.post("/core/tokens/", tokenBody(identifier, owner, days)), 201), owner);
      return (identifier);
   }



   /*******************************************************************************
    ** API bearer for cap probes, independent of the broker under test.
    *******************************************************************************/
   private TestApi apiAs(int owner)
   {
      String identifier = unique("api");
      tokens.add(identifier);
      expect(admin.post("/core/tokens/", new JSONObject().put("identifier", identifier).put("user", owner).put("intent", "api")), 201);
      return (new TestApi(stack.apiRoot(), admin.getOk(tokenPath(identifier) + "view_key/").getString("key")));
   }



   /*******************************************************************************
    ** Mint an app JWT using the explicitly enabled client-credentials grant.
    *******************************************************************************/
   private String subject(int owner) throws Exception
   {
      String identifier = appPassword(owner, 1);
      String key = admin.getOk(tokenPath(identifier) + "view_key/").getString("key");
      return (expect(credentials(admin.getOk("/core/users/" + owner + "/").getString("username"), key, "openid profile email"), 200).getString("access_token"));
   }



   /*******************************************************************************
    ** Exchange through the production broker, without substituting admin access.
    *******************************************************************************/
   private TestApi exchanged(int owner) throws Exception
   {
      JSONObject response = expect(exchange(subject(owner)), 200);
      assertThat(response.getInt("expires_in")).isBetween(1, 120);
      return (new TestApi(stack.apiRoot(), response.getString("access_token")));
   }



   /*******************************************************************************
    ** The primary provider consumes an app password to authenticate its owner.
    *******************************************************************************/
   private TestApi.Response credentials(String username, String key, String scope) throws Exception
   {
      return (form(Map.of("grant_type", "client_credentials", "client_id", AuthentikTestStack.APP_SLUG,
         "client_secret", "contract-test-oauth2-client-secret", "username", username, "password", key, "scope", scope)));
   }



   /*******************************************************************************
    ** RFC 8693 request used by both allowed and denied subject cases.
    *******************************************************************************/
   private TestApi.Response exchange(String subject) throws Exception
   {
      return (form(Map.of("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange", "client_id", "qqq-kof22-token-broker",
         "client_secret", AuthentikTestStack.TOKEN_BROKER_CLIENT_SECRET, "subject_token", subject,
         "subject_token_type", "urn:ietf:params:oauth:token-type:jwt", "scope", "goauthentik.io/api")));
   }



   /*******************************************************************************
    ** HTTP/1.1 avoids Authentik's h2c POST trap. No form in error messages.
    *******************************************************************************/
   private TestApi.Response form(Map<String, String> fields) throws Exception
   {
      String body = fields.entrySet().stream().map(entry -> TestApi.encode(entry.getKey()) + "=" + TestApi.encode(entry.getValue())).collect(Collectors.joining("&"));
      HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(stack.baseUrl() + "/application/o/token/"))
         .timeout(Duration.ofSeconds(30)).header("Content-Type", "application/x-www-form-urlencoded")
         .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
      return (new TestApi.Response(response.statusCode(), response.body()));
   }



   /*******************************************************************************
    ** Pin refusal instead of accepting a silently shortened lifetime.
    *******************************************************************************/
   private void refusedLifetime(TestApi caller, int owner, int days)
   {
      String identifier = unique("too-long");
      tokens.add(identifier);
      JSONObject response = expect(caller.post("/core/tokens/", tokenBody(identifier, owner, days)), 400);
      assertThat(response.getJSONArray("expires").toString()).contains("exceeds maximum lifetime");
   }



   /*******************************************************************************
    ** Match the update by immutable token PK and the service-account actor.
    *******************************************************************************/
   private String setKeyEvent(String identifier)
   {
      String pk = admin.getOk(tokenPath(identifier)).getString("pk");
      expect(stack.serviceAccount().post(tokenPath(identifier) + "set_key/", new JSONObject().put("key", UUID.randomUUID().toString() + UUID.randomUUID())), 204);
      String[] found = { null };
      try
      {
      AuthentikTestStack.waitFor(Duration.ofSeconds(30), "token model_updated event", () ->
      {
         //////////////////////////////////////////////////////////////////////
         // set_key logs model_to_dict(token): identifier, intent, user (key  //
         // masked), not the usual (app, model_name, pk) model reference      //
         //////////////////////////////////////////////////////////////////////
         JSONArray events = admin.getOk("/events/events/?action=model_updated&ordering=-created&page_size=50"
            + "&username=" + TestApi.encode(AuthentikTestStack.SERVICE_ACCOUNT)).getJSONArray("results");
         for(int i = 0; i < events.length(); i++)
         {
            JSONObject event = events.getJSONObject(i);
            JSONObject model = event.getJSONObject("context").optJSONObject("model");
            if(model != null && (pk.replace("-", "").equals(model.optString("pk").replace("-", "")) || identifier.equals(model.optString("identifier")))
               && AuthentikTestStack.SERVICE_ACCOUNT.equals(event.getJSONObject("user").optString("username")))
            {
               found[0] = event.getString("pk");
               return (true);
            }
         }
         return (false);
      });
      }
      catch(IllegalStateException e)
      {
         JSONArray recent = admin.getOk("/events/events/?ordering=-created&page_size=15").getJSONArray("results");
         for(int i = 0; i < recent.length(); i++)
         {
            JSONObject event = recent.getJSONObject(i);
            System.err.println("recent event " + event.optString("action") + " user=" + event.optJSONObject("user") + " ctx=" + event.optJSONObject("context"));
         }
         throw (e);
      }
      return (found[0]);
   }



   /*******************************************************************************
    ** Exclude unrelated notifications with destination and exact event filters.
    *******************************************************************************/
   private JSONArray notifications(int user, String event)
   {
      return (admin.getOk("/events/notifications/?user=" + user + "&event=" + event).getJSONArray("results"));
   }



   /*******************************************************************************
    ** Status diagnostics include redacted errors, never success bodies.
    *******************************************************************************/
   private static JSONObject expect(TestApi.Response response, int status)
   {
      assertThat(response.status()).as("Expected HTTP %s; %s", status, safeError(response)).isEqualTo(status);
      return (response.json());
   }



   /*******************************************************************************
    ** An unexpected success must not leak a key through assertion diagnostics.
    *******************************************************************************/
   private static String safeError(TestApi.Response response)
   {
      if(response.status() < 400)
      {
         return ("HTTP " + response.status() + " (body withheld)");
      }
      return (com.kingsrook.qbits.authentik.client.AuthentikRedactor.redactText(response.body(), null));
   }



   /*******************************************************************************
    ** Metadata assertions contain no credentials.
    *******************************************************************************/
   private static void assertOwner(JSONObject token, int owner)
   {
      assertThat(token.getInt("user")).isEqualTo(owner);
      assertThat(token.getString("intent")).isEqualTo("app_password");
   }



   /*******************************************************************************
    ** Supply every field whose omission triggers dangerous defaults.
    *******************************************************************************/
   private static JSONObject tokenBody(String identifier, int owner, int days)
   {
      return (new JSONObject().put("identifier", identifier).put("user", owner).put("intent", "app_password")
         .put("description", "Contract test").put("expiring", true).put("expires", expires(days)));
   }



   /*******************************************************************************
    ** Decode the server-issued payload without printing the JWT.
    *******************************************************************************/
   private static JSONObject claims(String jwt)
   {
      return (new JSONObject(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8)));
   }



   /*******************************************************************************
    ** Identifiers compatible with token URLs and Django slugify.
    *******************************************************************************/
   private static String unique(String prefix)
   {
      return ("tc-" + prefix + "-" + UUID.randomUUID().toString().substring(0, 8));
   }



   /*******************************************************************************
    ** Relative expiry comfortably away from the cap boundary.
    *******************************************************************************/
   private static String expires(int days)
   {
      return (Instant.now().plus(days, ChronoUnit.DAYS).toString());
   }



   /*******************************************************************************
    ** All identifiers here are internally generated safe URL components.
    *******************************************************************************/
   private static String tokenPath(String identifier)
   {
      return ("/core/tokens/" + identifier + "/");
   }
}
