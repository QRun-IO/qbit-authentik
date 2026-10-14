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

import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.processes.TokenKeyDelivery;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.processes.RunProcessAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.utils.JsonUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 ** Token actions against the in-memory Authentik 2026.8.3 model. No Docker.
 *******************************************************************************/
class TokenManagementTest
{
   private AdminTestSupport t;
   private final List<OneTimeKey> delivered = new ArrayList<>();
   private final List<String> logLines = new ArrayList<>();
   private AbstractAppender appender;

   /*******************************************************************************
    ** A non-protected person, broker, lifetime groups and capturing response SPI.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws QException
   {
      t = AdminTestSupport.create();
      t.config.withTokenBrokerClientId("test-broker").withTokenBrokerClientSecret("test-broker-secret")
         .withSubjectTokenSource(session -> "subject:3").withAppClientId("test-app").withAppPublicUrl("https://app.example.test")
         .withAuthentikPublicUrl("https://auth.example.test");
      t.authentik.group("token-users", false, List.of(), List.of());
      t.authentik.groupByName("token-users").getJSONObject("attributes").put("goauthentik.io/user/token-maximum-lifetime", "days=90");
      t.authentik.groupByName("token-users").getJSONArray("users").put(3);
      t.authentik.group("qqq-service-accounts", false, List.of(), List.of());
      t.authentik.groupByName("qqq-service-accounts").getJSONObject("attributes").put("goauthentik.io/user/token-maximum-lifetime", "days=365");
      t.authentik.groupByName("qqq-service-accounts").getJSONArray("users").put(6);
      t.loginAs("sam@example.test");
      TokenKeyDelivery.set((output, key) -> delivered.add(key));
      appender = new AbstractAppender("token-test-capture", null, null, false, Property.EMPTY_ARRAY)
      {
         /*******************************************************************************
          ** Capture formatted log messages without writing them elsewhere.
          *******************************************************************************/
         @Override
         public void append(LogEvent event)
         {
            logLines.add(event.getMessage().getFormattedMessage());
         }
      };
      appender.start();
      ((Logger) LogManager.getRootLogger()).addAppender(appender);
   }

   /*******************************************************************************
    ** Do not leak a test adapter into other tests.
    *******************************************************************************/
   @AfterEach
   void tearDown()
   {
      TokenKeyDelivery.set(null);
      ((Logger) LogManager.getRootLogger()).removeAppender(appender);
      appender.stop();
   }

   /*******************************************************************************
    ** A valid personal create request.
    *******************************************************************************/
   private AdminRequest create()
   {
      return (AdminRequest.of(AdminAction.CREATE_TOKEN, "", "automation").with("description", "CI access").with("expiresInDays", 30));
   }

   /*******************************************************************************
    ** A seeded expiring token.
    *******************************************************************************/
   private JSONObject seed(String id, int owner)
   {
      return (t.authentik.seedToken(id, owner, "app_password", Instant.now().plusSeconds(86400).toString()));
   }

   /*******************************************************************************
    ** Assert a Review refusal before Authentik mutates anything.
    *******************************************************************************/
   private void refused(AdminRequest request, String message) throws QException
   {
      int before = t.changes().size();
      AdminPlan plan = t.admin().plan(request);
      assertThat(plan.getState()).isEqualTo(AdminPlan.State.REFUSED);
      assertThat(plan.getMessage()).containsIgnoringCase(message);
      assertThat(t.changes()).hasSize(before);
   }

   /*******************************************************************************
    ** Personal create belongs to the exchanged caller and carries a one-time key.
    *******************************************************************************/
   @Test
   void createOwnAndRotateScopeThenRevoke() throws QException
   {
      t.config.withTokenScopesEnabled(true);
      AuthentikAdmin.AdminResult result = t.admin().execute(create().with("readOnly", true).with("tables", "post"));
      assertThat(result.ok()).as(result.message()).isTrue();
      OneTimeKey key = result.takeSecret();
      assertThat(result.takeSecret()).isNull();
      assertThat(key.label()).matches("qqq-pat-sam-[0-9]{8}-[a-z0-9]{6}");
      assertThat(key.usageText()).contains("https://auth.example.test/application/o/token/", "username=sam", "test-app", "https://app.example.test/qqq/v1/metaData");
      assertThat(key.masked()).endsWith(key.value().substring(key.value().length() - 4));
      assertThat(key.toString()).doesNotContain(key.value());
      assertThat(t.authentik.tokenCallers).containsOnly(3);
      assertThat(t.authentik.tokens.get("sam").get(0).getInt("user")).isEqualTo(3);
      TokenScopeStore store = new TokenScopeStore(t.config);
      assertThat(store.find(key.label()).getValueBoolean("readOnly")).isTrue();
      AuthentikAdmin.AdminResult rotated = t.admin().execute(AdminRequest.of(AdminAction.ROTATE_TOKEN, key.label(), "replace"));
      assertThat(rotated.ok()).as(rotated.message()).isTrue();
      OneTimeKey next = rotated.takeSecret();
      assertThat(next.label()).isNotEqualTo(key.label());
      assertThat(store.find(key.label())).isNull();
      assertThat(store.find(next.label()).getValueString("tables")).isEqualTo("post");
      assertThat(store.find(next.label()).getValue("rotatedAt")).isNotNull();
      assertThat(t.authentik.tokenKeys).doesNotContainKey(key.label());
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.REVOKE_TOKEN, next.label(), "done")).ok()).isTrue();
      assertThat(store.find(next.label())).isNull();
      assertNoKey(key, result);
      assertNoKey(next, rotated);
   }

   /*******************************************************************************
    ** Explicit PATCH fields preserve owner and intent for people and services.
    *******************************************************************************/
   @Test
   void extendOwnAndServiceAndRotateService() throws QException
   {
      seed("personal", 3);
      AuthentikAdmin.AdminResult result = t.admin().execute(AdminRequest.of(AdminAction.EXTEND_TOKEN, "personal", "needed").with("expiresInDays", 60));
      assertThat(result.ok()).as(result.message()).isTrue();
      JSONObject patch = t.authentik.writeBodies.get(0);
      assertThat(patch.getInt("user")).isEqualTo(3);
      assertThat(patch.getString("intent")).isEqualTo("app_password");
      assertThat(Instant.parse(patch.getString("expires"))).isAfter(Instant.now().plusSeconds(59 * 86400));
      t.loginAs("operator@example.test", IdentityPermission.values());
      seed("service", 6);
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.EXTEND_TOKEN, "service", "needed").with("expiresInDays", 365)).ok()).isTrue();
      String old = t.authentik.tokenKeys.get("service");
      result = t.admin().execute(AdminRequest.of(AdminAction.ROTATE_TOKEN, "service", "replace"));
      assertThat(result.ok()).as(result.message()).isTrue();
      OneTimeKey key = result.takeSecret();
      assertThat(key.value()).hasSize(64).matches("[A-Za-z0-9_-]+").isNotEqualTo(old);
      assertThat(t.authentik.tokenKeys.get("service")).isEqualTo(key.value());
      assertNoKey(key, result);
   }

   /*******************************************************************************
    ** Owner/intent movement after either update fails safely and logs no key.
    *******************************************************************************/
   @Test
   void raceGuardForPatchAndSetKey() throws QException
   {
      seed("personal", 3);
      t.authentik.moveTokenAfterUpdate = true;
      AuthentikAdmin.AdminResult result = t.admin().execute(AdminRequest.of(AdminAction.EXTEND_TOKEN, "personal", "needed").with("expiresInDays", 20));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).isEqualTo(AuthentikTokens.TOKEN_MOVED);
      t.loginAs("operator@example.test", IdentityPermission.values());
      seed("service", 6);
      result = t.admin().execute(AdminRequest.of(AdminAction.ROTATE_TOKEN, "service", "replace"));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).isEqualTo(AuthentikTokens.TOKEN_MOVED);
      assertThat(logLines).anyMatch(line -> line.contains("Token moved"));
   }

   /*******************************************************************************
    ** Service creation grants the lifetime group and requested subset groups.
    *******************************************************************************/
   @Test
   void serviceAccountAndSubsetRule() throws QException
   {
      t.loginAs("operator@example.test", IdentityPermission.values());
      AdminRequest request = AdminRequest.of(AdminAction.CREATE_SERVICE_ACCOUNT, "", "automation").with("name", "new-service")
         .with("groups", "kof-website-publishers").with("expiresInDays", 365);
      AuthentikAdmin.AdminResult result = t.admin().execute(request);
      assertThat(result.ok()).as(result.message()).isTrue();
      Integer pk = t.admin().userPkByUsername("new-service");
      assertThat(t.authentik.groupNamesOf(pk)).contains("qqq-service-accounts", "kof-website-publishers");
      OneTimeKey key = result.takeSecret();
      assertThat(key.label()).isEqualTo("service-account-new-service-password");
      assertNoKey(key, result);
      request.with("name", "refused-service").with("groups", "kof-website-analysts");
      refused(request, "do not hold");
      request.with("groups", "identity-admins");
      refused(request, "Protected account");
   }

   /*******************************************************************************
    ** Administrators may revoke a non-protected human, but never issue for them.
    *******************************************************************************/
   @Test
   void ownerAndPermissionRules() throws QException
   {
      seed("someone", 7);
      refused(AdminRequest.of(AdminAction.ROTATE_TOKEN, "someone", "reason"), "own tokens");
      refused(AdminRequest.of(AdminAction.EXTEND_TOKEN, "someone", "reason").with("expiresInDays", 1), "own tokens");
      refused(AdminRequest.of(AdminAction.REVOKE_TOKEN, "someone", "reason"), "own tokens");
      t.loginAs("sam@example.test", IdentityPermission.TOKENS_MANAGE);
      refused(AdminRequest.of(AdminAction.ROTATE_TOKEN, "someone", "reason"), "another person's");
      refused(AdminRequest.of(AdminAction.EXTEND_TOKEN, "someone", "reason").with("expiresInDays", 1), "another person's");
      refused(new AdminRequest(AdminAction.CREATE_TOKEN, "7", create().params(), "reason"), "for you");
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.REVOKE_TOKEN, "someone", "incident")).ok()).isTrue();
      refused(AdminRequest.of(AdminAction.CREATE_SERVICE_ACCOUNT, "", "reason"), "users.manage");
   }

   /*******************************************************************************
    ** Every protected class, including inherited admin membership, fails Review.
    *******************************************************************************/
   @Test
   void protectedOwners() throws QException
   {
      t.loginAs("sam@example.test", IdentityPermission.values());
      for(int owner : List.of(1, 4, 5))
      {
         seed("protected-" + owner, owner);
         refused(AdminRequest.of(AdminAction.REVOKE_TOKEN, "protected-" + owner, "incident"), "Protected account");
      }
      t.authentik.users.get(3).put("is_superuser", true);
      refused(create(), "superuser");
      t.authentik.users.get(3).put("is_superuser", false);
      t.authentik.users.get(3).getJSONObject("attributes").put("qqq.io/protected", true);
      refused(create(), "qqq.io/protected");
      t.authentik.users.get(3).getJSONObject("attributes").remove("qqq.io/protected");
      t.config.withProtectedUsernames(List.of("sam"));
      refused(create(), "protectedUsernames");
      t.config.withProtectedUsernames(List.of()).withTokenProtectedGroups(List.of());
      t.authentik.group("child-admin", false, List.of(), List.of(), "identity-admins");
      t.authentik.groupByName("child-admin").getJSONArray("users").put(3);
      refused(create(), "identity-admins");
      t.authentik.groupByName("child-admin").put("users", new JSONArray());
      t.authentik.group("child-super", false, List.of(), List.of(), "authentik Admins");
      t.authentik.groupByName("child-super").getJSONArray("users").put(3);
      refused(create(), "superuser");
      t.authentik.groupByName("child-super").put("users", new JSONArray());
      t.config.withTokenProtectedGroups(List.of("token-users"));
      refused(create(), "token-users");
   }

   /*******************************************************************************
    ** Expiry, scope opt-in, broker, delivery and feature guards all fail closed.
    *******************************************************************************/
   @Test
   void reviewRefusals() throws QException
   {
      AdminRequest missing = create();
      missing.params().remove("expiresInDays");
      refused(missing, "Expiry is required");
      refused(create().with("expiresInDays", 91), "90");
      refused(create().with("expiresInDays", 0), "1 and");
      refused(create().with("apps", "content"), "Scopes are not enabled");
      refused(create().with("description", ""), "description");
      t.config.withTokenBrokerClientSecret(null);
      refused(create(), "broker");
      t.config.withTokenBrokerClientSecret("test-secret").withSubjectTokenSource(session -> null);
      refused(create(), "signed-in Authentik session");
      t.config.withSubjectTokenSource(session -> "subject:3");
      TokenKeyDelivery.set(null);
      refused(create(), "upgrade QQQ");
      seed("own", 3);
      refused(AdminRequest.of(AdminAction.ROTATE_TOKEN, "own", "replace"), "upgrade QQQ");
      t.loginAs("operator@example.test", IdentityPermission.values());
      seed("service", 6);
      refused(AdminRequest.of(AdminAction.ROTATE_TOKEN, "service", "replace"), "upgrade QQQ");
      refused(AdminRequest.of(AdminAction.EXTEND_TOKEN, "service", "needed").with("expiresInDays", 366), "365");
      t.config.withTokensEnabled(false);
      refused(create(), "not enabled");
   }

   /*******************************************************************************
    ** Service token approvals use the existing second-person queue and replay.
    *******************************************************************************/
   @Test
   void twoPersonApproval() throws QException
   {
      t.config.withTokenTwoPersonApproval(true);
      t.loginAs("operator@example.test", IdentityPermission.values());
      seed("service", 6);
      for(AdminRequest request : List.of(AdminRequest.of(AdminAction.ROTATE_TOKEN, "service", "replace"),
         AdminRequest.of(AdminAction.CREATE_SERVICE_ACCOUNT, "", "automation").with("name", "approved-service").with("expiresInDays", 100)))
      {
         assertThat(t.admin().plan(request).getState()).isEqualTo(AdminPlan.State.NEEDS_APPROVAL);
         assertThat(t.admin().execute(request.with("approved", true)).pending()).isTrue();
      }
      List<QRecord> approvals = new QueryAction().execute(new QueryInput().withTableName("authentik_approval_request")).getRecords();
      t.loginAs("second@example.test", IdentityPermission.values());
      for(QRecord approval : approvals)
      {
         AuthentikAdmin.AdminResult result = t.admin().approve(approval.getValue("id"));
         assertThat(result.ok()).as(result.message()).isTrue();
         assertThat(result.takeSecret()).isNotNull();
      }
   }

   /*******************************************************************************
    ** Broker policy denial is mapped without echoing secrets or creating a token.
    *******************************************************************************/
   @Test
   void brokerDenial() throws QException
   {
      t.authentik.deniedSubjects.add(3);
      AuthentikAdmin.AdminResult result = t.admin().execute(create());
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).isEqualTo("Authentik refused to act as you (invalid_grant)");
      assertThat(t.authentik.tokenKeys).isEmpty();
   }

   /*******************************************************************************
    ** All key-producing actions go through real process state and response SPI.
    *******************************************************************************/
   @Test
   void realProcessesNeverPersistKeysAndBulkRevoke() throws QException
   {
      t.loginAs("sam@example.test", IdentityPermission.AUDIT_READ);
      run("createToken", null, Map.of("description", "automation", "expiresInDays", 30, "reason", "test"));
      assertThat(delivered).hasSize(1);
      String id = delivered.get(0).label();
      run("rotateToken", List.of(id), Map.of("reason", "replace"));
      assertThat(delivered).hasSize(2);
      t.loginAs("operator@example.test", IdentityPermission.values());
      seed("service", 6);
      run("rotateToken", List.of("service"), Map.of("reason", "replace"));
      run("createServiceAccount", null, Map.of("name", "process-service", "expiresInDays", 365, "reason", "test"));
      assertThat(delivered).hasSize(4);
      for(OneTimeKey key : delivered)
      {
         assertNoKey(key, new AuthentikAdmin.AdminResult(true, false, false, "done", null));
      }
      seed("human-other", 7);
      run("revokeToken", List.of(delivered.get(1).label(), "human-other", "service"), Map.of("reason", "incident"));
      assertThat(t.authentik.tokenKeys).doesNotContainKeys(delivered.get(1).label(), "human-other", "service");
   }

   /*******************************************************************************
    ** Loss of the response channel after Review revokes the new credential.
    *******************************************************************************/
   @Test
   void deliveryFailureRevokes() throws QException
   {
      t.loginAs("sam@example.test", IdentityPermission.AUDIT_READ);
      TokenKeyDelivery.set((output, key) ->
      {
         throw (new IllegalStateException("test channel failure"));
      });
      RunProcessOutput output = run("createToken", null, Map.of("description", "automation", "expiresInDays", 30, "reason", "test"));
      assertThat(JsonUtils.toJson(output.getValues())).contains("The token was revoked; nothing was kept.");
      assertThat(t.authentik.tokenKeys).isEmpty();
   }

   /*******************************************************************************
    ** Drive details, Review and Result through QQQ, inspecting saved state.
    *******************************************************************************/
   private RunProcessOutput run(String action, List<String> identifiers, Map<String, Serializable> values) throws QException
   {
      RunProcessInput input = new RunProcessInput();
      input.setProcessName(t.config.applyPrefix(action));
      if(identifiers != null)
      {
         input.addValue("recordIds", String.join(",", identifiers));
      }
      RunProcessOutput output = new RunProcessAction().execute(input);
      assertThat(output.getException()).isEmpty();
      input.setProcessUUID(output.getProcessUUID());
      values.forEach(input::addValue);
      input.setStartAfterStep("details");
      output = new RunProcessAction().execute(input);
      assertThat(output.getException()).isEmpty();
      assertThat(output.getProcessState().getNextStepName()).contains("review");
      input.setStartAfterStep("review");
      output = new RunProcessAction().execute(input);
      assertThat(output.getException()).isEmpty();
      String state = JsonUtils.toJson(RunProcessAction.getState(output.getProcessUUID()).orElseThrow().getValues());
      for(OneTimeKey key : delivered)
      {
         assertThat(state).doesNotContain(key.value());
         assertThat(JsonUtils.toJson(output.getValues())).doesNotContain(key.value());
      }
      return (output);
   }

   /*******************************************************************************
    ** Search every local table, events, diagnostics and safe request bodies.
    *******************************************************************************/
   private void assertNoKey(OneTimeKey key, AuthentikAdmin.AdminResult result) throws QException
   {
      assertThat(result.toString()).doesNotContain(key.value());
      assertThat(String.join("\n", logLines)).doesNotContain(key.value());
      assertThat(t.authentik.events.toString()).doesNotContain(key.value());
      for(QTableMetaData table : t.qInstance.getTables().values())
      {
         if(AdminTestSupport.LOCAL.equals(table.getBackendName()))
         {
            List<QRecord> records = new QueryAction().execute(new QueryInput().withTableName(table.getName())).getRecords();
            assertThat(JsonUtils.toJson(records)).as(table.getName()).doesNotContain(key.value());
         }
      }
      for(int i = 0; i < t.authentik.writes.size(); i++)
      {
         String path = t.authentik.writes.get(i);
         if(!path.endsWith("/set_key/") && !path.equals("POST /core/tokens/") && !path.equals("POST /core/users/service_account/"))
         {
            assertThat(t.authentik.writeBodies.get(i).toString()).doesNotContain(key.value());
         }
      }
   }

   /*******************************************************************************
    ** Both independent read permissions pass core and qbit table guards.
    *******************************************************************************/
   @Test
   void tokenMetadataReadPermissions() throws QException
   {
      seed("readable", 6);
      for(IdentityPermission permission : List.of(IdentityPermission.AUDIT_READ, IdentityPermission.TOKENS_MANAGE))
      {
         t.loginAs("sam@example.test", permission);
         new com.kingsrook.qbits.authentik.security.TokenReadPermission().checkPermissionsThrowing(null, null);
         assertThat(new QueryAction().execute(new QueryInput().withTableName("authentik_token")).getRecords()).hasSize(1);
      }
      t.loginAs("sam@example.test");
      org.assertj.core.api.Assertions.assertThatThrownBy(() -> new com.kingsrook.qbits.authentik.security.TokenReadPermission().checkPermissionsThrowing(null, null))
         .isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException.class);
   }



   /*******************************************************************************
    ** Replanning closes a stale Review after a new protected-group membership.
    *******************************************************************************/
   @Test
   void rechecksProtectionAndReportsMissingServiceGroup() throws QException
   {
      AdminPlan plan = t.admin().plan(create());
      assertThat(plan.isRunnable()).isTrue();
      t.authentik.groupByName("identity-admins").getJSONArray("users").put(3);
      assertThat(t.admin().execute(plan, null).ok()).isFalse();
      assertThat(t.authentik.tokenKeys).isEmpty();
      t.loginAs("operator@example.test", IdentityPermission.values());
      t.authentik.groups.remove(t.authentik.pk("qqq-service-accounts"));
      AuthentikAdmin.AdminResult result = t.admin().execute(AdminRequest.of(AdminAction.CREATE_SERVICE_ACCOUNT, "", "automation")
         .with("name", "missing-group").with("expiresInDays", 10));
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(result.message()).contains("is missing");
      assertThat(result.takeSecret().usageText()).contains("Expires:");
   }



   /*******************************************************************************
    ** Rotation refuses API/non-expiring tokens, and failed deletes retain the old.
    *******************************************************************************/
   @Test
   void rotationConstraintsAndPartialFailure() throws QException
   {
      JSONObject token = seed("old", 3);
      token.put("intent", "api");
      refused(AdminRequest.of(AdminAction.ROTATE_TOKEN, "old", "replace"), "Only app-password");
      token.put("intent", "app_password").put("expiring", false);
      refused(AdminRequest.of(AdminAction.ROTATE_TOKEN, "old", "replace"), "expiry");
      token.put("expiring", true);
      t.authentik.failTokenDelete = true;
      AuthentikAdmin.AdminResult result = t.admin().execute(AdminRequest.of(AdminAction.ROTATE_TOKEN, "old", "replace"));
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("revocation failed");
      assertThat(t.authentik.tokenKeys).containsKey("old");
      assertThat(result.takeSecret()).isNull();
   }



   /*******************************************************************************
    ** Feature defaults and metadata contain only non-secret token fields.
    *******************************************************************************/
   @Test
   void featureDefaultsAndMetadata()
   {
      assertThat(t.config.hasFeature(AuthentikFeature.TOKENS)).isTrue();
      assertThat(t.config.withReadOnly(true).hasFeature(AuthentikFeature.TOKENS)).isFalse();
      t.config.withReadOnly(false).withTokensEnabled(false);
      assertThat(t.config.hasFeature(AuthentikFeature.TOKENS)).isFalse();
      t.config.withTokensEnabled(true).withFeatures(EnumSet.of(AuthentikFeature.READ));
      assertThat(t.config.hasFeature(AuthentikFeature.TOKENS)).isFalse();
      t.config.withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.TOKENS));
      assertThat(t.config.hasFeature(AuthentikFeature.TOKENS)).isTrue();
      assertThat(AuthentikTables.get(AuthentikTables.TOKEN).getField("key")).isNull();
      assertThat(t.qInstance.getTable("authentik_token").getFields()).containsKeys("ownerPk", "ownerType", "ownerName", "managed").doesNotContainKey("key");
      assertThat(t.qInstance.getTable("authentik_token_scope").getFields()).doesNotContainKey("key");
      assertThat(t.config.toString()).doesNotContain("test-broker-secret");
   }
}
