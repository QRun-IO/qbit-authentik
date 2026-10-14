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

package com.kingsrook.qbits.authentik.preferences;


import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.admin.AdminAction;
import com.kingsrook.qbits.authentik.admin.AdminPlan;
import com.kingsrook.qbits.authentik.admin.AdminRequest;
import com.kingsrook.qbits.authentik.admin.AdminTestSupport;
import com.kingsrook.qbits.authentik.admin.TokenScopeStore;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.processes.TokenKeyDelivery;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.preferences.UserPreferencesAction;
import com.kingsrook.qqq.backend.core.actions.preferences.UserPreferencesKeyValueStoreMetaDataProvider;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.exceptions.QBadRequestException;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QNotFoundException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceActionMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceActionResult;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceActionScope;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceRow;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceSectionMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceSectionResult;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferencesMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.secrets.OneTimeSecret;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Exercise the real Preferences dispatcher against FakeAuthentik and local tables.
 *******************************************************************************/
class AccessTokenPreferencesTest
{
   private AdminTestSupport t;
   private final UserPreferencesAction actions = new UserPreferencesAction();
   private final List<String> logs = new ArrayList<>();
   private AbstractAppender appender;



   /*******************************************************************************
    ** No table permissions or process delivery adapter: core owns the response.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws QException
   {
      t = AdminTestSupport.create();
      t.config.withTokenBrokerClientId("test-broker").withTokenBrokerClientSecret("test-broker-secret")
         .withSubjectTokenSource(session -> "subject:3").withAppClientId("test-app")
         .withAppPublicUrl("https://app.example.test").withAuthentikPublicUrl("https://auth.example.test");
      t.authentik.users.get(3).getJSONObject("attributes").put("goauthentik.io/user/token-maximum-lifetime", "days=90");
      t.loginAs("sam@example.test");
      new UserPreferencesKeyValueStoreMetaDataProvider().defineAll(t.qInstance, AdminTestSupport.LOCAL, null);
      TokenKeyDelivery.set(null);
      appender = new AbstractAppender("preferences-token-capture", null, null, false, Property.EMPTY_ARRAY)
      {
         /*******************************************************************************
          ** Retain messages and throwable text for the secret-leak assertion.
          *******************************************************************************/
         @Override
         public void append(LogEvent event)
         {
            logs.add(event.getMessage().getFormattedMessage());
            if(event.getThrownProxy() != null)
            {
               logs.add(event.getThrownProxy().getExtendedStackTraceAsString());
            }
         }
      };
      appender.start();
      ((Logger) LogManager.getRootLogger()).addAppender(appender);
   }



   /*******************************************************************************
    ** Reset global fixture state after every test.
    *******************************************************************************/
   @AfterEach
   void tearDown()
   {
      ((Logger) LogManager.getRootLogger()).removeAppender(appender);
      appender.stop();
      TokenKeyDelivery.set(null);
      FixtureActionUtil.reset();
   }



   /*******************************************************************************
    ** Registration is independent of Identity app access; all cells are read-only.
    *******************************************************************************/
   @Test
   void metadataAndFeatureGate() throws QException
   {
      UserPreferenceSectionMetaData section = actions.getSection("access-tokens").getSection();
      assertThat(section.getLabel()).isEqualTo("Access tokens");
      assertThat(section.getIcon().getName()).isEqualTo("key");
      assertThat(section.getDescription()).isEqualTo("Personal access tokens for scripts and integrations. Keys are shown once.");
      assertThat(section.getOrder()).isEqualTo(30);
      assertThat(section.getShowInUserMenu()).isTrue();
      assertThat(section.getAppName()).isNull();
      assertThat(section.getPermissionName()).isNull();
      assertThat(section.getFields()).isEmpty();
      assertThat(section.getLists()).hasSize(1);
      assertThat(section.getLists().get(0).getRowLabel()).isEqualTo("Token");
      assertThat(section.getLists().get(0).getFields()).extracting(QFieldMetaData::getName)
         .containsExactly("description", "identifier", "intent", "expires", "scope");
      assertThat(section.getLists().get(0).getFields()).allMatch(field -> !field.getIsEditable());
      assertThat(section.getLists().get(0).getFields().get(3).getType()).isEqualTo(QFieldType.DATE_TIME);
      UserPreferenceActionMetaData create = section.getActions().get(0);
      assertThat(create.getScope()).isEqualTo(UserPreferenceActionScope.SECTION);
      assertThat(create.getListName()).isNull();
      assertThat(create.getInputFields()).extracting(QFieldMetaData::getName).containsExactly("description", "expiresInDays");
      assertThat(create.getInputFields()).allMatch(QFieldMetaData::getIsRequired);
      assertThat(create.getInputFields().get(1).getDefaultValue()).isEqualTo(30);
      assertThat(section.getActions().get(1).getConfirmationText()).isEqualTo("Rotate this token? The old key stops working now.");
      assertThat(section.getActions().get(1).getIsDestructive()).isTrue();
      assertThat(section.getActions().get(3).getConfirmationText()).isEqualTo("Revoke this token? Anything using it stops working now.");
      assertThat(section.getActions().get(3).getIsDestructive()).isTrue();
      assertThat(actions.listSections()).hasSize(1);
      t = AdminTestSupport.create(EnumSet.of(AuthentikFeature.READ));
      assertThat(actions.listSections()).isEmpty();
      assertThatThrownBy(() -> actions.getSection("access-tokens")).isInstanceOf(QNotFoundException.class);
   }



   /*******************************************************************************
    ** The service-account list request is owner/intent filtered even for managers.
    *******************************************************************************/
   @Test
   void loadOnlyOwnAppPasswordsAndRejectForeignRows() throws QException
   {
      seed("mine", 3, "app_password");
      seed("my-api", 3, "api");
      seed("someone-else", 7, "app_password");
      for(IdentityPermission[] permissions : List.of(new IdentityPermission[0], new IdentityPermission[] { IdentityPermission.TOKENS_MANAGE }))
      {
         t.loginAs("sam@example.test", permissions);
         assertThat(rows()).extracting(UserPreferenceRow::getKey).containsExactly("mine");
         assertThatThrownBy(() -> rowAction("revoke", "someone-else", Map.of())).isInstanceOf(QBadRequestException.class);
         assertThatThrownBy(() -> rowAction("rotate", "my-api", Map.of())).isInstanceOf(QBadRequestException.class);
      }
      assertThat(FixtureActionUtil.REQUESTS.stream().filter(r -> r.getURI().getPath().endsWith("/core/tokens/")))
         .allSatisfy(r ->
         {
            assertThat(r.getURI().getQuery()).contains("user__username=sam", "intent=app_password");
            assertThat(r.getFirstHeader("Authorization").getValue()).isEqualTo("Bearer " + t.config.getResolvedApiToken());
         });
      assertThat(t.changes()).isEmpty();
      t.loginAs("dormant@example.test");
      assertThat(rows()).extracting(UserPreferenceRow::getKey).containsExactly("someone-else");
   }



   /*******************************************************************************
    ** Create/rotate deliver one key each; extend/revoke never do. Reloads are safe.
    *******************************************************************************/
   @Test
   void lifecycleAndNoPersistedSecrets() throws QException
   {
      assertThat(TokenKeyDelivery.get().available()).isFalse();
      UserPreferenceActionResult created = create(Map.of("description", "Build script", "expiresInDays", 30));
      assertThat(created.getSecrets()).hasSize(1);
      OneTimeSecret first = created.getSecrets().get(0);
      String oldId = created.getFocusRowKey();
      assertThat(first.getLabel()).isEqualTo("Access token");
      assertThat(first.getMasked()).endsWith(first.getValue().substring(first.getValue().length() - 4));
      assertThat(first.getUsageText()).contains("https://auth.example.test/application/o/token/", "username=sam", "test-app",
         "https://app.example.test/qqq/v1/metaData", "Expires:");
      assertThat(rows()).extracting(UserPreferenceRow::getKey).containsExactly(oldId);
      assertThat(rows().get(0).getValues()).containsEntry("description", "Build script").containsEntry("scope", "Owner permissions");
      assertNoKey(first, created);

      UserPreferenceActionResult rotated = rowAction("rotate", oldId, Map.of());
      assertThat(rotated.getSecrets()).hasSize(1);
      OneTimeSecret next = rotated.getSecrets().get(0);
      String newId = rotated.getFocusRowKey();
      assertThat(newId).isNotEqualTo(oldId);
      assertThat(next.getValue()).isNotEqualTo(first.getValue());
      assertThat(t.authentik.tokenKeys).doesNotContainKey(oldId).containsEntry(newId, next.getValue());
      assertThat(rows()).extracting(UserPreferenceRow::getKey).containsExactly(newId);
      assertThat(rows().get(0).getValues().get("description")).isEqualTo("Build script");
      assertNoKey(next, rotated);

      UserPreferenceActionResult extended = rowAction("extend", newId, Map.of("expiresInDays", 60));
      assertThat(extended.getSecrets()).isEmpty();
      assertThat((Instant) rows().get(0).getValues().get("expires")).isAfter(Instant.now().plusSeconds(59 * 86400));
      assertThat(t.authentik.tokens.get("sam").get(0).getInt("user")).isEqualTo(3);
      assertThat(t.authentik.tokens.get("sam").get(0).getString("intent")).isEqualTo("app_password");
      assertNoKey(next, extended);

      UserPreferenceActionResult revoked = rowAction("revoke", newId, Map.of());
      assertThat(revoked.getSecrets()).isEmpty();
      assertThat(rows()).isEmpty();
      assertThat(t.authentik.tokenKeys).doesNotContainKey(newId);
      assertThat(FixtureActionUtil.REQUESTS.stream().filter(r -> r.getURI().getPath().contains("/core/tokens/")
         && (!"GET".equals(r.getMethod()) || r.getURI().getPath().endsWith("/view_key/"))))
         .allSatisfy(r -> assertThat(r.getFirstHeader("Authorization").getValue()).isEqualTo("Bearer user-bearer:3"));
      assertNoKey(first, revoked);
      assertNoKey(next, revoked);
      assertThat(new QueryAction().execute(new QueryInput().withTableName("user_preference")).getRecords()).isEmpty();
      List<QRecord> audits = new QueryAction().execute(new QueryInput().withTableName("authentik_admin_action")).getRecords();
      assertThat(audits).extracting(r -> r.getValueString("reason"))
         .containsExactly("Preferences: create", "Preferences: rotate", "Preferences: extend", "Preferences: revoke");
      assertThat(audits).allSatisfy(r ->
      {
         assertThat(r.getValueString("operator")).isEqualTo("sam@example.test");
         assertThat(r.getValueString("status")).isEqualTo("SUCCEEDED");
      });
   }



   /*******************************************************************************
    ** Scope inputs are conditional and their metadata survives rotation.
    *******************************************************************************/
   @Test
   void scopesAreOptIn() throws QException
   {
      assertThatThrownBy(() -> create(Map.of("description", "Scoped", "expiresInDays", 30, "readOnly", true)))
         .isInstanceOf(QBadRequestException.class);
      t.config.withTokenScopesEnabled(true);
      UserPreferencesMetaData.of(t.qInstance).getSections().clear();
      AccessTokenPreferences.register(t.qInstance, t.config);
      assertThat(actions.getSection("access-tokens").getSection().getActions().get(0).getInputFields()).extracting(QFieldMetaData::getName)
         .containsExactly("description", "expiresInDays", "readOnly", "apps", "tables");
      UserPreferenceActionResult created = create(Map.of("description", "Scoped", "expiresInDays", 30, "readOnly", true,
         "apps", "content", "tables", "post"));
      assertThat(rows().get(0).getValues().get("scope")).isEqualTo("readOnly: true; apps: content; tables: post");
      UserPreferenceActionResult rotated = rowAction("rotate", created.getFocusRowKey(), Map.of());
      assertThat(new TokenScopeStore(t.config).find(rotated.getFocusRowKey()).getValueBoolean("readOnly")).isTrue();
      assertThat(new TokenScopeStore(t.config).find(created.getFocusRowKey())).isNull();
      assertNoKey(created.getSecrets().get(0), created);
      assertNoKey(rotated.getSecrets().get(0), rotated);
   }



   /*******************************************************************************
    ** Domain refusals remain audited, before any token mutation or broker exchange.
    *******************************************************************************/
   @Test
   void protectedUserAndMissingBrokerRefused() throws QException
   {
      t.authentik.groupByName("identity-admins").getJSONArray("users").put(3);
      assertThatThrownBy(() -> create(Map.of("description", "Refused", "expiresInDays", 30)))
         .isInstanceOf(QUserFacingException.class).hasMessageContaining("Protected");
      t.authentik.groupByName("identity-admins").getJSONArray("users").remove(2);
      t.config.withTokenBrokerClientId("").withTokenBrokerClientSecret("");
      assertThatThrownBy(() -> create(Map.of("description", "Refused", "expiresInDays", 30)))
         .isInstanceOf(QUserFacingException.class).hasMessageContaining("token broker");
      assertThat(t.changes()).isEmpty();
      assertThat(t.authentik.tokenKeys).isEmpty();
      assertThat(FixtureActionUtil.REQUESTS).noneMatch(r -> r.getURI().getPath().endsWith("/application/o/token/"));
      assertThat(new QueryAction().execute(new QueryInput().withTableName("authentik_admin_action")).getRecords())
         .hasSize(2).allMatch(r -> "REFUSED".equals(r.getValueString("status")));
   }



   /*******************************************************************************
    ** Core rejects arbitrary values and row edits; omitted required inputs reach
    ** the existing domain validation rather than silently acquiring defaults.
    *******************************************************************************/
   @Test
   void validationAndReadOnlyRows() throws QException
   {
      seed("mine", 3, "app_password");
      assertThatThrownBy(() -> create(Map.of("description", "Missing expiry"))).hasMessageContaining("Expiry is required");
      assertThatThrownBy(() -> create(Map.of("expiresInDays", 30))).hasMessageContaining("description is required");
      assertThatThrownBy(() -> rowAction("extend", "mine", Map.of())).hasMessageContaining("Expiry is required");
      assertThatThrownBy(() -> create(Map.of("description", "Too long", "expiresInDays", 91))).hasMessageContaining("between 1 and 90");
      assertThatThrownBy(() -> create(Map.of("description", "Injected", "expiresInDays", 30, "deliveryChannel", "preferences")))
         .isInstanceOf(QBadRequestException.class);
      assertThatThrownBy(() -> actions.patchSection("access-tokens", Map.of("lists", Map.of("tokens",
         List.of(Map.of("key", "mine", "values", Map.of("description", "Changed")))))))
         .isInstanceOf(QBadRequestException.class).hasMessageContaining("can't be changed");
      assertThatThrownBy(() -> actions.patchSection("access-tokens", Map.of()))
         .isInstanceOf(QBadRequestException.class).hasMessageContaining("Use the access token actions");
      assertThat(t.changes()).isEmpty();
   }



   /*******************************************************************************
    ** Even a manager cannot use Preferences after the target moves to a person
    ** or service account, or changes intent, after the core row check.
    *******************************************************************************/
   @Test
   void managerCannotCrossOwnershipOrIntentBoundary() throws QException
   {
      t.loginAs("sam@example.test", IdentityPermission.TOKENS_MANAGE);
      JSONObject token = seed("mine", 3, "app_password");
      for(int owner : List.of(7, 6))
      {
         token.put("user", 3);
         AdminRequest request = AdminRequest.of(AdminAction.REVOKE_TOKEN, "mine", "Preferences: revoke").with("deliveryChannel", "preferences");
         AdminPlan plan = t.admin().plan(request);
         assertThat(plan.isRunnable()).isTrue();
         token.put("user", owner);
         assertThat(t.admin().execute(plan, null).ok()).isFalse();
      }
      token.put("user", 3).put("intent", "api");
      assertThat(t.admin().execute(AdminRequest.of(AdminAction.REVOKE_TOKEN, "mine", "Preferences: revoke")
         .with("deliveryChannel", "preferences")).ok()).isFalse();
      assertThat(t.changes()).isEmpty();
   }



   /*******************************************************************************
    ** A faulty upstream owner filter must never disclose another user's metadata.
    *******************************************************************************/
   @Test
   void refusesUnexpectedOwnerAndUnresolvedIdentity() throws QException
   {
      JSONObject foreign = seed("foreign", 7, "app_password");
      var original = FixtureActionUtil.handler;
      FixtureActionUtil.handler = request -> request.getURI().getPath().endsWith("/core/tokens/")
         ? FixtureActionUtil.response(200, new JSONObject().put("pagination", new JSONObject().put("total_pages", 1))
            .put("results", new JSONArray().put(foreign)).toString()) : original.apply(request);
      assertThatThrownBy(this::rows).isInstanceOf(QUserFacingException.class).hasMessageContaining("outside your personal token list");
      t.loginAs("unknown@example.test");
      assertThatThrownBy(this::rows).isInstanceOf(QUserFacingException.class);
   }



   /*******************************************************************************
    ** Drive a section-level action exactly as the UI API does.
    *******************************************************************************/
   private UserPreferenceActionResult create(Map<String, ?> values) throws QException
   {
      return (actions.runAction("access-tokens", "create", Map.of("values", values)));
   }



   /*******************************************************************************
    ** Drive a row action through core's loaded-row ownership check.
    *******************************************************************************/
   private UserPreferenceActionResult rowAction(String action, String key, Map<String, ?> values) throws QException
   {
      return (actions.runAction("access-tokens", action, Map.of("rowKey", key, "values", values)));
   }



   /*******************************************************************************
    ** Reload instead of reusing a previous action's response.
    *******************************************************************************/
   private List<UserPreferenceRow> rows() throws QException
   {
      return (actions.getSection("access-tokens").getValues().getLists().get("tokens"));
   }



   /*******************************************************************************
    ** Seed the upstream fake, never the local preference or token-scope store.
    *******************************************************************************/
   private JSONObject seed(String id, int owner, String intent)
   {
      return (t.authentik.seedToken(id, owner, intent, Instant.now().plusSeconds(86400).toString()));
   }



   /*******************************************************************************
    ** Inspect every local table (including audit and KV preferences), reloaded
    ** values, response section, events and captured messages/throwables.
    *******************************************************************************/
   private void assertNoKey(OneTimeSecret secret, UserPreferenceActionResult result) throws QException
   {
      String key = secret.getValue();
      assertThat(secret.toString()).doesNotContain(key);
      assertThat(result.getMessage()).doesNotContain(key);
      assertThat(JsonUtils.toJson(result.getSection())).doesNotContain(key);
      UserPreferenceSectionResult reload = actions.getSection("access-tokens");
      assertThat(JsonUtils.toJson(reload)).doesNotContain(key);
      assertThat(reload.getValues().getValues()).isEmpty();
      assertThat(String.join("\n", logs)).doesNotContain(key);
      assertThat(t.authentik.events.toString()).doesNotContain(key);
      for(QTableMetaData table : t.qInstance.getTables().values())
      {
         if(AdminTestSupport.LOCAL.equals(table.getBackendName()))
         {
            assertThat(JsonUtils.toJson(new QueryAction().execute(new QueryInput().withTableName(table.getName())).getRecords()))
               .as(table.getName()).doesNotContain(key);
         }
      }
   }
}
