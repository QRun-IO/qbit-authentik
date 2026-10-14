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


import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.permissions.AuthentikGroupPermissionMapper;
import com.kingsrook.qbits.authentik.policy.AuthentikPolicyClaimMapper;
import com.kingsrook.qbits.authentik.processes.TokenKeyDelivery;
import com.kingsrook.qbits.authentik.security.AuthentikTokenScopes;
import com.kingsrook.qbits.authentik.security.AuthentikTokenScopes.Mode;
import com.kingsrook.qbits.authentik.security.AuthentikTokenScopes.TokenScope;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.reporting.QReportMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Scope enforcement intersects existing permissions without Docker or OAuth.
 *******************************************************************************/
class TokenScopesTest
{
   private AdminTestSupport t;

   /*******************************************************************************
    ** Instance includes a table whose permission base differs from its name.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws QException
   {
      t = AdminTestSupport.create();
      t.config.withTokenScopesEnabled(true).withTokenBrokerClientId("broker").withTokenBrokerClientSecret("secret")
         .withSubjectTokenSource(session -> "subject:3");
      TokenKeyDelivery.set((output, key) -> {});
   }



   /*******************************************************************************
    ** Reset the response-only test adapter.
    *******************************************************************************/
   @AfterEach
   void tearDown()
   {
      TokenKeyDelivery.set(null);
   }



   /*******************************************************************************
    ** Seed a credential and optional local metadata.
    *******************************************************************************/
   private void seed(String id, AdminRequest scope) throws QException
   {
      t.authentik.seedToken(id, 3, "app_password", Instant.now().plusSeconds(86400).toString());
      if(scope != null)
      {
         new TokenScopeStore(t.config).create(id, t.authentik.users.get(3), scope, "sam@example.test");
      }
   }



   /*******************************************************************************
    ** No claim means no scope lookup and no changes to the permission set.
    *******************************************************************************/
   @Test
   void absentAndExternalClaims() throws QException
   {
      QSession session = QContext.getQSession().withPermissions("post.read", "post.edit");
      Set<String> before = Set.copyOf(session.getPermissions());
      AuthentikTokenScopes.apply(session, new JSONObject());
      assertThat(session.getPermissions()).isEqualTo(before);
      assertThat(AuthentikTokenScopes.forClaims(t.qInstance, null)).isEmpty();
      seed("external", null);
      assertThat(AuthentikTokenScopes.forClaims(t.qInstance, new JSONObject().put("qqq_token", "external")).orElseThrow().mode()).isEqualTo(Mode.UNSCOPED);
      AuthentikTokenScopes.apply(session, new JSONObject().put("qqq_token", "external"));
      assertThat(session.getPermissions()).isEqualTo(before);
      assertThat(session.getValue("qqq.credentialScope")).isEqualTo("external");
   }



   /*******************************************************************************
    ** Read-only strips writes and management hasAccess permissions.
    *******************************************************************************/
   @Test
   void readOnlyAndDeletedToken() throws QException
   {
      seed("limited", AdminRequest.of(AdminAction.CREATE_TOKEN, "", "test").with("readOnly", true));
      QSession session = t.loginAs("sam@example.test").withPermissions("cms.publish.hasAccess", "post.read", "post.edit", "authentik.tokens.manage.hasAccess");
      JSONObject claims = new JSONObject().put("qqq_token", "limited");
      AuthentikTokenScopes.apply(session, claims);
      assertThat(session.getPermissions()).containsExactlyInAnyOrder("cms.publish.hasAccess", "post.read");
      t.authentik.tokens.get("sam").clear();
      AuthentikRuntime.forBackend(t.config.getApiBackendName()).invalidateCache();
      AuthentikTokenScopes.apply(session, claims);
      assertThat(session.getPermissions()).isEmpty();
      assertThat(AuthentikTokenScopes.forClaims(t.qInstance, claims).orElseThrow().mode()).isEqualTo(Mode.DENY_ALL);
      assertThat(new TokenScopeStore(t.config).find("limited")).isNotNull();
   }



   /*******************************************************************************
    ** A scope cannot grant missing read permissions, even with a valid table.
    *******************************************************************************/
   @Test
   void tableNamesResolvePermissionAliasesAndNeverWiden() throws QException
   {
      seed("table", AdminRequest.of(AdminAction.CREATE_TOKEN, "", "test").with("tables", "post"));
      QSession session = t.loginAs("sam@example.test").withPermissions("cms.publish.hasAccess", "kof22.analytics.hasAccess");
      JSONObject claims = new JSONObject().put("qqq_token", "table");
      AuthentikTokenScopes.apply(session, claims);
      assertThat(session.getPermissions()).containsExactly("cms.publish.hasAccess");
      session.setPermissions(Set.of("kof22.analytics.hasAccess"));
      AuthentikTokenScopes.apply(session, claims);
      assertThat(session.getPermissions()).isEmpty();
   }



   /*******************************************************************************
    ** An app includes its table actions, reports and widgets, not other apps.
    *******************************************************************************/
   @Test
   void appChildrenAndExplicitTableUnion() throws QException
   {
      var rules = new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION);
      QProcessMetaData process = new QProcessMetaData().withName("publish").withTableName("post").withPermissionRules(rules);
      QReportMetaData report = new QReportMetaData().withName("report").withPermissionRules(rules);
      QWidgetMetaData widget = new QWidgetMetaData().withName("widget").withType("TABLE").withPermissionRules(rules);
      t.qInstance.addProcess(process);
      t.qInstance.addReport(report);
      t.qInstance.addWidget(widget);
      t.qInstance.addApp(new QAppMetaData().withName("content").withPermissionRules(rules).withChild(t.qInstance.getTable("post"))
         .withChild(report).withWidgets(List.of("widget")));
      seed("app", AdminRequest.of(AdminAction.CREATE_TOKEN, "", "test").with("apps", "content").with("tables", "analytics"));
      QSession session = t.loginAs("sam@example.test").withPermissions("content.hasAccess", "cms.publish.hasAccess", "publish.hasAccess", "report.hasAccess",
         "widget.hasAccess", "kof22.analytics.hasAccess", "unrelated.read");
      AuthentikTokenScopes.apply(session, new JSONObject().put("qqq_token", "app"));
      assertThat(session.getPermissions()).containsExactlyInAnyOrder("content.hasAccess", "cms.publish.hasAccess", "publish.hasAccess", "report.hasAccess",
         "widget.hasAccess", "kof22.analytics.hasAccess");
   }



   /*******************************************************************************
    ** The configured claim is enforced even if offering new scopes is disabled.
    *******************************************************************************/
   @Test
   void configuredClaimCacheAndMalformedClaim() throws QException
   {
      t.config.withTokenScopesEnabled(false).withTokenScopeClaim("credential");
      seed("external", null);
      QSession session = t.loginAs("sam@example.test").withPermissions("post.read");
      JSONObject claims = new JSONObject().put("credential", "external");
      AuthentikTokenScopes.apply(session, claims);
      t.authentik.tokens.get("sam").clear();
      AuthentikTokenScopes.apply(session, claims);
      assertThat(session.getPermissions()).containsExactly("post.read");
      AuthentikRuntime.forBackend(t.config.getApiBackendName()).invalidateCache();
      AuthentikTokenScopes.apply(session, claims);
      assertThat(session.getPermissions()).isEmpty();
      session.withPermission("post.read");
      AuthentikTokenScopes.apply(session, new JSONObject().put("credential", new JSONObject()));
      assertThat(session.getPermissions()).isEmpty();
   }



   /*******************************************************************************
    ** Both claims customizers narrow after computing their permission unions.
    *******************************************************************************/
   @Test
   void mappersCannotAddPermissionsAfterDenyAll()
   {
      JSONObject claims = new JSONObject().put("qqq_token", "deleted");
      QSession session = t.loginAs("sam@example.test").withPermission("post.read");
      new AuthentikPolicyClaimMapper().customizeSession(t.qInstance, session, Map.of("jwtPayloadJsonObject", claims));
      assertThat(session.getPermissions()).isEmpty();
      session.withPermission("post.read");
      new AuthentikGroupPermissionMapper().withGroupPermissions("test", List.of("post.edit"))
         .customizeSession(t.qInstance, session, Map.of("jwtPayloadJsonObject", claims.put("groups", List.of("test"))));
      assertThat(session.getPermissions()).isEmpty();
   }



   /*******************************************************************************
    ** Review validates current access and displays the scope; execution repeats.
    *******************************************************************************/
   @Test
   void reviewRejectsUnknownOrUnheldAndExecutionRechecks() throws QException
   {
      t.loginAs("sam@example.test");
      AdminRequest request = AdminRequest.of(AdminAction.CREATE_TOKEN, "", "test").with("description", "CI").with("expiresInDays", 30).with("tables", "missing");
      assertThat(t.admin().plan(request).getMessage()).contains("Unknown");
      request.with("tables", "post");
      assertThat(t.admin().plan(request).getMessage()).contains("read access");
      QContext.getQSession().withPermission("cms.publish.hasAccess");
      assertThat(t.admin().plan(request).describe()).contains("tables: post");
      QContext.getQSession().setPermissions(Set.of());
      assertThat(t.admin().execute(request).ok()).isFalse();
      assertThat(t.changes()).isEmpty();
   }
   /*******************************************************************************
    ** A long general response cache cannot extend the scope revocation window.
    ** Lookup outages deny, rather than falling back to unrestricted access.
    *******************************************************************************/
   @Test
   void verificationCacheIsIndependentAndApiFailureDenies() throws QException
   {
      t.config.withListCacheTtlSeconds(3600);
      seed("cached", null);
      QSession session = t.loginAs("sam@example.test").withPermission("post.read");
      JSONObject claims = new JSONObject().put("qqq_token", "cached");
      AuthentikTokenScopes.apply(session, claims);
      assertThat(session.getPermissions()).containsExactly("post.read");
      t.authentik.tokens.get("sam").clear();
      AuthentikRuntime.forBackend(t.config.getApiBackendName()).getTokenScopeCache().clear();
      AuthentikTokenScopes.apply(session, claims);
      assertThat(session.getPermissions()).isEmpty();
      session.withPermission("post.read");
      com.kingsrook.qbits.authentik.client.FixtureActionUtil.handler = request ->
         com.kingsrook.qbits.authentik.client.FixtureActionUtil.response(403, "{}");
      AuthentikTokenScopes.apply(session, new JSONObject().put("qqq_token", "unavailable"));
      assertThat(session.getPermissions()).isEmpty();
   }



   /*******************************************************************************
    ** The ID token may supply policy context while the access token binds scope.
    *******************************************************************************/
   @Test
   void idTokenContextCannotHideAccessTokenScope()
   {
      QSession session = t.loginAs("sam@example.test").withPermission("post.read");
      new AuthentikPolicyClaimMapper().customizeSession(t.qInstance, session, Map.of(
         "idToken", new JSONObject().put("email", "sam@example.test"),
         "jwtPayloadJsonObject", new JSONObject().put("qqq_token", "deleted")));
      assertThat(session.getPermissions()).isEmpty();
   }

}
