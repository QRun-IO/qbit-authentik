/*
 * Copyright 2026 Kingsrook, LLC
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kingsrook.qbits.authentik.permissions;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.sync.AuthentikSessionBindings;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QAuthenticationException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.OAuth2AuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QUser;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/*******************************************************************************
 ** Adapter protocol tests. JWT authenticity and SQL races have separate gates.
 ******************************************************************************/
class AuthentikRefreshingOAuth2ModuleTest
{
   private QInstance instance;
   private TestModule module;
   private QSession session;
   private static final String USER_UUID = "ec5b2c2c-68df-4cd5-972f-1e099728fe0b";

   /***************************************************************************
    ** A session returned by the verified-core seam, with internal mapper facts.
    ***************************************************************************/
   @BeforeEach
   void setup() throws Exception
   {
      instance = AuthentikTestSupport.produce(AuthentikTestSupport.unitConfig());
      OAuth2AuthenticationMetaData metadata = new OAuth2AuthenticationMetaData();
      metadata.setMaxSessionLifetimeSeconds(600);
      metadata.setName("refresh-test");
      metadata.setBaseUrl("https://identity.example.test");
      metadata.setClientId("test-client");
      metadata.setClientSecret("synthetic-test-secret");
      metadata.setScopes("openid profile");
      metadata.setUserSessionTableName(instance.getTables().keySet().iterator().next());
      metadata.setRedirectStateTableName(instance.getTables().keySet().iterator().next());
      instance.withInstanceDefaultAuthentication(metadata);
      module = new TestModule();
      session = new QSession();
      session.setUuid(UUID.randomUUID().toString());
      session.setUser(new QUser().withIdReference("original-subject"));
      session.setPermissions(Set.of("previous.hasAccess"));
      session.setValue(AuthentikRefreshingPermissionMapper.BACKEND, "authentikApi");
      session.setValue(AuthentikRefreshingPermissionMapper.CLAIMS, new JSONObject().put("qqq_identity",
         new JSONObject().put("pk", 123).put("uuid", USER_UUID)).put("iat", Instant.now().getEpochSecond()).toString());
      module.authenticated = session;
      QContext.init(instance, session);
   }

   /***************************************************************************
    ** Do not leak temporary privileged contexts into another test.
    ***************************************************************************/
   @AfterEach
   void cleanup()
   {
      QContext.clear();
   }

   /***************************************************************************
    ** A cookie alone never authorizes creating a missing durable binding.
    ***************************************************************************/
   @Test
   void missingCookieBindingCannotBeRecreated() throws Exception
   {
      assertThatThrownBy(() -> module.createSession(instance, Map.of("sessionUUID", session.getUuid())))
         .isInstanceOf(QAuthenticationException.class);
      verify(module.store).find(session.getUuid());
      verify(module.store, never()).bind(anyString(), any());
      verify(module.mapper, never()).refresh(any(), any());
      assertThat(session.getPermissions()).isEmpty();
      assertThat(QContext.getQSession()).isSameAs(session);
   }

   /***************************************************************************
    ** Refresh on every resume, and reject a later revoke on the same object.
    ***************************************************************************/
   @Test
   void resumedSessionRefreshesAndLaterRevocationDenies() throws Exception
   {
      when(module.store.find(session.getUuid())).thenReturn(binding()).thenReturn(null);
      assertThat(module.createSession(instance, Map.of("sessionUUID", session.getUuid()))).isSameAs(session);
      verify(module.mapper).refresh(instance, session);
      assertThat(module.isSessionValid(instance, session)).isFalse();
      assertThat(session.getPermissions()).isEmpty();
      verify(module.store, never()).bind(anyString(), any());
   }

   /***************************************************************************
    ** The verified callback establishes identity with a bounded login deadline.
    ***************************************************************************/
   @Test
   void newVerifiedCallbackBindsOnce() throws Exception
   {
      when(module.store.bind(eq(session.getUuid()), any())).thenAnswer(invocation ->
      {
         AuthentikSessionBindings.Binding value = invocation.getArgument(1);
         assertThat(value.userPk()).isEqualTo(123);
         assertThat(value.userUuid()).isEqualTo(USER_UUID);
         assertThat(value.userReference()).isEqualTo("original-subject");
         assertThat(value.expiresAt()).isAfter(Instant.now().plusSeconds(590)).isBefore(Instant.now().plusSeconds(601));
         return (value);
      });
      module.createSession(instance, Map.of("code", "verified-by-core", "state", "verified-by-core"));
      verify(module.store).bind(eq(session.getUuid()), any());
      verify(module.mapper).refresh(instance, session);
   }

   /***************************************************************************
    ** Same pk/uuid cannot silently change the original core user reference.
    ***************************************************************************/
   @Test
   void identityReassignmentDeniesBeforeRefresh() throws Exception
   {
      when(module.store.find(session.getUuid())).thenReturn(new AuthentikSessionBindings.Binding(123, USER_UUID, "different", Instant.now().plusSeconds(600)));
      assertThat(module.isSessionValid(instance, session)).isFalse();
      verify(module.mapper, never()).refresh(any(), any());
      assertThat(session.getPermissions()).isEmpty();
   }

   /***************************************************************************
    ** Unsafe metadata must reject before any core authentication starts.
    ***************************************************************************/
   @Test
   void rejectsCachedOrUnboundedConfiguration() throws Exception
   {
      var actual = new AuthentikRefreshingOAuth2Module();
      assertThatThrownBy(() -> actual.createSession(instance, Map.of())).isInstanceOf(QAuthenticationException.class);
      var metadata = (OAuth2AuthenticationMetaData) instance.getAuthentication();
      metadata.setCustomizer(new QCodeReference(AuthentikRefreshingPermissionMapper.class));
      metadata.setSessionStoreEnabled(true);
      assertThatThrownBy(() -> actual.mapper(instance)).isInstanceOf(QAuthenticationException.class);
      metadata.setSessionStoreEnabled(false);
      metadata.setMaxSessionLifetimeSeconds(null);
      assertThatThrownBy(() -> actual.mapper(instance)).isInstanceOf(QAuthenticationException.class);
      metadata.setMaxSessionLifetimeSeconds(2592001);
      assertThatThrownBy(() -> actual.mapper(instance)).isInstanceOf(QAuthenticationException.class);
      metadata.setMaxSessionLifetimeSeconds(600);
      assertThat(actual.mapper(instance)).isInstanceOf(AuthentikRefreshingPermissionMapper.class);
      metadata.setCustomizer(new QCodeReference(AuthentikGroupPermissionMapper.class));
      assertThatThrownBy(() -> actual.mapper(instance)).isInstanceOf(QAuthenticationException.class);
      assertThat(actual.isSessionValid(instance, session)).isFalse();
      assertThat(session.getPermissions()).isEmpty();
   }

   /***************************************************************************
    ** Existing unexpired login reference.
    ***************************************************************************/
   private AuthentikSessionBindings.Binding binding()
   {
      return (new AuthentikSessionBindings.Binding(123, USER_UUID, "original-subject", Instant.now().plusSeconds(600)));
   }

   /***************************************************************************
    ** A bearer binding cannot outlive its verified token, even with a long host lifetime.
    ***************************************************************************/
   @Test
   void bearerDeadlineIsBoundedByToken() throws Exception
   {
      Instant expiry = Instant.now().plusSeconds(30).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
      session.setValue(AuthentikRefreshingOAuth2Module.BEARER_SESSION_VALUE_KEY, "true");
      session.setValue(AuthentikRefreshingOAuth2Module.BEARER_SESSION_EXPIRES_AT_VALUE_KEY, Long.toString(expiry.getEpochSecond()));
      when(module.store.bind(eq(session.getUuid()), any())).thenAnswer(invocation ->
      {
         AuthentikSessionBindings.Binding value = invocation.getArgument(1);
         assertThat(value.expiresAt()).isEqualTo(expiry);
         return (value);
      });
      module.createSession(instance, Map.of("accessToken", "verified-by-core"));
      verify(module.store).bind(eq(session.getUuid()), any());
   }

   /***************************************************************************
    ** A signed token's age must survive missing bindings and tombstone cleanup.
    ** Otherwise a long-lived bearer could receive a fresh deadline after logout.
    ***************************************************************************/
   @Test
   void bearerLifetimeStartsAtSignedIssueTime() throws Exception
   {
      Instant issued = Instant.now().minusSeconds(300).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
      session.setValue(AuthentikRefreshingOAuth2Module.BEARER_SESSION_VALUE_KEY, "true");
      session.setValue(AuthentikRefreshingOAuth2Module.BEARER_SESSION_EXPIRES_AT_VALUE_KEY, Long.toString(Instant.now().plusSeconds(3600).getEpochSecond()));
      var claims = new JSONObject(session.getValue(AuthentikRefreshingPermissionMapper.CLAIMS)).put("iat", issued.getEpochSecond());
      session.setValue(AuthentikRefreshingPermissionMapper.CLAIMS, claims.toString());
      when(module.store.bind(eq(session.getUuid()), any())).thenAnswer(invocation ->
      {
         AuthentikSessionBindings.Binding value = invocation.getArgument(1);
         assertThat(value.expiresAt()).isEqualTo(issued.plusSeconds(600));
         return (value);
      });
      module.createSession(instance, Map.of("accessToken", "verified-by-core"));
   }

   /***************************************************************************
    ** Missing, future, malformed or too-old signed issue times cannot create a
    ** binding or authorize an existing session, even while token exp is future.
    ***************************************************************************/
   @Test
   void invalidBearerAgeCannotBindOrResume() throws Exception
   {
      session.setValue(AuthentikRefreshingOAuth2Module.BEARER_SESSION_VALUE_KEY, "true");
      session.setValue(AuthentikRefreshingOAuth2Module.BEARER_SESSION_EXPIRES_AT_VALUE_KEY, Long.toString(Instant.now().plusSeconds(3600).getEpochSecond()));
      when(module.store.bind(anyString(), any())).thenReturn(binding());
      when(module.store.find(anyString())).thenReturn(binding());
      for(Object issued : new Object[] { JSONObject.NULL, "123", 1.5, -1, Instant.now().plusSeconds(300).getEpochSecond(), Instant.now().minusSeconds(601).getEpochSecond() })
      {
         var claims = new JSONObject(session.getValue(AuthentikRefreshingPermissionMapper.CLAIMS)).put("iat", issued);
         session.setValue(AuthentikRefreshingPermissionMapper.CLAIMS, claims.toString());
         assertThatThrownBy(() -> module.createSession(instance, Map.of("accessToken", "verified-by-core")))
            .isInstanceOf(QAuthenticationException.class);
         assertThat(module.isSessionValid(instance, session)).isFalse();
      }
      verify(module.store, never()).bind(anyString(), any());
      verify(module.mapper, never()).refresh(any(), any());
   }

   /***************************************************************************
    ** Logout leaves a durable tombstone and restores the caller's context.
    ***************************************************************************/
   @Test
   void logoutRevokesBinding() throws Exception
   {
      module.logout(instance, session.getUuid());
      verify(module.store).revoke(session.getUuid());
      assertThat(QContext.getQSession()).isSameAs(session);
   }

   /***************************************************************************
    ** Isolate external verification and SQL; preserve the adapter protocol.
    ***************************************************************************/
   private static class TestModule extends AuthentikRefreshingOAuth2Module
   {
      private final AuthentikSessionBindings store = mock(AuthentikSessionBindings.class);
      private final AuthentikRefreshingPermissionMapper mapper = mock(AuthentikRefreshingPermissionMapper.class);
      private QSession authenticated;

      /***********************************************************************
       ** The mapper name matches internal facts produced by verified login.
       ***********************************************************************/
      TestModule()
      {
         when(mapper.getApiBackendName()).thenReturn("authentikApi");
      }

      /***********************************************************************
       ** Substitute only the configured customizer.
       ***********************************************************************/
      @Override
      protected AuthentikRefreshingPermissionMapper mapper(QInstance ignored)
      {
         return (mapper);
      }

      /***********************************************************************
       ** SQL persistence is covered by H2 and PostgreSQL contracts.
       ***********************************************************************/
      @Override
      protected AuthentikSessionBindings bindings(AuthentikRefreshingPermissionMapper ignored)
      {
         return (store);
      }

      /***********************************************************************
       ** Never treat this seam as proof of real token authenticity.
       ***********************************************************************/
      @Override
      protected QSession authenticate(QInstance ignored, Map<String, String> context)
      {
         return (authenticated);
      }

      /***********************************************************************
       ** Protocol tests begin after core credential validity has passed.
       ***********************************************************************/
      @Override
      protected boolean authenticatedSessionValid(QInstance ignored, QSession candidate)
      {
         return (true);
      }
   }
}
