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
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.security.AuthentikSessionIdentity;
import com.kingsrook.qbits.authentik.sync.AuthentikMirrorAccess;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QAuthenticationException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Request-time replacement must not revive grants carried by an old login.
 ******************************************************************************/
class AuthentikRefreshingPermissionMapperTest
{
   /***************************************************************************
    ** Leave no internal system context behind between tests.
    ***************************************************************************/
   @AfterEach
   void cleanup()
   {
      QContext.clear();
   }

   /***************************************************************************
    ** The same login follows membership changes and drops old session grants.
    ***************************************************************************/
   @Test
   void replacesOldGrantsAndRestoresCallerContext() throws Exception
   {
      QInstance instance = AuthentikTestSupport.produce(AuthentikTestSupport.unitConfig());
      QSession session = new QSession();
      session.setPermissions(Set.of("old.session.hasAccess"));
      QContext.init(instance, session);
      CurrentMapper mapper = new CurrentMapper();
      mapper.withGroupPermissions("Readers", List.of("host.read.hasAccess"));
      mapper.current = ready(Set.of("Readers"), Set.of("document.read.hasAccess"));
      JSONObject claims = claims().put("groups", List.of("OldAdmins")).put("access_token", "never-retain");
      mapper.customizeSession(instance, session, Map.of(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY, claims));
      assertThat(session.getPermissions()).containsExactlyInAnyOrder("host.read.hasAccess", "document.read.hasAccess");
      assertThat(session.getValue(AuthentikRefreshingPermissionMapper.CLAIMS)).doesNotContain("OldAdmins", "never-retain", "groups");
      String retained = session.getValue(AuthentikRefreshingPermissionMapper.CLAIMS);
      mapper.current = ready(Set.of(), Set.of());
      mapper.refresh(instance, session);
      assertThat(session.getPermissions()).isEmpty();
      assertThat(session.getValue(AuthentikRefreshingPermissionMapper.CLAIMS)).isEqualTo(retained);
      assertThat(QContext.getQSession()).isSameAs(session);
   }

   /***************************************************************************
    ** Missing/inactive identities and stale mirrors fail closed on old sessions.
    ***************************************************************************/
   @Test
   void deniedOrUnavailableProjectionClearsPermissions() throws Exception
   {
      QInstance instance = AuthentikTestSupport.produce(AuthentikTestSupport.unitConfig());
      QSession session = new QSession();
      QContext.init(instance, session);
      CurrentMapper mapper = new CurrentMapper();
      mapper.current = ready(Set.of(), Set.of("document.read.hasAccess"));
      mapper.customizeSession(instance, session, Map.of(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY, claims()));
      for(var status : List.of(AuthentikMirrorAccess.Status.DENIED, AuthentikMirrorAccess.Status.UNAVAILABLE))
      {
         session.setPermissions(Set.of("stale.hasAccess"));
         mapper.current = new AuthentikMirrorAccess.Result(status, null);
         assertThatThrownBy(() -> mapper.refresh(instance, session)).isInstanceOf(QAuthenticationException.class);
         assertThat(session.getPermissions()).isEmpty();
         assertThat(QContext.getQSession()).isSameAs(session);
      }
   }

   /***************************************************************************
    ** Mutable email and legacy subject are not substitutes for signed identity.
    ***************************************************************************/
   @Test
   void rejectsLegacyClaimsWithoutImmutableIdentity() throws Exception
   {
      QInstance instance = AuthentikTestSupport.produce(AuthentikTestSupport.unitConfig());
      QSession session = new QSession();
      session.setPermissions(Set.of("stale.hasAccess"));
      QContext.init(instance, session);
      CurrentMapper mapper = new CurrentMapper();
      assertThatThrownBy(() -> mapper.customizeSession(instance, session,
         Map.of(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY, new JSONObject().put("sub", "someone@example.test"))))
         .isInstanceOf(IllegalStateException.class);
      assertThat(session.getPermissions()).isEmpty();
      assertThat(session.getValue(AuthentikRefreshingPermissionMapper.CLAIMS)).isNull();
   }

   /***************************************************************************
    ** Synthetic verified claims; JWT authentication belongs to the OAuth module.
    ***************************************************************************/
   private static JSONObject claims()
   {
      return (new JSONObject().put("qqq_identity", new JSONObject().put("pk", 123)
         .put("uuid", "ec5b2c2c-68df-4cd5-972f-1e099728fe0b")).put("sub", "opaque-subject")
         .put("iss", "https://authentik.example.test/application/o/app/"));
   }

   /***************************************************************************
    ** A trusted OAuth issuer cannot borrow another directory's matching pk/uuid.
    ** Check provenance before mirror lookup, on login and existing-session use.
    ***************************************************************************/
   @Test
   void foreignIssuerCannotBorrowDirectoryIdentity() throws Exception
   {
      var config = AuthentikTestSupport.unitConfig();
      var instance = AuthentikTestSupport.produce(config);
      var mapper = new CurrentMapper();
      mapper.current = ready(Set.of("Readers"), Set.of("document.read.hasAccess"));
      var session = new QSession();
      QContext.init(instance, session);
      for(Object issuer : new Object[] { "https://foreign.example.test/application/o/app/", JSONObject.NULL, 42,
         "https://authentik.example.test.evil.test/", "http://authentik.example.test/application/o/app/" })
      {
         session.setPermissions(Set.of("stale.hasAccess"));
         assertThatThrownBy(() -> mapper.customizeSession(instance, session,
            Map.of(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY, claims().put("iss", issuer))))
            .isInstanceOf(IllegalStateException.class);
         assertThat(session.getPermissions()).isEmpty();
         assertThat(mapper.reads).isZero();
      }
      mapper.customizeSession(instance, session, Map.of(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY, claims()));
      assertThat(session.getPermissions()).containsExactly("document.read.hasAccess");
      assertThat(mapper.reads).isEqualTo(1);
      config.withAuthentikPublicUrl("https://replacement.example.test");
      assertThatThrownBy(() -> mapper.refresh(instance, session)).isInstanceOf(QAuthenticationException.class);
      assertThat(session.getPermissions()).isEmpty();
      assertThat(mapper.reads).isEqualTo(1);
      assertThat(QContext.getQSession()).isSameAs(session);
   }

   /***************************************************************************
    ** Cut-over fallback uses current directory email/groups, not login claims.
    ***************************************************************************/
   @Test
   void hostFallbackUsesCurrentIdentityAndGroups() throws Exception
   {
      var config = AuthentikTestSupport.unitConfig().withHostPermissionSource((email, groups) ->
      {
         assertThat(email).isEqualTo("current@example.test");
         assertThat(groups).containsExactly("Current");
         return (Set.of("host.current.hasAccess"));
      });
      QInstance instance = AuthentikTestSupport.produce(config);
      QSession session = new QSession();
      QContext.init(instance, session);
      CurrentMapper mapper = new CurrentMapper();
      mapper.active = false;
      mapper.current = ready(Set.of("Current"), Set.of("policy.notYetActive.hasAccess"));
      mapper.customizeSession(instance, session, Map.of(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY,
         claims().put("email", "old@example.test").put("groups", List.of("Old"))));
      assertThat(session.getPermissions()).containsExactly("host.current.hasAccess");
   }

   /***************************************************************************
    ** A malformed credential scope must narrow even immutable bootstrap grants.
    ***************************************************************************/
   @Test
   void credentialRestrictionsApplyAfterBootstrapOnEveryRefresh() throws Exception
   {
      var config = AuthentikTestSupport.unitConfig().withBootstrapOperatorSubjects("123");
      QInstance instance = AuthentikTestSupport.produce(config);
      QSession session = new QSession();
      QContext.init(instance, session);
      CurrentMapper mapper = new CurrentMapper();
      mapper.current = ready(Set.of(), Set.of("document.read.hasAccess"));
      mapper.customizeSession(instance, session, Map.of(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY, claims()));
      assertThat(session.getPermissions()).contains("authentik.users.read.hasAccess");
      mapper.customizeSession(instance, session, Map.of(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY,
         claims().put(config.getTokenScopeClaim(), 123)));
      assertThat(session.getPermissions()).isEmpty();
      mapper.refresh(instance, session);
      assertThat(session.getPermissions()).isEmpty();
      assertThat(QContext.getQSession()).isSameAs(session);
   }

   /***************************************************************************
    ** A committed projection supplied by the reader seam.
    ***************************************************************************/
   private static AuthentikMirrorAccess.Result ready(Set<String> groups, Set<String> permissions)
   {
      return (new AuthentikMirrorAccess.Result(AuthentikMirrorAccess.Status.READY,
         new AuthentikMirrorAccess.Access(groups, permissions, Instant.now(), "current@example.test")));
   }

   /***************************************************************************
    ** Only storage and cut-over are isolated; grant replacement is production code.
    ***************************************************************************/
   private static class CurrentMapper extends AuthentikRefreshingPermissionMapper
   {
      private AuthentikMirrorAccess.Result current;
      private boolean active = true;
      private int reads;

      /***********************************************************************
       ** Reader runs as the system and receives the signed immutable identity.
       ***********************************************************************/
      @Override
      protected AuthentikMirrorAccess.Result readCurrent(AuthentikSessionIdentity identity)
      {
         reads++;
         assertThat(QContext.getQSession()).isInstanceOf(QSystemUserSession.class);
         assertThat(identity.pk()).isEqualTo(123);
         return (current);
      }

      /***********************************************************************
       ** These tests exercise the active policy state.
       ***********************************************************************/
      @Override
      protected boolean enforced(QInstance instance)
      {
         return (active);
      }
   }
}
