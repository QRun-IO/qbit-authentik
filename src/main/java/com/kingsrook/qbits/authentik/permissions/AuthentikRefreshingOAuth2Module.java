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
import java.util.Objects;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.security.AuthentikSessionIdentity;
import com.kingsrook.qbits.authentik.sync.AuthentikSessionBindings;
import com.kingsrook.qqq.backend.core.actions.customizers.QCodeLoader;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QAuthenticationException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.OAuth2AuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.modules.authentication.implementations.OAuth2AuthenticationModule;
import org.json.JSONObject;

/*******************************************************************************
 ** Native OAuth verification plus durable immutable identity and current grants.
 ** Opt-in hosts must install the sync schema, a fresh mirror, signed identity
 ** mapping, refreshing customizer, disabled session cache and finite lifetime.
 ******************************************************************************/
public class AuthentikRefreshingOAuth2Module extends OAuth2AuthenticationModule
{
   /***************************************************************************
    ** Authenticate through core before binding a new login or checking a resume.
    ***************************************************************************/
   @Override
   public QSession createSession(QInstance instance, Map<String, String> context) throws QAuthenticationException
   {
      mapper(instance);
      QSession session = authenticate(instance, context);
      boolean newLogin = context != null && context.containsKey("code")
         && (context.containsKey("state") || (context.containsKey("redirectUri") && context.containsKey("codeVerifier")));
      return (check(instance, session, newLogin || bearer(session)));
   }

   /***************************************************************************
    ** Core also verifies the expected service username before this boundary.
    ***************************************************************************/
   @Override
   public QSession createServiceSession(QInstance instance, String token, String expectedUsername) throws QAuthenticationException
   {
      mapper(instance);
      return (check(instance, super.createServiceSession(instance, token, expectedUsername), true));
   }

   /***************************************************************************
    ** Already-created session objects must not bypass binding or grant refresh.
    ***************************************************************************/
   @Override
   public boolean isSessionValid(QInstance instance, QSession session)
   {
      if(session instanceof QSystemUserSession)
      {
         return (true);
      }
      try
      {
         mapper(instance);
         if(session == null || !authenticatedSessionValid(instance, session))
         {
            throw (new QAuthenticationException("Session is not valid."));
         }
         check(instance, session, false);
         return (true);
      }
      catch(Exception failure)
      {
         if(session != null)
         {
            session.setPermissions(new TreeSet<>());
         }
         return (false);
      }
   }

   /***************************************************************************
    ** Durable revocation precedes core cleanup, which still runs on failure.
    ***************************************************************************/
   @Override
   public void logout(QInstance instance, String sessionUuid)
   {
      var previous = QContext.capture();
      try
      {
         var mapper = mapper(instance);
         QContext.init(instance, new QSystemUserSession(instance));
         bindings(mapper).revoke(sessionUuid);
      }
      catch(Exception failure)
      {
         throw (new IllegalStateException("Durable session revocation could not be completed."));
      }
      finally
      {
         QContext.init(previous);
         super.logout(instance, sessionUuid);
      }
   }

   /***************************************************************************
    ** Never use request claims or mutable email to establish source identity.
    ***************************************************************************/
   private QSession check(QInstance instance, QSession session, boolean allowBind) throws QAuthenticationException
   {
      var previous = QContext.capture();
      try
      {
         var mapper = mapper(instance);
         JSONObject claims = new JSONObject(session.getValue(AuthentikRefreshingPermissionMapper.CLAIMS));
         var identity = AuthentikSessionIdentity.fromVerifiedClaims(claims).orElseThrow();
         if(!Objects.equals(mapper.getApiBackendName(), session.getValue(AuthentikRefreshingPermissionMapper.BACKEND)))
         {
            throw (new QAuthenticationException("Session backend changed."));
         }
         String reference = session.getUser().getIdReference();
         QContext.init(instance, new QSystemUserSession(instance));
         var store = bindings(mapper);
         AuthentikSessionBindings.Binding binding;
         Instant now = Instant.now();
         long lifetime = ((OAuth2AuthenticationMetaData) instance.getAuthentication()).getMaxSessionLifetimeSeconds();
         Instant deadline = now.plusSeconds(lifetime);
         if(bearer(session))
         {
            // A deterministic deadline survives row/tombstone cleanup. Check it
            // on resumes too, so an old binding cannot bypass a shortened limit.
            Object rawIssued = claims.opt("iat");
            if(!(rawIssued instanceof Number issued))
            {
               throw (new QAuthenticationException("Bearer credentials require a signed issue time."));
            }
            long issuedSeconds = new java.math.BigDecimal(issued.toString()).longValueExact();
            if(issuedSeconds <= 0 || issuedSeconds > now.getEpochSecond())
            {
               throw (new QAuthenticationException("Bearer issue time is invalid."));
            }
            deadline = Instant.ofEpochSecond(issuedSeconds).plusSeconds(lifetime);
            Instant tokenExpiry = Instant.ofEpochSecond(Long.parseLong(session.getValue(BEARER_SESSION_EXPIRES_AT_VALUE_KEY)));
            if(tokenExpiry.isBefore(deadline))
            {
               deadline = tokenExpiry;
            }
            if(!deadline.isAfter(now))
            {
               throw (new QAuthenticationException("Bearer session lifetime has expired."));
            }
         }
         if(allowBind)
         {
            binding = store.bind(session.getUuid(), new AuthentikSessionBindings.Binding(identity.pk(), identity.uuid(), reference, deadline));
         }
         else
         {
            binding = store.find(session.getUuid());
         }
         if(binding == null || !Objects.equals(binding.userPk(), identity.pk()) || !binding.userUuid().equals(identity.uuid())
            || !Objects.equals(binding.userReference(), reference))
         {
            throw (new QAuthenticationException("Session identity binding is unavailable."));
         }
         mapper.refresh(instance, session);
         return (session);
      }
      catch(Exception failure)
      {
         if(session != null)
         {
            session.setPermissions(new TreeSet<>());
         }
         throw (new QAuthenticationException("Current Authentik session access could not be established."));
      }
      finally
      {
         QContext.init(previous);
      }
   }

   /***************************************************************************
    ** Caching must be off: core bearer cache hits bypass the customizer.
    ***************************************************************************/
   protected AuthentikRefreshingPermissionMapper mapper(QInstance instance) throws QAuthenticationException
   {
      if(!(instance.getAuthentication() instanceof OAuth2AuthenticationMetaData metadata)
         || Boolean.TRUE.equals(metadata.getSessionStoreEnabled()) || metadata.getMaxSessionLifetimeSeconds() == null
         || metadata.getMaxSessionLifetimeSeconds() <= 0
         || metadata.getMaxSessionLifetimeSeconds() > AuthentikSessionBindings.REVOCATION_RETENTION.toSeconds() || metadata.getCustomizer() == null)
      {
         throw (new QAuthenticationException("Refreshing OAuth requires a customizer, disabled session cache and a session lifetime of at most thirty days."));
      }
      try
      {
         return (QCodeLoader.getAdHoc(AuthentikRefreshingPermissionMapper.class, metadata.getCustomizer()));
      }
      catch(Exception failure)
      {
         throw (new QAuthenticationException("Refreshing OAuth requires AuthentikRefreshingPermissionMapper."));
      }
   }

   /***************************************************************************
    ** Host-backed durable store; no additional pool or remote API writes.
    ***************************************************************************/
   protected AuthentikSessionBindings bindings(AuthentikRefreshingPermissionMapper mapper)
   {
      return (new AuthentikSessionBindings(mapper.runtime().getConfig()));
   }

   /***************************************************************************
    ** Core owns token verification, authorization-code exchange and refresh.
    ***************************************************************************/
   protected QSession authenticate(QInstance instance, Map<String, String> context) throws QAuthenticationException
   {
      return (super.createSession(instance, context));
   }

   /***************************************************************************
    ** Core validates expiry and stored OAuth credentials before current access.
    ***************************************************************************/
   protected boolean authenticatedSessionValid(QInstance instance, QSession session)
   {
      return (super.isSessionValid(instance, session));
   }

   /***************************************************************************
    ** Only core's internal marker distinguishes verified stateless credentials.
    ***************************************************************************/
   private static boolean bearer(QSession session)
   {
      return (session != null && "true".equals(session.getValue(BEARER_SESSION_VALUE_KEY)));
   }
}
