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
package com.kingsrook.qbits.authentik.sync;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.module.rdbms.jdbc.ConnectionManager;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData;

/*******************************************************************************
 ** Durable, write-once identity for an authenticated QQQ cookie session.
 ** Only the authentication adapter may bind a NEW verified login. Resumption
 ** must use find(), never recreate a missing binding from an old token/email.
 ** The UUID's SHA-256 digest is stored; no reusable session credential is kept.
 ******************************************************************************/
public final class AuthentikSessionBindings
{
   public static final Duration REVOCATION_RETENTION = Duration.ofDays(30);
   private final AuthentikSyncLease.Connections connections;
   private final String table;
   private final AuthentikQBitConfig config;

   /***************************************************************************
    ** Stable source identity, original core user reference and absolute login
    ** lifetime. Token refresh does not extend or reassign this binding.
    ***************************************************************************/
   public record Binding(Integer userPk, String userUuid, String userReference, Instant expiresAt)
   {
      /***********************************************************************
       ** Avoid implicit identity disclosure in exceptions and diagnostics.
       ***********************************************************************/
      @Override
      public String toString()
      {
         return ("AuthentikSessionBinding");
      }
   }

   /***************************************************************************
    ** Borrow from the host's configured provider, without a second pool.
    ***************************************************************************/
   public AuthentikSessionBindings(AuthentikQBitConfig config)
   {
      this(config, () ->
      {
         if(!(QContext.getQInstance().getBackend(config.getLocalBackendName()) instanceof RDBMSBackendMetaData backend))
         {
            throw (new SQLException("Session bindings require the configured host RDBMS backend."));
         }
         return (ConnectionManager.getConnection(backend));
      });
   }

   /***************************************************************************
    ** Isolated host database seam for shared H2/PostgreSQL acceptance tests.
    ***************************************************************************/
   AuthentikSessionBindings(AuthentikQBitConfig config, AuthentikSyncLease.Connections connections)
   {
      this.config = Objects.requireNonNull(config);
      this.connections = Objects.requireNonNull(connections);
      table = config.applyTablePrefix(AuthentikSyncTables.SESSION_BINDING);
      if(config.getLocalBackendName() == null || !table.matches("[A-Za-z][A-Za-z0-9_]*") || config.getApiRoot() == null)
      {
         throw (new IllegalArgumentException("A local backend, valid table prefix and Authentik API root are required."));
      }
   }

   /***************************************************************************
    ** First writer fixes identity and deadline. A duplicate same-identity login
    ** returns the original deadline; competing identities, expired bindings
    ** and revoked bindings are rejected. Unique-key enforcement handles races.
    ***************************************************************************/
   public Binding bind(String sessionUuid, Binding binding) throws SQLException, QPermissionDeniedException
   {
      guard();
      String key = sessionHash(sessionUuid);
      if(binding == null || binding.userPk() == null || binding.userPk() < 1 || binding.userUuid() == null
         || binding.userUuid().isBlank() || binding.userUuid().length() > 64 || binding.userReference() == null
         || binding.userReference().isBlank() || binding.userReference().length() > 1024 || binding.expiresAt() == null)
      {
         throw (new IllegalArgumentException("A verified immutable identity and finite session lifetime are required."));
      }
      try(var connection = connections.open())
      {
         connection.setAutoCommit(false);
         if(!binding.expiresAt().isAfter(AuthentikSyncLease.now(connection)))
         {
            throw (new IllegalArgumentException("Session binding has already expired."));
         }
         try(var insert = connection.prepareStatement("INSERT INTO " + table
            + " (session_hash,issuer_fingerprint,user_pk,user_uuid,user_reference,expires_at,revoked) VALUES (?,?,?,?,?,?,FALSE)"))
         {
            insert.setString(1, key);
            insert.setString(2, digest(config.getApiRoot()));
            insert.setInt(3, binding.userPk());
            insert.setString(4, binding.userUuid());
            insert.setString(5, binding.userReference());
            insert.setTimestamp(6, Timestamp.from(binding.expiresAt()));
            insert.executeUpdate();
            connection.commit();
         }
         catch(SQLException failure)
         {
            connection.rollback();
            if(!"23505".equals(failure.getSQLState()))
            {
               throw (failure);
            }
         }
         Binding existing = find(connection, key);
         if(existing == null || !Objects.equals(existing.userPk(), binding.userPk()) || !existing.userUuid().equals(binding.userUuid())
            || !existing.userReference().equals(binding.userReference()))
         {
            throw (new QPermissionDeniedException("Session identity binding cannot be reassigned or revived."));
         }
         return (existing);
      }
   }

   /***************************************************************************
    ** Uncached lookup shared by all application nodes. Missing/expired/revoked
    ** bindings never authorize recreating identity from mutable user references.
    ***************************************************************************/
   public Binding find(String sessionUuid) throws SQLException, QPermissionDeniedException
   {
      guard();
      String key = sessionHash(sessionUuid);
      try(var connection = connections.open())
      {
         return (find(connection, key));
      }
   }

   /***************************************************************************
    ** Retain a tombstone so a delayed duplicate login cannot undo revocation.
    ***************************************************************************/
   public void revoke(String sessionUuid) throws SQLException, QPermissionDeniedException
   {
      guard();
      String key = sessionHash(sessionUuid);
      try(var connection = connections.open())
      {
         connection.setAutoCommit(false);
         // A logout arriving before a delayed login must still leave a tombstone.
         try(var insert = connection.prepareStatement("INSERT INTO " + table
            + " (session_hash,issuer_fingerprint,expires_at,revoked) VALUES (?,?,?,TRUE)"))
         {
            insert.setString(1, key);
            insert.setString(2, digest(config.getApiRoot()));
            insert.setTimestamp(3, Timestamp.from(AuthentikSyncLease.now(connection)));
            insert.executeUpdate();
            connection.commit();
         }
         catch(SQLException failure)
         {
            connection.rollback();
            if(!"23505".equals(failure.getSQLState()))
            {
               throw (failure);
            }
         }
         try(var update = connection.prepareStatement("UPDATE " + table + " SET revoked=TRUE WHERE session_hash=?"))
         {
            update.setString(1, key);
            update.executeUpdate();
            connection.commit();
         }
      }
   }

   /***************************************************************************
    ** Bounded retention by lifetime: preserve tombstones for thirty days after
    ** expiry. The adapter must deny resumed sessions whose bindings are absent.
    ***************************************************************************/
   public int purgeExpired() throws SQLException, QPermissionDeniedException
   {
      guard();
      try(var connection = connections.open(); var delete = connection.prepareStatement("DELETE FROM " + table + " WHERE expires_at < ?"))
      {
         connection.setAutoCommit(true);
         delete.setTimestamp(1, Timestamp.from(AuthentikSyncLease.now(connection).minus(REVOCATION_RETENTION)));
         return (delete.executeUpdate());
      }
   }

   /***************************************************************************
    ** Database-clock expiry and issuer validation, with no process-local cache.
    ***************************************************************************/
   private Binding find(Connection connection, String key) throws SQLException
   {
      Instant now = AuthentikSyncLease.now(connection);
      try(var query = connection.prepareStatement("SELECT user_pk,user_uuid,user_reference,expires_at FROM " + table
         + " WHERE session_hash=? AND issuer_fingerprint=? AND revoked=FALSE AND expires_at>?"))
      {
         query.setString(1, key);
         query.setString(2, digest(config.getApiRoot()));
         query.setTimestamp(3, Timestamp.from(now));
         try(var rows = query.executeQuery())
         {
            return (rows.next() ? new Binding(rows.getInt(1), rows.getString(2), rows.getString(3), rows.getTimestamp(4).toInstant()) : null);
         }
      }
   }

   /***************************************************************************
    ** Authentication internals only; normal admin permissions are insufficient.
    ***************************************************************************/
   private static void guard() throws QPermissionDeniedException
   {
      if(!(QContext.getQSession() instanceof QSystemUserSession))
      {
         throw (new QPermissionDeniedException("Session identity storage requires the internal authentication context."));
      }
   }

   /***************************************************************************
    ** Canonical UUIDs prevent different hashes for the same cookie identifier.
    ***************************************************************************/
   private static String sessionHash(String value)
   {
      try
      {
         String canonical = UUID.fromString(value).toString();
         if(!canonical.equalsIgnoreCase(value))
         {
            throw (new IllegalArgumentException());
         }
         return (digest(canonical));
      }
      catch(RuntimeException invalid)
      {
         throw (new IllegalArgumentException("A canonical QQQ session UUID is required."));
      }
   }

   /***************************************************************************
    ** Store only a digest of the cookie identifier and configured source root.
    ***************************************************************************/
   private static String digest(String value)
   {
      try
      {
         return (HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))));
      }
      catch(NoSuchAlgorithmException impossible)
      {
         throw (new IllegalStateException("SHA-256 is unavailable", impossible));
      }
   }
}
