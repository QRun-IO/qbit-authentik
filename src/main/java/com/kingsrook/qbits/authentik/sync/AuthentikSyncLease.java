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

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;

/*******************************************************************************
 ** One host-database lease serializes all directory publishers, including
 ** different webhook hints and scheduled reconciliation. Remote reads happen
 ** without a database transaction; publication locks and fences the lease row.
 *******************************************************************************/
public final class AuthentikSyncLease
{
   private final Connections connections;
   private final String table;
   private final Duration duration;
   private final AuthentikQBitConfig config;

   /*******************************************************************************
    ** Borrow from the host connection provider; no additional pool or secrets.
    *******************************************************************************/
   @FunctionalInterface
   public interface Connections
   {
      /***************************************************************************
       ** The caller owns and closes this borrowed connection.
       ***************************************************************************/
      Connection open() throws SQLException;
   }

   /*******************************************************************************
    ** Database time captured before remote reads is the next safe watermark.
    *******************************************************************************/
   public record Claim(String owner, Instant startedAt, Instant watermark, String scopeFingerprint, boolean sameScope)
   {
      /***************************************************************************
       ** Do not expose ownership tokens in diagnostics.
       ***************************************************************************/
      @Override
      public String toString()
      {
         return ("DirectorySyncClaim[startedAt=" + startedAt + "]");
      }
   }

   /*******************************************************************************
    ** The local-backend adapter is responsible for selecting the host database.
    *******************************************************************************/
   public AuthentikSyncLease(Connections connections, AuthentikQBitConfig config, Duration duration)
   {
      this.connections = Objects.requireNonNull(connections);
      this.config = Objects.requireNonNull(config);
      table = config.applyTablePrefix(AuthentikSyncTables.STATE);
      if(config.getLocalBackendName() == null || !table.matches("[A-Za-z][A-Za-z0-9_]*") || duration == null
         || duration.compareTo(Duration.ofSeconds(1)) < 0 || duration.compareTo(Duration.ofMinutes(15)) > 0)
      {
         throw (new IllegalArgumentException("A local sync backend and lease of one second to fifteen minutes are required."));
      }
      this.duration = duration;
   }

   /*******************************************************************************
    ** Initialize once using the unique key, then claim under a short row lock.
    ** A contender returns null without reading or publishing remote state.
    *******************************************************************************/
   public Claim acquire() throws SQLException
   {
      try(var connection = connections.open())
      {
         connection.setAutoCommit(false);
         try(var insert = connection.prepareStatement("INSERT INTO " + table + " (sync_key) VALUES ('directory')"))
         {
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
         try
         {
            Instant watermark;
            String fingerprint = scopeFingerprint(config);
            boolean sameScope;
            try(var query = connection.prepareStatement("SELECT lease_until,watermark,scope_fingerprint FROM " + table + " WHERE sync_key='directory' FOR UPDATE");
               var result = query.executeQuery())
            {
               if(!result.next())
               {
                  throw (new SQLException("Missing directory synchronization state."));
               }
               Instant now = now(connection);
               if(result.getTimestamp(1) != null && result.getTimestamp(1).toInstant().isAfter(now))
               {
                  connection.rollback();
                  return (null);
               }
               watermark = result.getTimestamp(2) == null ? null : result.getTimestamp(2).toInstant();
               sameScope = fingerprint.equals(result.getString(3));
            }
            Instant started = now(connection);
            Claim claim = new Claim(UUID.randomUUID().toString(), started, watermark, fingerprint, sameScope);
            try(var update = connection.prepareStatement("UPDATE " + table + " SET lease_owner=?,lease_until=? WHERE sync_key='directory'"))
            {
               update.setString(1, claim.owner());
               update.setTimestamp(2, Timestamp.from(started.plus(duration)));
               update.executeUpdate();
            }
            connection.commit();
            return (claim);
         }
         catch(SQLException | RuntimeException failure)
         {
            connection.rollback();
            throw (failure);
         }
      }
   }

   /*******************************************************************************
    ** An expired owner cannot renew or publish, even if no one replaced it yet.
    *******************************************************************************/
   public boolean renew(Claim claim) throws SQLException
   {
      try(var connection = connections.open())
      {
         connection.setAutoCommit(false);
         try
         {
            if(!lock(connection, claim))
            {
               connection.rollback();
               return (false);
            }
            try(var update = connection.prepareStatement("UPDATE " + table + " SET lease_until=? WHERE sync_key='directory'"))
            {
               update.setTimestamp(1, Timestamp.from(now(connection).plus(duration)));
               update.executeUpdate();
            }
            connection.commit();
            return (true);
         }
         catch(SQLException | RuntimeException failure)
         {
            connection.rollback();
            throw (failure);
         }
      }
   }

   /*******************************************************************************
    ** Caller-owned transaction: keep this row locked through mirror, audit,
    ** checkpoint and session-marker changes, then commit using QQQ's lifecycle.
    *******************************************************************************/
   public boolean lock(Connection connection, Claim claim) throws SQLException
   {
      if(connection.getAutoCommit())
      {
         throw (new SQLException("Directory publication requires a transaction."));
      }
      try(var query = connection.prepareStatement("SELECT lease_owner,lease_until FROM " + table + " WHERE sync_key='directory' FOR UPDATE");
         var result = query.executeQuery())
      {
         return (result.next() && claim.owner().equals(result.getString(1)) && result.getTimestamp(2) != null
            && result.getTimestamp(2).toInstant().isAfter(now(connection)));
      }
   }

   /*******************************************************************************
    ** Advance only inside the successfully fenced publication transaction.
    ** Recheck ownership; the caller must roll back if this returns false.
    *******************************************************************************/
   public boolean complete(Connection connection, Claim claim, boolean full) throws SQLException
   {
      if(!lock(connection, claim))
      {
         return (false);
      }
      try(var update = connection.prepareStatement("UPDATE " + table + " SET watermark=?,scope_fingerprint=?,"
         + (full ? "last_full_sync=?," : "") + "lease_owner=NULL,lease_until=NULL WHERE sync_key='directory'"))
      {
         update.setTimestamp(1, Timestamp.from(claim.startedAt()));
         update.setString(2, claim.scopeFingerprint());
         if(full)
         {
            update.setTimestamp(3, Timestamp.from(claim.startedAt()));
         }
         return (update.executeUpdate() == 1);
      }
   }

   /*******************************************************************************
    ** Failed work releases only its own lease, preserving the prior checkpoint.
    *******************************************************************************/
   public void release(Claim claim) throws SQLException
   {
      try(var connection = connections.open())
      {
         connection.setAutoCommit(false);
         try(var update = connection.prepareStatement("UPDATE " + table + " SET lease_owner=NULL,lease_until=NULL WHERE sync_key='directory' AND lease_owner=?"))
         {
            update.setString(1, claim.owner());
            update.executeUpdate();
            connection.commit();
         }
         catch(SQLException failure)
         {
            connection.rollback();
            throw (failure);
         }
      }
   }

   /*******************************************************************************
    ** Targeted events do not certify unrelated profiles as newly reconciled.
    ** Release ownership atomically with publication, preserving the watermark.
    *******************************************************************************/
   public boolean completeHint(Connection connection, Claim claim) throws SQLException
   {
      if(!lock(connection, claim))
      {
         return (false);
      }
      try(var update = connection.prepareStatement("UPDATE " + table + " SET lease_owner=NULL,lease_until=NULL WHERE sync_key='directory'"))
      {
         return (update.executeUpdate() == 1);
      }
   }

   /*******************************************************************************
    ** Database clock keeps different hosts from disagreeing on ownership.
    *******************************************************************************/
   static Instant now(Connection connection) throws SQLException
   {
      String clock = "PostgreSQL".equals(connection.getMetaData().getDatabaseProductName()) ? "clock_timestamp()" : "CURRENT_TIMESTAMP";
      try(var query = connection.prepareStatement("SELECT " + clock); var result = query.executeQuery())
      {
         result.next();
         return (result.getTimestamp(1).toInstant());
      }
   }

   /*******************************************************************************
    ** Scope/configuration changes require a full baseline, including expansion
    ** to users whose source timestamps did not change. Persist only a digest.
    *******************************************************************************/
   static String scopeFingerprint(AuthentikQBitConfig config)
   {
      var groups = config.getUserScopeGroupNames() == null ? java.util.List.<String>of()
         : config.getUserScopeGroupNames().stream().sorted().distinct().toList();
      String value = new org.json.JSONArray().put(config.getApiRoot()).put(config.getUserScopePathStartsWith())
         .put(new org.json.JSONArray(groups)).put(new org.json.JSONArray(com.kingsrook.qbits.authentik.client.AuthentikTables.DEFAULT_USER_TYPES))
         .put(config.getPolicyFormat().spec()).put(config.getPolicyFormat().version()).put(config.getPolicyFormat().attribute()).toString();
      try
      {
         return (java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
            .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
      }
      catch(java.security.NoSuchAlgorithmException impossible)
      {
         throw (new IllegalStateException("SHA-256 is unavailable", impossible));
      }
   }
}
