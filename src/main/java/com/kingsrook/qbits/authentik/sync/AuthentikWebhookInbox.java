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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;

/*******************************************************************************
 ** Durable at-least-once work queue on the HOST database, never Authentik's DB.
 ** Unique event keys arbitrate concurrent delivery. Conditional updates fence
 ** expired workers; database time avoids disagreement between host clocks.
 ** SQL uses standard JDBC so no driver or pool is owned by this component.
 *******************************************************************************/
public final class AuthentikWebhookInbox
{
   public static final int MAX_ATTEMPTS = 5;
   public static final int MAX_BATCH = 50;
   private final AuthentikSyncLease.Connections connections;
   private final String table;
   private final Duration lease;

   /*******************************************************************************
    ** Local database work only. Perform network reads before entering this
    ** callback; the inbox row remains locked until the transaction completes.
    *******************************************************************************/
   @FunctionalInterface
   public interface LocalWork
   {
      /***************************************************************************
       ** Apply local mirror/session invalidation changes on this connection.
       ** Do not commit, roll back, close, or change the connection's settings.
       ***************************************************************************/
      void apply(Connection connection) throws Exception;
   }

   /*******************************************************************************
    ** One leased hint. The token must accompany every state transition.
    *******************************************************************************/
   public record Claim(long id, String token, String payload, int attempt)
   {
      /***************************************************************************
       ** Avoid accidental payload/claim-token disclosure in diagnostics.
       ***************************************************************************/
      @Override
      public String toString()
      {
         return ("WebhookClaim[id=" + id + ", attempt=" + attempt + "]");
      }
   }

   /*******************************************************************************
    ** Use the host's local-backend DataSource and a bounded processing lease.
    ** The integration adapter must verify localBackendName before constructing.
    *******************************************************************************/
   public AuthentikWebhookInbox(DataSource dataSource, AuthentikQBitConfig config, Duration lease)
   {
      this(Objects.requireNonNull(dataSource)::getConnection, config, lease);
   }

   /*******************************************************************************
    ** Use the host connection provider under a short internal system context.
    *******************************************************************************/
   public AuthentikWebhookInbox(AuthentikQBitConfig config, Duration lease)
   {
      this(() ->
      {
         if(!(com.kingsrook.qqq.backend.core.context.QContext.getQSession() instanceof com.kingsrook.qqq.backend.core.model.session.QSystemUserSession)
            || !(com.kingsrook.qqq.backend.core.context.QContext.getQInstance().getBackend(config.getLocalBackendName())
               instanceof com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData backend))
         {
            throw (new SQLException("Webhook inbox requires an internal host RDBMS context."));
         }
         return (com.kingsrook.qqq.backend.module.rdbms.jdbc.ConnectionManager.getConnection(backend));
      }, config, lease);
   }

   /*******************************************************************************
    ** Shared validation for host-managed connections and contract data sources.
    *******************************************************************************/
   private AuthentikWebhookInbox(AuthentikSyncLease.Connections connections, AuthentikQBitConfig config, Duration lease)
   {
      this.connections = connections;
      this.table = config.applyTablePrefix(AuthentikSyncTables.INBOX);
      if(!table.matches("[A-Za-z][A-Za-z0-9_]*") || config.getLocalBackendName() == null)
      {
         throw (new IllegalArgumentException("A valid local sync backend and table name are required"));
      }
      if(lease == null || lease.compareTo(Duration.ofSeconds(1)) < 0 || lease.compareTo(Duration.ofMinutes(15)) > 0)
      {
         throw (new IllegalArgumentException("Webhook lease must be between one second and fifteen minutes"));
      }
      this.lease = lease;
   }

   /*******************************************************************************
    ** Commit before acknowledging receipt. Duplicate delivery never replaces
    ** the original payload or resets its processing/retention timestamps.
    *******************************************************************************/
   public boolean accept(AuthentikWebhookEnvelope event) throws SQLException
   {
      AuthentikWebhookEnvelope validated = AuthentikWebhookEnvelope.fromStorage(event.storageJson());
      String payload = validated.storageJson();
      try(Connection connection = connections.open())
      {
         connection.setAutoCommit(false);
         try(var insert = connection.prepareStatement("INSERT INTO " + table
            + " (event_pk,payload_json,status,attempts,received_at) VALUES (?,?,'PENDING',0,CURRENT_TIMESTAMP)"))
         {
            insert.setString(1, validated.eventPk());
            insert.setString(2, payload);
            insert.executeUpdate();
            connection.commit();
            return (true);
         }
         catch(SQLException failure)
         {
            connection.rollback();
            // PostgreSQL/H2 unique violation only; other storage failures must
            // propagate so the transport retries instead of acknowledging loss.
            if("23505".equals(failure.getSQLState()))
            {
               try(var query = connection.prepareStatement("SELECT id FROM " + table + " WHERE event_pk=?"))
               {
                  query.setString(1, validated.eventPk());
                  try(var result = query.executeQuery())
                  {
                     if(result.next())
                     {
                        connection.rollback();
                        return (false);
                     }
                  }
               }
            }
            throw (failure);
         }
      }
   }

   /*******************************************************************************
    ** Claim a bounded batch. The predicate is repeated on UPDATE so competing
    ** processors cannot both claim the same version. A crashed final attempt
    ** becomes FAILED rather than remaining PROCESSING forever.
    *******************************************************************************/
   public List<Claim> claim(int limit) throws SQLException
   {
      if(limit < 1 || limit > MAX_BATCH)
      {
         throw (new IllegalArgumentException("Webhook batch must contain 1 to 50 events"));
      }
      try(Connection connection = connections.open())
      {
         connection.setAutoCommit(false);
         try
         {
            Instant now = now(connection);
            try(var expired = connection.prepareStatement("UPDATE " + table
               + " SET status='FAILED',processed_at=?,lease_owner=NULL,lease_until=NULL,error_code='LEASE_EXPIRED'"
               + " WHERE status='PROCESSING' AND lease_until<=? AND attempts>=?"))
            {
               expired.setTimestamp(1, Timestamp.from(now));
               expired.setTimestamp(2, Timestamp.from(now));
               expired.setInt(3, MAX_ATTEMPTS);
               expired.executeUpdate();
            }
            String eligible = "attempts<5 AND ((status='PENDING' AND (next_attempt_at IS NULL OR next_attempt_at<=?))"
               + " OR (status='PROCESSING' AND lease_until<=?))";
            List<Claim> candidates = new ArrayList<>();
            try(var query = connection.prepareStatement("SELECT id,payload_json,attempts FROM " + table + " WHERE " + eligible + " ORDER BY received_at,id"))
            {
               query.setTimestamp(1, Timestamp.from(now));
               query.setTimestamp(2, Timestamp.from(now));
               query.setMaxRows(limit);
               try(var result = query.executeQuery())
               {
                  while(result.next())
                  {
                     candidates.add(new Claim(result.getLong(1), UUID.randomUUID().toString(), result.getString(2), result.getInt(3) + 1));
                  }
               }
            }
            List<Claim> claimed = new ArrayList<>();
            for(Claim candidate : candidates)
            {
               try(var update = connection.prepareStatement("UPDATE " + table
                  + " SET status='PROCESSING',attempts=attempts+1,lease_owner=?,lease_until=?,error_code=NULL"
                  + " WHERE id=? AND " + eligible))
               {
                  update.setString(1, candidate.token());
                  update.setTimestamp(2, Timestamp.from(now.plus(lease)));
                  update.setLong(3, candidate.id());
                  update.setTimestamp(4, Timestamp.from(now));
                  update.setTimestamp(5, Timestamp.from(now));
                  if(update.executeUpdate() == 1)
                  {
                     claimed.add(candidate);
                  }
               }
            }
            connection.commit();
            return (List.copyOf(claimed));
         }
         catch(SQLException | RuntimeException failure)
         {
            connection.rollback();
            throw (failure);
         }
      }
   }

   /*******************************************************************************
    ** Renew before doing external work. A stale worker cannot resurrect a claim.
    *******************************************************************************/
   public boolean renew(Claim claim) throws SQLException
   {
      return (transition(claim, "RENEW"));
   }

   /*******************************************************************************
    ** Fence mirror writes in the same transaction as their ownership check.
    ** A worker whose lease was reclaimed cannot publish an older snapshot.
    ** No network work is performed while holding this row lock. Completion
    ** remains separate, so a crash after commit safely repeats the live read.
    *******************************************************************************/
   public boolean withClaim(Claim claim, LocalWork work) throws Exception
   {
      Objects.requireNonNull(work);
      try(Connection connection = connections.open())
      {
         connection.setAutoCommit(false);
         try
         {
            if(!lockClaim(connection, claim))
            {
               connection.rollback();
               return (false);
            }
            work.apply(connection);
            connection.commit();
            return (true);
         }
         catch(Exception failure)
         {
            connection.rollback();
            throw (failure);
         }
      }
   }

   /*******************************************************************************
    ** Fence publication inside a caller-owned host transaction. The caller must
    ** use this inbox's host database, commit/rollback itself, and hold the row
    ** lock until all local work is complete. This permits QQQ's transaction
    ** lifecycle to retain its after-commit callbacks rather than bypassing it.
    *******************************************************************************/
   public boolean lockClaim(Connection connection, Claim claim) throws SQLException
   {
      if(connection.getAutoCommit())
      {
         throw (new SQLException("Claim publication requires a transaction."));
      }
      try(var query = connection.prepareStatement("SELECT lease_owner,lease_until,status FROM " + table + " WHERE id=? FOR UPDATE"))
      {
         query.setLong(1, claim.id());
         try(var result = query.executeQuery())
         {
            return (result.next() && claim.token().equals(result.getString(1)) && "PROCESSING".equals(result.getString(3))
               && result.getTimestamp(2) != null && result.getTimestamp(2).toInstant().isAfter(now(connection)));
         }
      }
   }

   /*******************************************************************************
    ** Mark success only after mirror/session work succeeds. Replays are safe
    ** because the handler must re-read live state rather than apply event data.
    *******************************************************************************/
   public boolean complete(Claim claim) throws SQLException
   {
      return (transition(claim, "SUCCEEDED"));
   }

   /*******************************************************************************
    ** Retry with bounded exponential delay; persist no exception text or body.
    *******************************************************************************/
   public boolean fail(Claim claim) throws SQLException
   {
      return (transition(claim, "FAILED"));
   }

   /*******************************************************************************
    ** Publication contention is not an upstream failure. Return current owned
    ** work to the next polling interval without consuming its failure budget.
    *******************************************************************************/
   public boolean defer(Claim claim) throws SQLException
   {
      return (transition(claim, "DEFER"));
   }

   /*******************************************************************************
    ** Compare-and-set every terminal/retry transition against a live lease.
    *******************************************************************************/
   private boolean transition(Claim claim, String outcome) throws SQLException
   {
      try(Connection connection = connections.open())
      {
         connection.setAutoCommit(false);
         try
         {
            Instant now = now(connection);
            boolean renew = "RENEW".equals(outcome);
            boolean defer = "DEFER".equals(outcome);
            boolean retry = defer || ("FAILED".equals(outcome) && claim.attempt() < MAX_ATTEMPTS);
            String sql = renew ? " SET lease_until=?" : " SET status=?,processed_at=?,next_attempt_at=?,lease_owner=NULL,lease_until=NULL,error_code=?"
               + (defer ? ",attempts=attempts-1" : "");
            try(var update = connection.prepareStatement("UPDATE " + table + sql + " WHERE id=? AND lease_owner=? AND status='PROCESSING' AND lease_until>?"))
            {
               int i = 1;
               if(renew)
               {
                  update.setTimestamp(i++, Timestamp.from(now.plus(lease)));
               }
               else
               {
                  update.setString(i++, retry ? "PENDING" : outcome);
                  update.setTimestamp(i++, retry ? null : Timestamp.from(now));
                  update.setTimestamp(i++, retry ? Timestamp.from(now.plusSeconds(defer ? 2 : 1L << claim.attempt())) : null);
                  update.setString(i++, "FAILED".equals(outcome) ? "PROCESSING_FAILED" : null);
               }
               update.setLong(i++, claim.id());
               update.setString(i++, claim.token());
               update.setTimestamp(i, Timestamp.from(now));
               boolean changed = update.executeUpdate() == 1;
               connection.commit();
               return (changed);
            }
         }
         catch(SQLException | RuntimeException failure)
         {
            connection.rollback();
            throw (failure);
         }
      }
   }

   /*******************************************************************************
    ** Retain unfinished work. Completed/failed hints expire thirty days after
    ** processing, preserving a full deduplication window after delayed work.
    *******************************************************************************/
   public int purge() throws SQLException
   {
      try(Connection connection = connections.open())
      {
         connection.setAutoCommit(false);
         try(var delete = connection.prepareStatement("DELETE FROM " + table + " WHERE status IN ('SUCCEEDED','FAILED') AND processed_at<?"))
         {
            delete.setTimestamp(1, Timestamp.from(now(connection).minus(Duration.ofDays(30))));
            int count = delete.executeUpdate();
            connection.commit();
            return (count);
         }
         catch(SQLException | RuntimeException failure)
         {
            connection.rollback();
            throw (failure);
         }
      }
   }

   /*******************************************************************************
    ** Authoritative timestamp from the storage database, in the transaction.
    *******************************************************************************/
   private static Instant now(Connection connection) throws SQLException
   {
      return (AuthentikSyncLease.now(connection));
   }
}
