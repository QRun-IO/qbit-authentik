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
package com.kingsrook.qbits.authentik.sync;

import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.module.rdbms.jdbc.ConnectionManager;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData;
import org.json.JSONArray;

/*******************************************************************************
 ** Uncached authorization projection for session reevaluation and fallback.
 ** Identity must already be bound to an immutable Authentik pk AND uuid by the
 ** authentication adapter. An email, username or caller-supplied token claim
 ** is not an identity binding. No caller may merge stale claims after denial.
 ******************************************************************************/
public final class AuthentikMirrorAccess
{
   private final AuthentikQBitConfig config;
   private final AuthentikSyncLease.Connections connections;
   private final Duration maximumAge;
   private final String userTable;
   private final String stateTable;

   /***************************************************************************
    ** READY supplies current grants; DENIED is an authoritative inactive or
    ** absent identity; UNAVAILABLE has no usable completed/fresh projection.
    ***************************************************************************/
   public enum Status { READY, DENIED, UNAVAILABLE }

   /***************************************************************************
    ** Immutable sets prevent cached session mutations from altering this read.
    ** This includes only directory grants, not host/static/bootstrap grants.
    ***************************************************************************/
   public record Access(Set<String> groups, Set<String> permissions, Instant refreshedAt, String email)
   {
      /***********************************************************************
       ** Defensive copies at the authorization boundary.
       ***********************************************************************/
      public Access
      {
         groups = Set.copyOf(groups);
         permissions = Set.copyOf(permissions);
      }
   }

   /***************************************************************************
    ** No grants accompany an unavailable or denied read.
    ***************************************************************************/
   public record Result(Status status, Access access)
   {
   }

   /***************************************************************************
    ** Reuse the configured host database and its existing connection provider.
    ***************************************************************************/
   public AuthentikMirrorAccess(AuthentikQBitConfig config, Duration maximumAge)
   {
      this(config, () ->
      {
         if(!(QContext.getQInstance().getBackend(config.getLocalBackendName()) instanceof RDBMSBackendMetaData backend))
         {
            throw (new SQLException("Session mirror requires the configured host RDBMS backend."));
         }
         return (ConnectionManager.getConnection(backend));
      }, maximumAge);
   }

   /***************************************************************************
    ** Injectable host connection seam, shared by H2/PostgreSQL acceptance tests.
    ** Maximum staleness is explicit and cannot exceed fifteen minutes, even
    ** when reconciliation stalls or a worker retains its directory lease.
    ***************************************************************************/
   AuthentikMirrorAccess(AuthentikQBitConfig config, AuthentikSyncLease.Connections connections, Duration maximumAge)
   {
      this.config = Objects.requireNonNull(config);
      this.connections = Objects.requireNonNull(connections);
      if(maximumAge == null || maximumAge.isNegative() || maximumAge.isZero() || maximumAge.compareTo(Duration.ofMinutes(15)) > 0)
      {
         throw (new IllegalArgumentException("Mirror access freshness must be positive and at most fifteen minutes."));
      }
      this.maximumAge = maximumAge;
      userTable = config.applyTablePrefix(AuthentikSyncTables.USER);
      stateTable = config.applyTablePrefix(AuthentikSyncTables.STATE);
      if(config.getLocalBackendName() == null || !userTable.matches("[A-Za-z][A-Za-z0-9_]*") || !stateTable.matches("[A-Za-z][A-Za-z0-9_]*"))
      {
         throw (new IllegalArgumentException("A valid local mirror backend and table prefix are required."));
      }
   }

   /***************************************************************************
    ** Read checkpoint and identity in ONE SQL statement so concurrent commit
    ** cannot pair old grants with a new checkpoint. Missing/inactive identities
    ** never fall back to old tokens. SQL failures propagate to the adapter.
    ***************************************************************************/
   public Result read(Integer pk, String uuid) throws SQLException, QPermissionDeniedException
   {
      if(!(QContext.getQSession() instanceof QSystemUserSession))
      {
         throw (new QPermissionDeniedException("Session mirror reads require the internal authentication context."));
      }
      if(pk == null || pk < 1 || uuid == null || uuid.isBlank())
      {
         return (new Result(Status.DENIED, null));
      }
      try(var connection = connections.open())
      {
         Instant now = AuthentikSyncLease.now(connection);
         String query = "SELECT s.watermark, s.last_full_sync, s.scope_fingerprint, u.pk, u.is_active, u.group_names, u.effective_permissions, u.refreshed_at, u.email"
            + " FROM " + stateTable + " s LEFT JOIN " + userTable + " u ON u.pk = ? AND u.uuid = ? WHERE s.sync_key = 'directory'";
         try(var statement = connection.prepareStatement(query))
         {
            statement.setInt(1, pk);
            statement.setString(2, uuid);
            try(var rows = statement.executeQuery())
            {
               if(!rows.next() || rows.getTimestamp(1) == null || rows.getTimestamp(2) == null
                  || !AuthentikSyncLease.scopeFingerprint(config).equals(rows.getString(3)))
               {
                  return (new Result(Status.UNAVAILABLE, null));
               }
               Instant watermark = rows.getTimestamp(1).toInstant();
               if(watermark.isAfter(now) || watermark.isBefore(now.minus(maximumAge)) || rows.getTimestamp(2).toInstant().isAfter(watermark))
               {
                  return (new Result(Status.UNAVAILABLE, null));
               }
               if(rows.getObject(4) == null || !Boolean.TRUE.equals(rows.getObject(5)))
               {
                  return (new Result(Status.DENIED, null));
               }
               // QQQ DATE_TIME columns store UTC LocalDateTime, while the
               // JDBC-owned checkpoint is a TIMESTAMP WITH TIME ZONE instant.
               var refreshed = rows.getObject(8, java.time.LocalDateTime.class);
               if(refreshed == null || !watermark.equals(refreshed.toInstant(java.time.ZoneOffset.UTC)))
               {
                  return (new Result(Status.UNAVAILABLE, null));
               }
               try
               {
                  Access access = new Access(strings(rows.getString(6)), strings(rows.getString(7)), watermark, rows.getString(9));
                  return (rows.next() ? new Result(Status.UNAVAILABLE, null) : new Result(Status.READY, access));
               }
               catch(IllegalArgumentException | org.json.JSONException malformed)
               {
                  return (new Result(Status.UNAVAILABLE, null));
               }
            }
         }
      }
   }

   /***************************************************************************
    ** Strict bounded JSON, never coercing objects/numbers into permission IDs.
    ***************************************************************************/
   private static Set<String> strings(String json)
   {
      if(json == null || json.length() > 2_000_000)
      {
         throw (new IllegalArgumentException("Invalid mirror authorization data."));
      }
      JSONArray array = new JSONArray(json);
      if(array.length() > 20_000)
      {
         throw (new IllegalArgumentException("Mirror authorization data exceeds the supported bound."));
      }
      Set<String> values = new TreeSet<>();
      for(Object value : array)
      {
         if(!(value instanceof String text) || text.isBlank() || text.length() > 1024)
         {
            throw (new IllegalArgumentException("Invalid mirror authorization entry."));
         }
         values.add(text);
      }
      return (values);
   }
}
