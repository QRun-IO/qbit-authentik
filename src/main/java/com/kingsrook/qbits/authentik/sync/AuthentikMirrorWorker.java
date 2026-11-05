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

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.module.rdbms.actions.RDBMSTransaction;
import com.kingsrook.qqq.backend.module.rdbms.jdbc.ConnectionManager;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData;

/*******************************************************************************
 ** Full reconciliation on the configured host backend. The directory lease
 ** spans remote reads and local publication. No remote write is ever performed.
 ** Metadata/scheduling remain disabled until session integration is complete.
 *******************************************************************************/
public final class AuthentikMirrorWorker
{
   private final AuthentikQBitConfig config;
   private final AuthentikActionUtil client;
   private final AuthentikSyncLease.Connections connections;
   private final AuthentikSyncLease lease;

   /*******************************************************************************
    ** Mandatory publication hook for persistent session reevaluation markers.
    ** It runs in the mirror/audit/checkpoint transaction, with no remote I/O.
    *******************************************************************************/
   @FunctionalInterface
   public interface Publication
   {
      /***************************************************************************
       ** Do not commit or close the transaction. Failure rolls back everything.
       ***************************************************************************/
      void apply(AuthentikMirrorSnapshot snapshot, RDBMSTransaction transaction) throws Exception;
   }

   /*******************************************************************************
    ** Reuse QQQ's configured connection provider, including vendor/schema setup.
    *******************************************************************************/
   public AuthentikMirrorWorker(AuthentikQBitConfig config, AuthentikActionUtil client)
   {
      this.config = Objects.requireNonNull(config);
      this.client = Objects.requireNonNull(client);
      if(!(QContext.getQInstance().getBackend(config.getLocalBackendName()) instanceof RDBMSBackendMetaData backend))
      {
         throw (new IllegalArgumentException("Mirror synchronization requires the configured host RDBMS backend."));
      }
      connections = () -> ConnectionManager.getConnection(backend);
      lease = new AuthentikSyncLease(connections, config, Duration.ofMinutes(15));
   }

   /*******************************************************************************
    ** Both scheduled and webhook refreshes use the same global lease. For a
    ** webhook publication also fence its inbox claim, on the same database.
    ** False means another worker owns the refresh or this worker lost ownership.
    *******************************************************************************/
   public boolean fullRefresh(Publication publication, AuthentikWebhookInbox inbox, AuthentikWebhookInbox.Claim event) throws Exception
   {
      return (refresh(true, publication, inbox, event, false));
   }

   /*******************************************************************************
    ** Fifteen-minute reconcile. First use needs a complete baseline. Subsequent
    ** runs overlap the previous watermark by a minute to cover timestamp
    ** precision and ordinary clock skew; nightly full refresh repairs omissions.
    *******************************************************************************/
   public boolean incrementalRefresh(Publication publication) throws Exception
   {
      return (refresh(false, publication, null, null, false));
   }

   /*******************************************************************************
    ** A durable event is a hint to re-read live state, never a grant document.
    ** Existing baselines retain their freshness deadline; a missing baseline
    ** needs a full refresh before any targeted publication is safe.
    *******************************************************************************/
   public boolean applyEvent(Publication publication, AuthentikWebhookInbox inbox, AuthentikWebhookInbox.Claim event) throws Exception
   {
      Objects.requireNonNull(inbox);
      Objects.requireNonNull(event);
      return (refresh(false, publication, inbox, event, true));
   }

   /*******************************************************************************
    ** Common lease/preflight/publication boundary for full and incremental work.
    *******************************************************************************/
   private boolean refresh(boolean full, Publication publication, AuthentikWebhookInbox inbox, AuthentikWebhookInbox.Claim event, boolean eventOnly) throws Exception
   {
      if(!(QContext.getQSession() instanceof QSystemUserSession))
      {
         throw (new QPermissionDeniedException("Mirror synchronization requires the internal session."));
      }
      Objects.requireNonNull(publication);
      if((inbox == null) != (event == null))
      {
         throw (new IllegalArgumentException("An inbox and event claim must be supplied together."));
      }
      var claim = lease.acquire();
      if(claim == null)
      {
         return (false);
      }
      try
      {
         AuthentikActionUtil.SyncProgress progress = () -> renew(claim, inbox, event);
         AuthentikRuntime.forBackend(config.getApiBackendName()).invalidateCache();
         var existing = rows(AuthentikSyncTables.USER, null);
         full = full || claim.watermark() == null || !claim.sameScope() || existing.stream().anyMatch(row -> row.getValue("path") == null
            || row.getValue("sourceIsSuperuser") == null || row.getValue("sourceIsProtected") == null);
         boolean targeted = eventOnly && !full;
         List<org.json.JSONObject> users;
         Set<Integer> touched = new HashSet<>();
         if(targeted)
         {
            var hint = AuthentikWebhookEnvelope.fromStorage(event.payload());
            String pk = "user".equals(hint.modelName()) ? hint.modelPk() : null;
            if(pk == null && hint.modelName() == null && hint.username() != null)
            {
               var matching = existing.stream().filter(row -> hint.username().equals(row.getValueString("username"))).toList();
               if(matching.size() > 1)
               {
                  throw (new QException("Event username is ambiguous in the mirror."));
               }
               pk = matching.isEmpty() ? null : matching.getFirst().getValueString("pk");
            }
            org.json.JSONObject user = pk != null ? client.syncUser(pk, progress)
               : hint.modelName() == null && hint.username() != null ? client.syncUserByUsername(hint.username(), progress) : null;
            if(hint.modelName() == null && (hint.username() == null || hint.username().isBlank()))
            {
               throw (new QException("Event has no resolvable directory identity."));
            }
            if(pk != null && user == null)
            {
               String absentPk = pk;
               existing = existing.stream().filter(row -> !absentPk.equals(row.getValueString("pk"))).toList();
            }
            users = user == null ? List.of() : List.of(user);
            users.forEach(value -> touched.add(value.getInt("pk")));
         }
         else
         {
            users = client.syncUsers(full ? null : claim.watermark().minusSeconds(60), AuthentikActionUtil.MAX_SWEEP_OBJECTS, progress);
         }
         if(!lease.renew(claim))
         {
            return (false);
         }
         var groups = client.syncGroups(AuthentikActionUtil.MAX_SWEEP_OBJECTS, progress);
         if(!full)
         {
            users = incrementalUsers(existing, users, groups, progress);
         }
         Map<Integer, AuthentikMirrorSnapshot.Metrics> metrics = new java.util.HashMap<>();
         if(targeted)
         {
            existing.forEach(row -> metrics.put(row.getValueInteger("pk"), new AuthentikMirrorSnapshot.Metrics(
               row.getValueInteger("mfaDeviceCount"), row.getValueInteger("failedLogins24h"))));
         }
         for(var user : users)
         {
            if(targeted && metrics.containsKey(user.getInt("pk")) && !touched.contains(user.getInt("pk")))
            {
               continue;
            }
            var counts = client.syncMetrics(user, progress);
            metrics.put(user.getInt("pk"), new AuthentikMirrorSnapshot.Metrics(counts.mfaDeviceCount(), counts.failedLogins24h()));
         }
         var snapshot = AuthentikMirrorSnapshot.build(config, QContext.getQInstance(), users, groups, metrics, targeted ? claim.watermark() : claim.startedAt());
         Set<String> oldUsers = keys(AuthentikSyncTables.USER, null);
         Set<String> oldGroups = keys(AuthentikSyncTables.GROUP, null);
         client.confirmSyncDeletions(missing(oldUsers, snapshot.users()), missing(oldGroups, snapshot.groups()), progress);
         if(!lease.renew(claim))
         {
            return (false);
         }
         try(var transaction = new RDBMSTransaction(connections.open()))
         {
            try
            {
               if(!lease.lock(transaction.getConnection(), claim) || (event != null && !inbox.lockClaim(transaction.getConnection(), event)))
               {
                  transaction.rollback();
                  return (false);
               }
               if(!oldUsers.equals(keys(AuthentikSyncTables.USER, transaction)) || !oldGroups.equals(keys(AuthentikSyncTables.GROUP, transaction)))
               {
                  throw (new QException("Mirror identities changed after deletion preflight; retry synchronization."));
               }
               new AuthentikMirrorWriter(config).fullRefresh(snapshot, transaction);
               publication.apply(snapshot, transaction);
               if(!(targeted ? lease.completeHint(transaction.getConnection(), claim) : lease.complete(transaction.getConnection(), claim, full)))
               {
                  transaction.rollback();
                  return (false);
               }
               transaction.commit();
               return (true);
            }
            catch(Exception failure)
            {
               transaction.rollback();
               throw (failure);
            }
         }
      }
      catch(OwnershipLost lost)
      {
         return (false);
      }
      finally
      {
         lease.release(claim);
      }
   }

   /*******************************************************************************
    ** The directory lease and optional inbox lease must both remain current.
    ** No background thread or shared mutable client callback is needed.
    *******************************************************************************/
   private void renew(AuthentikSyncLease.Claim claim, AuthentikWebhookInbox inbox, AuthentikWebhookInbox.Claim event) throws QException
   {
      try
      {
         if(!lease.renew(claim) || (event != null && !inbox.renew(event)))
         {
            throw (new OwnershipLost());
         }
      }
      catch(java.sql.SQLException failure)
      {
         String state = failure.getSQLState();
         String diagnostic = state != null && state.matches("[A-Z0-9]{5}") ? state : "unknown";
         throw (new QException("Unable to renew directory synchronization ownership (SQL state " + diagnostic + ")."));
      }
   }

   /*******************************************************************************
    ** Expected contention/cancellation, distinct from API or storage failure.
    *******************************************************************************/
   private static final class OwnershipLost extends QException
   {
      private static final long serialVersionUID = 1L;

      /***************************************************************************
       ** No identity, ownership token or upstream response in this exception.
       ***************************************************************************/
      private OwnershipLost()
      {
         super("Directory synchronization ownership was lost.");
      }
   }

   /*******************************************************************************
    ** Read local identities completely; a truncated result cannot prove absence.
    *******************************************************************************/
   private Set<String> keys(String name, RDBMSTransaction transaction) throws QException
   {
      Set<String> keys = new HashSet<>();
      for(QRecord row : rows(name, transaction))
      {
         String key = row.getValueString("pk");
         if(key == null || !keys.add(key))
         {
            throw (new QException("Mirror has missing or duplicate source identities."));
         }
      }
      return (keys);
   }

   /*******************************************************************************
    ** Only complete bounded local reads may participate in reconciliation.
    *******************************************************************************/
   private List<QRecord> rows(String name, RDBMSTransaction transaction) throws QException
   {
      var rows = new QueryAction().execute(new QueryInput().withTableName(config.applyTablePrefix(name)).withTransaction(transaction)
         .withFilter(new QQueryFilter().withLimit(1_000_001))).getRecords();
      if(rows.size() > 1_000_000)
      {
         throw (new QException("Mirror exceeds the synchronization row limit."));
      }
      return (rows);
   }

   /*******************************************************************************
    ** Group membership writes need not update a user's last_updated. Discover
    ** newly visible members using live scoped reads, then recompute all retained
    ** users from the new graph. Unchanged known users require no detail request.
    *******************************************************************************/
   private List<org.json.JSONObject> incrementalUsers(List<QRecord> existing, List<org.json.JSONObject> changed,
      List<org.json.JSONObject> groups, AuthentikActionUtil.SyncProgress progress) throws Exception
   {
      Set<Integer> known = new HashSet<>();
      existing.forEach(row -> known.add(row.getValueInteger("pk")));
      changed.forEach(user -> known.add(user.getInt("pk")));
      Set<Integer> changedKeys = new HashSet<>();
      changed.forEach(user -> changedKeys.add(user.getInt("pk")));
      Set<Integer> discovered = new java.util.TreeSet<>();
      // Authentik's is_superuser can itself include inherited status. Refresh
      // these source profiles rather than retaining a stale true after demotion.
      existing.stream().filter(row -> Boolean.TRUE.equals(row.getValueBoolean("sourceIsSuperuser")))
         .map(row -> row.getValueInteger("pk")).filter(pk -> !changedKeys.contains(pk)).forEach(discovered::add);
      for(var group : groups)
      {
         var members = group.optJSONArray("users");
         if(members == null)
         {
            throw (new QException("Group synchronization is missing membership data."));
         }
         for(int i = 0; i < members.length(); i++)
         {
            int pk = members.getInt(i);
            if(!known.contains(pk))
            {
               discovered.add(pk);
            }
         }
      }
      if(discovered.size() > AuthentikActionUtil.MAX_SWEEP_OBJECTS)
      {
         throw (new QException("Group synchronization exceeds the user discovery limit."));
      }
      List<org.json.JSONObject> updates = new java.util.ArrayList<>(changed);
      Set<Integer> absent = new HashSet<>();
      for(Integer pk : discovered)
      {
         var user = client.syncUser(pk.toString(), progress);
         if(user != null)
         {
            updates.add(user);
         }
         else
         {
            absent.add(pk);
         }
      }
      return (AuthentikMirrorSnapshot.incrementalUsers(config,
         existing.stream().filter(row -> !absent.contains(row.getValueInteger("pk"))).toList(), updates, groups));
   }

   /*******************************************************************************
    ** Only candidates absent from the complete new snapshot need live checks.
    *******************************************************************************/
   private static List<String> missing(Set<String> existing, List<QRecord> desired)
   {
      Set<String> missing = new HashSet<>(existing);
      desired.forEach(row -> missing.remove(row.getValueString("pk")));
      return (missing.stream().sorted().toList());
   }
}
