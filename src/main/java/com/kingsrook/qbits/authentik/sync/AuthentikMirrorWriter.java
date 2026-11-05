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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.actions.tables.DeleteAction;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;

/*******************************************************************************
 ** Reconcile local mirrors through standard QQQ actions, retaining RECORD audit.
 ** The caller owns a real host-backend transaction and must hold the sync lease
 ** on that same connection. This class neither commits nor closes it.
 *******************************************************************************/
public final class AuthentikMirrorWriter
{
   private static final int MAX_LOCAL_ROWS = 1_000_000;
   private static final int BATCH_SIZE = 100;
   private final AuthentikQBitConfig config;

   /*******************************************************************************
    ** Only the configured local tables are writable by this component.
    *******************************************************************************/
   public AuthentikMirrorWriter(AuthentikQBitConfig config)
   {
      this.config = Objects.requireNonNull(config);
   }

   /*******************************************************************************
    ** Full snapshots may remove missing rows. Incremental user snapshots must
    ** never enter this method. Any failure requires caller rollback of all
    ** mirrors, audit writes, checkpoint and session invalidation markers.
    *******************************************************************************/
   public void fullRefresh(AuthentikMirrorSnapshot snapshot, QBackendTransaction transaction) throws QException
   {
      if(!(QContext.getQSession() instanceof QSystemUserSession))
      {
         throw (new QPermissionDeniedException("Mirror writes require the internal synchronization session."));
      }
      Objects.requireNonNull(transaction, "Mirror refresh requires a host transaction");
      for(String name : List.of(AuthentikSyncTables.USER, AuthentikSyncTables.GROUP, AuthentikSyncTables.MEMBERSHIP))
      {
         var table = QContext.getQInstance().getTable(config.applyTablePrefix(name));
         if(table == null || !Objects.equals(config.getLocalBackendName(), table.getBackendName()) || table.getAuditRules() == null
            || table.getAuditRules().getAuditLevel() != com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel.RECORD)
         {
            throw (new QException("Mirror metadata must use the configured local backend and audit rules."));
         }
      }
      reconcile(AuthentikSyncTables.GROUP, snapshot.groups(), List.of("pk"), transaction);
      reconcile(AuthentikSyncTables.USER, snapshot.users(), List.of("pk"), transaction);
      reconcile(AuthentikSyncTables.MEMBERSHIP, snapshot.memberships(), List.of("userPk", "groupPk"), transaction);
   }

   /*******************************************************************************
    ** Preserve local record IDs across source renames and attribute changes.
    ** Never delete rows when the existing directory query might be truncated.
    *******************************************************************************/
   private void reconcile(String name, List<QRecord> desired, List<String> keyFields, QBackendTransaction transaction) throws QException
   {
      String table = config.applyTablePrefix(name);
      List<QRecord> existing = new QueryAction().execute(new QueryInput().withTableName(table).withTransaction(transaction)
         .withFilter(new QQueryFilter().withLimit(MAX_LOCAL_ROWS + 1))).getRecords();
      if(existing.size() > MAX_LOCAL_ROWS || desired.size() > MAX_LOCAL_ROWS)
      {
         throw (new QException("Mirror refresh exceeds the supported local row limit; no changes may be committed."));
      }
      Map<List<Serializable>, QRecord> oldByKey = new HashMap<>();
      for(QRecord row : existing)
      {
         if(oldByKey.put(key(row, keyFields), row) != null)
         {
            throw (new QException("Mirror contains duplicate identity keys."));
         }
      }
      List<QRecord> inserts = new ArrayList<>();
      List<QRecord> updates = new ArrayList<>();
      List<QRecord> reserveIdentities = new ArrayList<>();
      java.util.Set<String> reservedNames = new java.util.HashSet<>();
      if(AuthentikSyncTables.USER.equals(name))
      {
         existing.forEach(row -> reservedNames.add(row.getValueString("username")));
         desired.forEach(row -> reservedNames.add(row.getValueString("username")));
      }
      java.util.Set<List<Serializable>> seen = new java.util.HashSet<>();
      for(QRecord row : desired)
      {
         List<Serializable> key = key(row, keyFields);
         if(!seen.add(key))
         {
            throw (new QException("Mirror snapshot contains duplicate identity keys."));
         }
         QRecord old = oldByKey.remove(key);
         QRecord write = new QRecord();
         row.getValues().forEach(write::setValue);
         if(old == null)
         {
            inserts.add(write);
         }
         else if(!row.getValues().entrySet().stream().allMatch(e -> Objects.equals(e.getValue(), old.getValue(e.getKey()))))
         {
            write.setValue("id", old.getValue("id"));
            updates.add(write);
            if(AuthentikSyncTables.USER.equals(name))
            {
               QRecord reservation = new QRecord().withValue("id", old.getValue("id"));
               if(row.getValues().containsKey("username") && !Objects.equals(row.getValue("username"), old.getValue("username")))
               {
                  String temporary;
                  do
                  {
                     temporary = "__qqq_sync_" + java.util.UUID.randomUUID();
                  }
                  while(!reservedNames.add(temporary));
                  reservation.withValue("username", temporary);
               }
               if(row.getValues().containsKey("email") && !Objects.equals(row.getValue("email"), old.getValue("email")))
               {
                  reservation.withValue("email", null);
               }
               if(reservation.getValues().size() > 1)
               {
                  reserveIdentities.add(reservation);
               }
            }
         }
      }
      // Delete obsolete identities first to allow a rename/replacement to reuse
      // an old unique username/email. Transaction isolation hides intermediate rows.
      List<Serializable> deletes = oldByKey.values().stream().map(r -> r.getValue("id")).toList();
      for(int offset = 0; offset < deletes.size(); offset += BATCH_SIZE)
      {
         var batch = deletes.subList(offset, Math.min(offset + BATCH_SIZE, deletes.size()));
         var output = new DeleteAction().execute(new DeleteInput().withTableName(table).withTransaction(transaction).withPrimaryKeys(batch));
         if(output.getDeletedRecordCount() != batch.size() || (output.getRecordsWithErrors() != null && !output.getRecordsWithErrors().isEmpty()))
         {
            throw (new QException("Mirror delete failed; roll back this refresh."));
         }
      }
      // Release changed unique names/emails before applying the final values,
      // allowing swaps and reuse by new identities. These temporary values are
      // isolated inside the caller's transaction and use audited QQQ updates.
      for(int offset = 0; offset < reserveIdentities.size(); offset += BATCH_SIZE)
      {
         var batch = reserveIdentities.subList(offset, Math.min(offset + BATCH_SIZE, reserveIdentities.size()));
         check(new UpdateAction().execute(new UpdateInput().withTableName(table).withTransaction(transaction).withRecords(batch)).getRecords(), batch.size());
      }
      for(int offset = 0; offset < inserts.size(); offset += BATCH_SIZE)
      {
         var batch = inserts.subList(offset, Math.min(offset + BATCH_SIZE, inserts.size()));
         check(new InsertAction().execute(new InsertInput().withTableName(table).withTransaction(transaction).withRecords(batch)).getRecords(), batch.size());
      }
      for(int offset = 0; offset < updates.size(); offset += BATCH_SIZE)
      {
         var batch = updates.subList(offset, Math.min(offset + BATCH_SIZE, updates.size()));
         check(new UpdateAction().execute(new UpdateInput().withTableName(table).withTransaction(transaction).withRecords(batch)).getRecords(), batch.size());
      }
   }

   /*******************************************************************************
    ** Stable source identity, independent of user-editable display labels.
    *******************************************************************************/
   private static List<Serializable> key(QRecord record, List<String> fields) throws QException
   {
      List<Serializable> values = new ArrayList<>();
      for(String field : fields)
      {
         Serializable value = record.getValue(field);
         if(value == null)
         {
            throw (new QException("Mirror identity key is missing."));
         }
         values.add(value);
      }
      return (List.copyOf(values));
   }

   /*******************************************************************************
    ** QQQ may return per-record errors without throwing; never commit them.
    *******************************************************************************/
   private static void check(List<QRecord> records, int expected) throws QException
   {
      if(records == null || records.size() != expected || records.stream().anyMatch(r -> r.getErrors() != null && !r.getErrors().isEmpty()))
      {
         throw (new QException("Mirror write failed; roll back this refresh."));
      }
   }
}
