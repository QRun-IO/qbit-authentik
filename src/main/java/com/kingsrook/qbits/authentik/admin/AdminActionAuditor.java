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


import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;


/*******************************************************************************
 ** Writes the local, append-only audit row (DESIGN.md sections 6.2 and 9.2).
 ** The row is inserted BEFORE the Authentik call; if that insert fails the call
 ** is not made. After the call the same row moves to its final status. Rows are
 ** never deleted.
 *******************************************************************************/
public class AdminActionAuditor
{
   private final AuthentikQBitConfig config;



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   public AdminActionAuditor(AuthentikQBitConfig config)
   {
      this.config = config;
   }



   /*******************************************************************************
    ** Insert the row for a plan before it runs (or is refused / queued) and
    ** return its id. Throws when the audit trail cannot be written, so the
    ** caller must not proceed.
    *******************************************************************************/
   public Serializable begin(AdminPlan plan, String correlationId, String operator, AuthentikLocalTables.ActionStatus status, String approver) throws QException
   {
      QRecord record = new QRecord()
         .withValue("correlationId", correlationId)
         .withValue("actionName", plan.getRequest().action().name())
         .withValue("operator", operator)
         .withValue("reason", plan.getRequest().reason())
         .withValue("targetType", plan.getTargetType())
         .withValue("targetKey", plan.getRequest().targetKey())
         .withValue("targetLabel", plan.getTargetLabel())
         .withValue("beforeText", plan.getBefore())
         .withValue("afterText", plan.getAfter())
         .withValue("status", status.name())
         .withValue("approver", approver)
         .withValue("errorMessage", status == AuthentikLocalTables.ActionStatus.REFUSED ? plan.getMessage() : null)
         .withValue("createDate", Instant.now())
         .withValue("modifyDate", Instant.now());

      InsertInput insertInput = new InsertInput();
      insertInput.setTableName(config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION));
      insertInput.setRecords(List.of(record));
      InsertOutput output = new InsertAction().execute(insertInput);
      QRecord      saved  = output.getRecords().isEmpty() ? null : output.getRecords().get(0);
      if(saved == null || saved.getValue("id") == null || !saved.getErrors().isEmpty())
      {
         throw (new QException("The audit row could not be written, so nothing was changed in Authentik."));
      }
      return (saved.getValue("id"));
   }



   /*******************************************************************************
    ** Move a row to its final status. A failure here is logged by the caller;
    ** the Authentik change has already happened.
    *******************************************************************************/
   public void finish(Serializable id, AuthentikLocalTables.ActionStatus status, String errorMessage, String eventPk, String approver) throws QException
   {
      QRecord update = new QRecord()
         .withValue("id", id)
         .withValue("status", status.name())
         .withValue("errorMessage", errorMessage)
         .withValue("authentikEventPk", eventPk)
         .withValue("modifyDate", Instant.now());
      if(approver != null)
      {
         update.withValue("approver", approver);
      }
      UpdateInput updateInput = new UpdateInput();
      updateInput.setTableName(config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION));
      updateInput.setRecords(List.of(update));
      new UpdateAction().execute(updateInput);
   }

}
