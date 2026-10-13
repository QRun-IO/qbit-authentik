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

package com.kingsrook.qbits.authentik.policy;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qqq.backend.core.actions.tables.DeleteAction;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateOutput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.json.JSONObject;


/*******************************************************************************
 ** The authentik_policy rows (DESIGN.md section 12.2): the QQQ record of each
 ** group's last policy save, plus the fingerprint used to tell when the policy
 ** was changed in Authentik since.
 *******************************************************************************/
public final class PolicyStore
{

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private PolicyStore()
   {
   }



   /*******************************************************************************
    ** A fingerprint of a group's policy attribute value: of its canonical form
    ** when it parses (so formatting differences do not count), else of the raw
    ** text. Null for no policy.
    *******************************************************************************/
   public static String fingerprint(Object attributeValue, PolicyFormat format)
   {
      return (fingerprint(attributeValue, format, null));
   }



   /*******************************************************************************
    ** Fingerprint including registered table features in the canonical form.
    *******************************************************************************/
   public static String fingerprint(Object attributeValue, PolicyFormat format, PolicyCatalog catalog)
   {
      if(attributeValue == null || JSONObject.NULL.equals(attributeValue) || "".equals(attributeValue))
      {
         return (null);
      }
      String text;
      try
      {
         text = PolicyGenerator.toCompact(PolicyGenerator.canonical(attributeValue, format, catalog));
      }
      catch(PolicyParseException e)
      {
         text = String.valueOf(attributeValue);
      }
      try
      {
         return (HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))));
      }
      catch(NoSuchAlgorithmException e)
      {
         throw (new IllegalStateException(e));
      }
   }



   /*******************************************************************************
    ** The row of a group, or null (also null when the table is not set up).
    *******************************************************************************/
   public static QRecord find(AuthentikQBitConfig config, String groupPk) throws QException
   {
      String table = config.applyTablePrefix(AuthentikLocalTables.POLICY);
      if(QContext.getQInstance() == null || QContext.getQInstance().getTable(table) == null)
      {
         return (null);
      }
      QueryInput queryInput = new QueryInput();
      queryInput.setTableName(table);
      queryInput.setFilter(new QQueryFilter(new QFilterCriteria("groupPk", QCriteriaOperator.EQUALS, groupPk)));
      QueryOutput output = new QueryAction().execute(queryInput);
      return (output.getRecords().isEmpty() ? null : output.getRecords().get(0));
   }



   /*******************************************************************************
    ** Remove the row of a deleted group (no-op without one).
    *******************************************************************************/
   public static void delete(AuthentikQBitConfig config, String groupPk) throws QException
   {
      QRecord existing = find(config, groupPk);
      if(existing != null)
      {
         DeleteInput deleteInput = new DeleteInput();
         deleteInput.setTableName(config.applyTablePrefix(AuthentikLocalTables.POLICY));
         deleteInput.setPrimaryKeys(List.of(existing.getValue("id")));
         new DeleteAction().execute(deleteInput);
      }
   }



   /*******************************************************************************
    ** Insert or update the row of a group after a save to Authentik.
    **
    ** @param document the canonical document that was saved (empty statements
    **                 when the policy was removed)
    *******************************************************************************/
   public static void save(AuthentikQBitConfig config, String groupPk, String groupName, JSONObject document, int permissionCount, String savedBy, String fingerprint) throws QException
   {
      String  table    = config.applyTablePrefix(AuthentikLocalTables.POLICY);
      QRecord existing = find(config, groupPk);
      QRecord record = new QRecord()
         .withValue("groupPk", groupPk)
         .withValue("groupName", groupName)
         .withValue("policyJson", PolicyGenerator.toPretty(document))
         .withValue("statementCount", document.optJSONArray("Statement") == null ? 0 : document.getJSONArray("Statement").length())
         .withValue("permissionCount", permissionCount)
         .withValue("savedBy", savedBy)
         .withValue("savedDate", Instant.now())
         .withValue("authentikFingerprint", fingerprint)
         .withValue("modifyDate", Instant.now());

      if(existing == null)
      {
         record.setValue("createDate", Instant.now());
         InsertInput insertInput = new InsertInput();
         insertInput.setTableName(table);
         insertInput.setRecords(List.of(record));
         InsertOutput output = new InsertAction().execute(insertInput);
         if(output.getRecords().isEmpty() || !output.getRecords().get(0).getErrors().isEmpty())
         {
            throw (new QException("The policy record could not be written: " + (output.getRecords().isEmpty() ? "no record" : output.getRecords().get(0).getErrors())));
         }
      }
      else
      {
         record.setValue("id", existing.getValue("id"));
         UpdateInput updateInput = new UpdateInput();
         updateInput.setTableName(table);
         updateInput.setRecords(List.of(record));
         UpdateOutput output = new UpdateAction().execute(updateInput);
         if(output.getRecords().isEmpty() || !output.getRecords().get(0).getErrors().isEmpty())
         {
            throw (new QException("The policy record could not be written: " + (output.getRecords().isEmpty() ? "no record" : output.getRecords().get(0).getErrors())));
         }
      }
   }
}
