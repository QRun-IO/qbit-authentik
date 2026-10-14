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


import java.time.Instant;
import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.actions.tables.DeleteAction;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.json.JSONObject;


/*******************************************************************************
 ** Non-secret bookkeeping. No method accepts a key or a bearer.
 *******************************************************************************/
public class TokenScopeStore
{
   public static final List<String> SCOPE_FIELDS = List.of("readOnly", "apps", "tables", "processes", "reports", "widgets", "operationIds");
   private final AuthentikQBitConfig config;

   /*******************************************************************************
    ** Bind to one qbit's local backend.
    *******************************************************************************/
   public TokenScopeStore(AuthentikQBitConfig config)
   {
      this.config = config;
   }



   /*******************************************************************************
    ** Local table name.
    *******************************************************************************/
   private String table()
   {
      return (config.applyTablePrefix(AuthentikLocalTables.TOKEN_SCOPE));
   }



   /*******************************************************************************
    ** Fetch the unique scope row.
    *******************************************************************************/
   public QRecord find(String identifier) throws QException
   {
      List<QRecord> rows = new QueryAction().execute(new QueryInput().withTableName(table())
         .withFilter(new QQueryFilter(new QFilterCriteria("tokenIdentifier", QCriteriaOperator.EQUALS, identifier)))).getRecords();
      return (rows.isEmpty() ? null : rows.get(0));
   }



   /*******************************************************************************
    ** Record a new identifier, even when scopes are disabled.
    *******************************************************************************/
   public void create(String identifier, JSONObject owner, AdminRequest request, String operator) throws QException
   {
      QRecord row = new QRecord().withValue("tokenIdentifier", identifier).withValue("ownerPk", owner.getInt("pk"))
         .withValue("ownerUsername", owner.getString("username")).withValue("createdBy", operator).withValue("createdAt", Instant.now());
      if(Boolean.TRUE.equals(config.getTokenScopesEnabled()))
      {
         for(String field : SCOPE_FIELDS)
         {
            if(request.params().containsKey(field))
            {
               row.setValue(field, request.params().get(field));
            }
         }
      }
      List<QRecord> rows = new InsertAction().execute(new InsertInput().withTableName(table()).withRecords(List.of(row))).getRecords();
      check(rows);
   }



   /*******************************************************************************
    ** Keep all scope and reminder fields when rotating a personal credential.
    *******************************************************************************/
   public void move(String oldIdentifier, String newIdentifier) throws QException
   {
      QRecord row = find(oldIdentifier);
      if(row != null)
      {
         row.setValue("tokenIdentifier", newIdentifier);
         row.setValue("rotatedAt", Instant.now());
         check(new UpdateAction().execute(new UpdateInput().withTableName(table()).withRecords(List.of(row))).getRecords());
      }
   }



   /*******************************************************************************
    ** Revoke removes only the corresponding metadata row.
    *******************************************************************************/
   public void delete(String identifier) throws QException
   {
      QRecord row = find(identifier);
      if(row != null)
      {
         new DeleteAction().execute(new DeleteInput().withTableName(table()).withPrimaryKeys(List.of(row.getValue("id"))));
      }
   }



   /*******************************************************************************
    ** Fail closed if local storage rejects the write.
    *******************************************************************************/
   private static void check(List<QRecord> rows) throws QException
   {
      if(rows.isEmpty() || !rows.get(0).getErrors().isEmpty())
      {
         throw (new QException("Token scope metadata could not be saved."));
      }
   }
}
