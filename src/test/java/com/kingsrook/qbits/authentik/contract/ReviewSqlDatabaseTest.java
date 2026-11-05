/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.contract;

import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qbits.authentik.admin.TokenScopeStore;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 ** Exercise the token widget's scope lookup against the review SQL migrations.
 ******************************************************************************/
class ReviewSqlDatabaseTest
{
   /***************************************************************************
    ** Tokens without local scope records still need every mapped column valid.
    ***************************************************************************/
   @Test
   void tokenScopeLookupUsesPublishedColumnNames() throws Exception
   {
      var instance = new QInstance();
      instance.withInstanceDefaultAuthentication(new com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData()
         .withName("mock").withType(com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType.MOCK));
      var database = new ReviewSqlDatabase(instance);
      var config = new AuthentikQBitConfig().withLocalBackendName(ReviewSqlDatabase.BACKEND);
      instance.addTable(AuthentikLocalTables.tokenScope(config));
      database.initialize(instance);
      var previous = QContext.capture();
      try
      {
         QContext.init(instance, new QSystemUserSession(instance));
         assertThat(new TokenScopeStore(config).find("review-widget-regression")).isNull();
      }
      finally
      {
         QContext.init(previous);
      }
   }
}
