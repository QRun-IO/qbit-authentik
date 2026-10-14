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

package com.kingsrook.qbits.authentik.client;

import java.util.List;
import com.kingsrook.qbits.authentik.admin.AdminTestSupport;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.OAuth2AuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Exact OAuth2 session-table contract from the locally pinned core sources.
 *******************************************************************************/
class OAuth2SubjectTokenSourceTest
{
   /*******************************************************************************
    ** A UUID identifies exactly one row, and hidden accessToken is readable.
    *******************************************************************************/
   @Test
   void currentSessionOnly() throws QException
   {
      AdminTestSupport t = AdminTestSupport.create();
      t.qInstance.addTable(new QTableMetaData().withName("oauth_sessions").withBackendName(AdminTestSupport.LOCAL).withPrimaryKeyField("id")
         .withUniqueKey(new com.kingsrook.qqq.backend.core.model.metadata.tables.UniqueKey("uuid"))
         .withField(new QFieldMetaData("id", QFieldType.INTEGER)).withField(new QFieldMetaData("uuid", QFieldType.STRING))
         .withField(new QFieldMetaData("accessToken", QFieldType.STRING).withIsHidden(true)));
      OAuth2AuthenticationMetaData oauth = new OAuth2AuthenticationMetaData().withUserSessionTableName("oauth_sessions");
      oauth.setName("oauth");
      QContext.getQSession().setUuid("current-session");
      new InsertAction().execute(new InsertInput().withTableName("oauth_sessions").withRecords(List.of(
         new QRecord().withValue("uuid", "current-session").withValue("accessToken", "subject:3"),
         new QRecord().withValue("uuid", "other-session").withValue("accessToken", "subject:4"))));
      t.qInstance.withInstanceDefaultAuthentication(oauth);
      OAuth2SubjectTokenSource source = new OAuth2SubjectTokenSource();
      assertThat(source.subjectToken(QContext.getQSession())).isEqualTo("subject:3");
      QContext.getQSession().setUuid("unknown");
      assertThatThrownBy(() -> source.subjectToken(QContext.getQSession())).hasMessage(OAuth2SubjectTokenSource.UNAVAILABLE);
      assertThatThrownBy(() -> source.subjectToken(null)).hasMessage(OAuth2SubjectTokenSource.UNAVAILABLE);
   }

   /*******************************************************************************
    ** Static/mock sessions are never exchanged as the qbit service account.
    *******************************************************************************/
   @Test
   void unavailableSessionRefused() throws QException
   {
      AdminTestSupport.create();
      assertThatThrownBy(() -> new OAuth2SubjectTokenSource().subjectToken(QContext.getQSession()))
         .hasMessage(OAuth2SubjectTokenSource.UNAVAILABLE);
   }
}
