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


import java.util.Map;
import com.kingsrook.qqq.backend.core.actions.tables.GetAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.OAuth2AuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;


/*******************************************************************************
 ** Reads the OAuth2 module's user-session row (uuid and accessToken in RC.2).
 ** No memoization: the credential lives only for the current action.
 *******************************************************************************/
public class OAuth2SubjectTokenSource implements AuthentikSubjectTokenSource
{
   public static final String UNAVAILABLE = "Self-service tokens need a signed-in Authentik session.";

   /*******************************************************************************
    ** Look up the exact current session, including its hidden access token.
    *******************************************************************************/
   @Override
   public String subjectToken(QSession session) throws QException
   {
      if(session != null && session == QContext.getQSession() && !(session instanceof QSystemUserSession) && session.getUser() != null && session.getUuid() != null && QContext.getQInstance() != null
         && QContext.getQInstance().getAuthentication() instanceof OAuth2AuthenticationMetaData oauth
         && oauth.getUserSessionTableName() != null)
      {
         QRecord row;
         QSession previous = QContext.getQSession();
         try
         {
            // Core uses a system read here too, avoiding recursive OAuth validation.
            // The UUID is taken only from the already authorized current session.
            QContext.setQSession(new QSystemUserSession());
            row = new GetAction().executeForRecord(new GetInput(oauth.getUserSessionTableName())
               .withUniqueKey(Map.of("uuid", session.getUuid())).withShouldMaskPasswords(false).withShouldOmitHiddenFields(false));
         }
         catch(QException e)
         {
            throw (new QUserFacingException(UNAVAILABLE));
         }
         finally
         {
            QContext.setQSession(previous);
         }
         if(row != null && row.getValueString("accessToken") != null && !row.getValueString("accessToken").isBlank())
         {
            return (row.getValueString("accessToken"));
         }
      }
      throw (new QUserFacingException(UNAVAILABLE));
   }
}
