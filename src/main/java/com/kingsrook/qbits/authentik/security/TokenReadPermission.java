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

package com.kingsrook.qbits.authentik.security;


import com.kingsrook.qqq.backend.core.actions.permissions.CustomPermissionChecker;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.AbstractActionInput;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.MetaDataWithPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;


/*******************************************************************************
 ** Either auditors or token managers may read token metadata.
 *******************************************************************************/
public class TokenReadPermission implements CustomPermissionChecker
{
   /*******************************************************************************
    ** Shared metadata rules for the API and local token tables.
    *******************************************************************************/
   public static QPermissionRules rules()
   {
      return (IdentityPermission.AUDIT_READ.rules().withCustomPermissionChecker(new QCodeReference(TokenReadPermission.class)));
   }



   /*******************************************************************************
    ** Require either permission; core invokes this for table-level access.
    *******************************************************************************/
   @Override
   public void checkPermissionsThrowing(AbstractActionInput input, MetaDataWithPermissionRules metadata) throws QPermissionDeniedException
   {
      if(!AuthentikGuard.has(QContext.getQSession(), IdentityPermission.AUDIT_READ)
         && !AuthentikGuard.has(QContext.getQSession(), IdentityPermission.TOKENS_MANAGE))
      {
         throw (new QPermissionDeniedException("Token metadata requires authentik.audit.read or authentik.tokens.manage."));
      }
   }
}
