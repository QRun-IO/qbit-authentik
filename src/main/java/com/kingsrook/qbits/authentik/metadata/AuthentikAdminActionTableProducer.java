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

package com.kingsrook.qbits.authentik.metadata;


import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitComponentMetaDataProducer;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** authentik_admin_action: the append-only audit trail of every change made from QQQ.
 *******************************************************************************/
public class AuthentikAdminActionTableProducer extends QBitComponentMetaDataProducer<QTableMetaData, AuthentikQBitConfig>
{

   /*******************************************************************************
    ** Needs the local backend.
    *******************************************************************************/
   @Override
   public boolean isEnabled()
   {
      return (getQBitConfig() != null && getQBitConfig().getLocalBackendName() != null);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public QTableMetaData produce(QInstance qInstance) throws QException
   {
      return (AuthentikLocalTables.adminAction(getQBitConfig()));
   }



   /*******************************************************************************
    ** After the backend.
    *******************************************************************************/
   @Override
   public int getSortOrder()
   {
      return (300);
   }

}
