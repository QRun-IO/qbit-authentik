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
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.MetaDataProducerMultiOutput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitComponentMetaDataProducer;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitProductionContext;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** The "Identity" app (DESIGN.md section 8.1): the qbit's tables (and, from
 ** phase 1, its widgets), gated by identity.users.read. Hosts re-parent it, e.g.
 ** kof22 nests it under Admin; its name stays the same. Processes are only
 ** ever table or record actions, never navigation entries.
 *******************************************************************************/
public class AuthentikAppMetaDataProducer extends QBitComponentMetaDataProducer<QAppMetaData, AuthentikQBitConfig>
{
   public static final String APP_NAME = "admin";



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public QAppMetaData produce(QInstance qInstance) throws QException
   {
      AuthentikQBitConfig config = getQBitConfig();

      QAppMetaData app = new QAppMetaData()
         .withName(config.applyPrefix(APP_NAME))
         .withLabel("Identity")
         .withIcon(new QIcon("badge"))
         .withPermissionRules(IdentityPermission.USERS_READ.rules());

      MetaDataProducerMultiOutput produced = QBitProductionContext.peekMetaDataProducerMultiOutput();
      if(produced != null)
      {
         for(String specName : AuthentikTables.all().keySet())
         {
            QTableMetaData table = produced.get(QTableMetaData.class, config.applyPrefix(specName));
            if(table != null)
            {
               app.withChild(table);
            }
         }
      }
      return (app);
   }



   /*******************************************************************************
    ** Last, so the tables exist in the output.
    *******************************************************************************/
   @Override
   public int getSortOrder()
   {
      return (900);
   }

}
