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


import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.client.AuthentikFieldSpec;
import com.kingsrook.qbits.authentik.client.AuthentikTableSpec;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitComponentMetaDataProducer;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.module.api.model.metadata.APITableBackendDetails;


/*******************************************************************************
 ** Builds a read-only QQQ table from an AuthentikTableSpec and registers it
 ** with the runtime. Subclasses name the spec.
 *******************************************************************************/
public abstract class AbstractAuthentikTableProducer extends QBitComponentMetaDataProducer<QTableMetaData, AuthentikQBitConfig>
{

   /*******************************************************************************
    ** The unprefixed spec name, e.g. AuthentikTables.USER.
    *******************************************************************************/
   protected abstract String getSpecName();



   /*******************************************************************************
    ** Tables need READ; subclasses may add conditions.
    *******************************************************************************/
   @Override
   public boolean isEnabled()
   {
      return (getQBitConfig() != null && getQBitConfig().hasFeature(AuthentikFeature.READ));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public QTableMetaData produce(QInstance qInstance) throws QException
   {
      return (buildTable(getQBitConfig(), AuthentikTables.get(getSpecName())));
   }



   /*******************************************************************************
    ** Build the table and register it with the config's runtime.
    *******************************************************************************/
   public static QTableMetaData buildTable(AuthentikQBitConfig config, AuthentikTableSpec spec)
   {
      String tableName = config.applyTablePrefix(spec.getName());

      QTableMetaData table = new QTableMetaData()
         .withName(tableName)
         .withLabel(spec.getLabel())
         .withIcon(new QIcon(spec.getIcon()))
         .withBackendName(config.getApiBackendName())
         .withPrimaryKeyField(spec.getKeyFieldName())
         .withBackendDetails(new APITableBackendDetails().withTablePath(spec.getPath()))
         .withPermissionRules(spec.readRules())
         .withCapabilities(Capability.TABLE_QUERY, Capability.TABLE_GET, Capability.TABLE_COUNT, Capability.TABLE_EXPORT)
         .withoutCapabilities(Capability.TABLE_INSERT, Capability.TABLE_UPDATE, Capability.TABLE_DELETE, Capability.QUERY_STATS);

      for(AuthentikFieldSpec field : spec.getFields())
      {
         QFieldMetaData fieldMetaData = new QFieldMetaData(field.getName(), field.getType()).withLabel(field.getLabel());
         if(field.isHidden())
         {
            fieldMetaData.withIsHidden(true);
         }
         table.withField(fieldMetaData);
      }

      if(!spec.getRecordLabelFields().isEmpty())
      {
         table.withRecordLabelFormat(String.join(" ", spec.getRecordLabelFields().stream().map(f -> "%s").toList()));
         table.withRecordLabelFields(spec.getRecordLabelFields());
      }

      AuthentikRuntime.forBackend(config.getApiBackendName()).registerTable(tableName, spec);
      return (table);
   }



   /*******************************************************************************
    ** After the backend.
    *******************************************************************************/
   @Override
   public int getSortOrder()
   {
      return (200);
   }

}
