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
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.WidgetType;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitComponentMetaDataProducer;


/*******************************************************************************
 ** The "Identity Drift Report" widget: a standard TABLE widget (generic UI, no
 ** frontend work) listing the AuthentikDriftReport findings. Needs
 ** identity.admin. The renderer finds the qbit through the "backendName"
 ** default value.
 *******************************************************************************/
public class AuthentikDriftReportWidgetProducer extends QBitComponentMetaDataProducer<QWidgetMetaData, AuthentikQBitConfig>
{
   public static final String NAME              = "driftReport";
   public static final String BACKEND_NAME_KEY  = "backendName";



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public QWidgetMetaData produce(QInstance qInstance) throws QException
   {
      AuthentikQBitConfig config = getQBitConfig();
      return (new QWidgetMetaData()
         .withName(config.applyPrefix(NAME))
         .withLabel("Identity Drift Report")
         .withType(WidgetType.TABLE.getType())
         .withGridColumns(12)
         .withIsCard(true)
         .withCodeReference(new QCodeReference(AuthentikDriftReportWidgetRenderer.class))
         .withPermissionRules(IdentityPermission.ADMIN.rules())
         .withDefaultValue(BACKEND_NAME_KEY, config.getApiBackendName()));
   }



   /*******************************************************************************
    ** After the tables, before the app.
    *******************************************************************************/
   @Override
   public int getSortOrder()
   {
      return (500);
   }

}
