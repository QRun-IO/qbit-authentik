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
import com.kingsrook.qbits.authentik.app.AuthentikTokenWidget;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitComponentMetaDataProducer;


/*******************************************************************************
 ** Access token administration uses a standard TABLE widget (guardrail G5).
 *******************************************************************************/
public class AuthentikTokenWidgetProducer extends QBitComponentMetaDataProducer<QWidgetMetaData, AuthentikQBitConfig>
{
   public static final String NAME = "accessTokens";

   /*******************************************************************************
    ** Token inventory needs the local metadata table.
    *******************************************************************************/
   @Override
   public boolean isEnabled()
   {
      return (getQBitConfig() != null && getQBitConfig().getLocalBackendName() != null && getQBitConfig().hasFeature(AuthentikFeature.TOKENS));
   }



   /*******************************************************************************
    ** Register before the app, alongside the existing home widgets.
    *******************************************************************************/
   @Override
   public int getSortOrder()
   {
      return (500);
   }



   /*******************************************************************************
    ** Permission is checked again in the renderer.
    *******************************************************************************/
   @Override
   public QWidgetMetaData produce(QInstance instance)
   {
      AuthentikQBitConfig config = getQBitConfig();
      return (new QWidgetMetaData().withName(config.applyPrefix(NAME)).withLabel("Access tokens").withType(com.kingsrook.qqq.backend.core.model.dashboard.widgets.WidgetType.TABLE.getType())
         .withGridColumns(12).withIsCard(true).withPermissionRules(IdentityPermission.TOKENS_MANAGE.rules())
         .withCodeReference(new QCodeReference(AuthentikTokenWidget.class)).withDefaultValue("backendName", config.getApiBackendName()));
   }
}
