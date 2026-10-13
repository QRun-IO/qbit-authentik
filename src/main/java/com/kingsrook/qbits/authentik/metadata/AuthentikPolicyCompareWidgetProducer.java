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
import com.kingsrook.qbits.authentik.policy.PolicyCutoverWidgets;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.WidgetType;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitComponentMetaDataProducer;


/*******************************************************************************
 ** Compare Access (DESIGN.md section 12.8): today's access against what the policies would grant, per active person. Read only.
 *******************************************************************************/
public class AuthentikPolicyCompareWidgetProducer extends QBitComponentMetaDataProducer<QWidgetMetaData, AuthentikQBitConfig>
{

   /*******************************************************************************
    ** Only with the POLICIES feature.
    *******************************************************************************/
   @Override
   public boolean isEnabled()
   {
      return (getQBitConfig() != null && getQBitConfig().hasFeature(AuthentikFeature.POLICIES));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public QWidgetMetaData produce(QInstance qInstance) throws QException
   {
      AuthentikQBitConfig config = getQBitConfig();
      return (new QWidgetMetaData()
         .withName(config.applyPrefix(PolicyCutoverWidgets.COMPARE))
         .withLabel("Compare Access")
         .withType(WidgetType.TABLE.getType())
         .withGridColumns(12)
         .withIsCard(true)
         .withCodeReference(new QCodeReference(PolicyCutoverWidgets.CompareRenderer.class))
         .withPermissionRules(IdentityPermission.ADMIN.rules())
         .withDefaultValue(PolicyCutoverWidgets.BACKEND_NAME_KEY, config.getApiBackendName()));
   }



   /*******************************************************************************
    ** After the tables, before the app.
    *******************************************************************************/
   @Override
   public int getSortOrder()
   {
      return (470);
   }
}
