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
import com.kingsrook.qbits.authentik.processes.AuthentikTokenReminders;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QBackendStepMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitComponentMetaDataProducer;
import com.kingsrook.qqq.backend.core.model.metadata.scheduleing.QScheduleMetaData;


/*******************************************************************************
 ** Daily background task, hidden from navigation; no scheduler dependency.
 *******************************************************************************/
public class AuthentikTokenReminderProcessProducer extends QBitComponentMetaDataProducer<QProcessMetaData, AuthentikQBitConfig>
{
   /*******************************************************************************
    ** Reminders require local dedupe storage and the TOKENS feature.
    *******************************************************************************/
   @Override
   public boolean isEnabled()
   {
      return (getQBitConfig() != null && getQBitConfig().getLocalBackendName() != null && getQBitConfig().hasFeature(AuthentikFeature.TOKENS));
   }



   /*******************************************************************************
    ** Use the configured scheduler or the instance's first registered scheduler.
    *******************************************************************************/
   @Override
   public QProcessMetaData produce(QInstance instance)
   {
      AuthentikQBitConfig config = getQBitConfig();
      QProcessMetaData process = new QProcessMetaData().withName(config.applyPrefix("tokenReminders"))
         .withLabel("Access token reminders").withIsHidden(true).withPermissionRules(IdentityPermission.TOKENS_MANAGE.rules())
         .withStep(new QBackendStepMetaData().withName("run").withCode(new QCodeReference(AuthentikTokenReminders.class))
            .withInputData(new com.kingsrook.qqq.backend.core.model.metadata.processes.QFunctionInputMetaData()
               .withField(new com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData("backendName", com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType.STRING)
                  .withDefaultValue(config.getApiBackendName()))));
      String scheduler = config.getTokenReminderSchedulerName();
      if(scheduler == null && !instance.getSchedulers().isEmpty())
      {
         scheduler = instance.getSchedulers().keySet().iterator().next();
      }
      if(scheduler != null)
      {
         process.withSchedule(new QScheduleMetaData().withSchedulerName(scheduler).withRepeatSeconds(86400).withInitialDelaySeconds(3600));
      }
      return (process);
   }
}
