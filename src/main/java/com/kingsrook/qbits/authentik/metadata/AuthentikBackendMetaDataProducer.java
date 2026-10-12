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
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitComponentMetaDataProducer;
import com.kingsrook.qqq.backend.module.api.model.AuthorizationType;
import com.kingsrook.qqq.backend.module.api.model.metadata.APIBackendMetaData;


/*******************************************************************************
 ** The API backend all Authentik tables use. Authorization is CUSTOM: the
 ** action util adds the bearer token itself, from the qbit config, so the token
 ** never sits in backend metadata (which QQQ can serialize).
 *******************************************************************************/
public class AuthentikBackendMetaDataProducer extends QBitComponentMetaDataProducer<APIBackendMetaData, AuthentikQBitConfig>
{

   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public APIBackendMetaData produce(QInstance qInstance) throws QException
   {
      AuthentikQBitConfig config = getQBitConfig();
      APIBackendMetaData backend = new APIBackendMetaData()
         .withBaseUrl(config.getApiRoot())
         .withAuthorizationType(AuthorizationType.CUSTOM)
         .withContentType("application/json")
         .withActionUtil(new QCodeReference(AuthentikActionUtil.class));
      backend.setName(config.getApiBackendName());
      return (backend);
   }



   /*******************************************************************************
    ** First: the tables reference it.
    *******************************************************************************/
   @Override
   public int getSortOrder()
   {
      return (100);
   }

}
