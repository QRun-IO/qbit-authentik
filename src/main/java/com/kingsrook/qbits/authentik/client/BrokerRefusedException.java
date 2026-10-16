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


import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;


/*******************************************************************************
 ** Authentik's token endpoint refused a broker request. Carries only the
 ** standard OAuth2 error code (never the untrusted response body).
 *******************************************************************************/
public class BrokerRefusedException extends QUserFacingException
{
   private final String errorCode;



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   public BrokerRefusedException(String errorCode)
   {
      super("Authentik refused to act as you (" + errorCode + ")");
      this.errorCode = errorCode;
   }



   /*******************************************************************************
    ** The OAuth2 error code, or exchange_failed when it was not a standard one.
    *******************************************************************************/
   public String getErrorCode()
   {
      return (errorCode);
   }
}
