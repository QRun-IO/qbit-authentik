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


/*******************************************************************************
 ** Proof that {@link AuthentikGuard} authorized one write. AuthentikActionUtil
 ** refuses to send any request that changes Authentik data without one, and the
 ** constructor is package-private, so only the guard can mint it (DESIGN.md
 ** section 5.3: every write path goes through the guard).
 *******************************************************************************/
public final class WriteAuthorization
{
   private final String action;
   private final String operator;



   /*******************************************************************************
    ** Constructor (package-private: only AuthentikGuard authorizes).
    *******************************************************************************/
   WriteAuthorization(String action, String operator)
   {
      this.action = action;
      this.operator = operator;
   }



   /*******************************************************************************
    ** Getter for action
    *******************************************************************************/
   public String getAction()
   {
      return (action);
   }



   /*******************************************************************************
    ** Getter for operator
    *******************************************************************************/
   public String getOperator()
   {
      return (operator);
   }

}
