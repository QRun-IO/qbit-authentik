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

package com.kingsrook.qbits.authentik.policy;


import java.util.Optional;


/*******************************************************************************
 ** The five standard actions, in canonical statement order. Table features use
 ** their registered string names separately. Each standard action
 ** maps to the QQQ permission suffix of the same name ({resource}.{action}).
 *******************************************************************************/
public enum PolicyAction
{
   HAS_ACCESS("hasAccess"),
   READ("read"),
   INSERT("insert"),
   EDIT("edit"),
   DELETE("delete");

   /** "All five actions" in a statement's Action array. */
   public static final String WILDCARD = "*";

   private final String jsonName;



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   PolicyAction(String jsonName)
   {
      this.jsonName = jsonName;
   }



   /*******************************************************************************
    ** The name used in documents and as the QQQ permission suffix.
    *******************************************************************************/
   public String getJsonName()
   {
      return (jsonName);
   }



   /*******************************************************************************
    ** The QQQ permission this action grants on a resource.
    *******************************************************************************/
   public String permission(String resource)
   {
      return (resource + "." + jsonName);
   }



   /*******************************************************************************
    ** Look up by document name (case-sensitive, like QQQ permission names).
    *******************************************************************************/
   public static Optional<PolicyAction> fromJsonName(String name)
   {
      for(PolicyAction action : values())
      {
         if(action.jsonName.equals(name))
         {
            return (Optional.of(action));
         }
      }
      return (Optional.empty());
   }
}
