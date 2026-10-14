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

package com.kingsrook.qbits.authentik.admin;

/*******************************************************************************
 ** A response-only value. Deliberately not Serializable; never a process value.
 *******************************************************************************/
public final class OneTimeKey
{
   private final String label;
   private final String value;
   private final String usageText;

   /*******************************************************************************
    ** Construct the one-time response.
    *******************************************************************************/
   public OneTimeKey(String label, String value, String usageText)
   {
      this.label = label;
      this.value = value;
      this.usageText = usageText;
   }



   /*******************************************************************************
    ** Getter for label.
    *******************************************************************************/
   public String label()
   {
      return (label);
   }



   /*******************************************************************************
    ** Getter for value.
    *******************************************************************************/
   public String value()
   {
      return (value);
   }



   /*******************************************************************************
    ** Getter for masked.
    *******************************************************************************/
   public String masked()
   {
      return ("\u2022\u2022\u2022\u2022" + value.substring(Math.max(0, value.length() - 4)));
   }



   /*******************************************************************************
    ** Getter for usageText.
    *******************************************************************************/
   public String usageText()
   {
      return (usageText);
   }



   /*******************************************************************************
    ** Never render the key or its usage text.
    *******************************************************************************/
   @Override
   public String toString()
   {
      return ("OneTimeKey{label=" + label + ", value=[one-time]}" );
   }
}
