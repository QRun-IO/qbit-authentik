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

package com.kingsrook.qbits.authentik.processes;


import com.kingsrook.qbits.authentik.admin.OneTimeKey;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;


/*******************************************************************************
 ** Response-only delivery SPI. Hosts may install their core-compatible adapter.
 *******************************************************************************/
@FunctionalInterface
public interface TokenKeyDelivery
{
   /*******************************************************************************
    ** Deliver only into a response-only core channel, never process values.
    *******************************************************************************/
   void deliver(RunBackendStepOutput output, OneTimeKey key);

   /*******************************************************************************
    ** Whether this implementation can show a key once.
    *******************************************************************************/
   default boolean available()
   {
      return (true);
   }



   /*******************************************************************************
    ** Current adapter; null restores the safe reflection adapter.
    *******************************************************************************/
   static void set(TokenKeyDelivery delivery)
   {
      Holder.delivery = delivery == null ? new ReflectiveDelivery() : delivery;
   }



   /*******************************************************************************
    ** Current adapter.
    *******************************************************************************/
   static TokenKeyDelivery get()
   {
      return (Holder.delivery);
   }



   /*******************************************************************************
    ** Fail closed if runtime delivery becomes unavailable after Review.
    *******************************************************************************/
   static boolean tryDeliver(RunBackendStepOutput output, OneTimeKey key)
   {
      try
      {
         TokenKeyDelivery delivery = get();
         if(!delivery.available())
         {
            return (false);
         }
         delivery.deliver(output, key);
         return (true);
      }
      catch(RuntimeException e)
      {
         return (false);
      }
   }



   /*******************************************************************************
    ** Mutable holder, without putting a credential in static state.
    *******************************************************************************/
   final class Holder
   {
      private static volatile TokenKeyDelivery delivery = new ReflectiveDelivery();

      /*******************************************************************************
       ** Utility holder.
       *******************************************************************************/
      private Holder()
      {
      }
   }



   /*******************************************************************************
    ** STAND-IN(core=QRun-IO/qqq#1162, removeBy=4.1.0-RC.7)
    ** Reflection keeps RC.2 binary-compatible and never falls back to values.
    *******************************************************************************/
   final class ReflectiveDelivery implements TokenKeyDelivery
   {
      /*******************************************************************************
       ** Check the complete core contract before any irreversible key mutation.
       *******************************************************************************/
      @Override
      public boolean available()
      {
         try
         {
            Class<?> type = Class.forName("com.kingsrook.qqq.backend.core.model.secrets.OneTimeSecret");
            type.getConstructor();
            for(String field : new String[] { "Label", "Value", "Masked", "UsageText" })
            {
               type.getMethod("with" + field, String.class);
            }
            RunBackendStepOutput.class.getMethod("addOneTimeSecret", type);
            return (true);
         }
         catch(ReflectiveOperationException e)
         {
            return (false);
         }
      }



      /*******************************************************************************
       ** Add to core's response-only channel; never include failures' contents.
       *******************************************************************************/
      @Override
      public void deliver(RunBackendStepOutput output, OneTimeKey key)
      {
         try
         {
            Class<?> type = Class.forName("com.kingsrook.qqq.backend.core.model.secrets.OneTimeSecret");
            Object secret = type.getConstructor().newInstance();
            type.getMethod("withLabel", String.class).invoke(secret, key.label());
            type.getMethod("withValue", String.class).invoke(secret, key.value());
            type.getMethod("withMasked", String.class).invoke(secret, key.masked());
            type.getMethod("withUsageText", String.class).invoke(secret, key.usageText());
            RunBackendStepOutput.class.getMethod("addOneTimeSecret", type).invoke(output, secret);
         }
         catch(ReflectiveOperationException e)
         {
            throw (new IllegalStateException("One-time output unavailable"));
         }
      }
   }
}
