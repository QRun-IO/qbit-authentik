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
import com.kingsrook.qqq.backend.core.model.secrets.OneTimeSecret;


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
    ** Current adapter; null restores the core response-only adapter.
    *******************************************************************************/
   static void set(TokenKeyDelivery delivery)
   {
      Holder.delivery = delivery == null ? new CoreDelivery() : delivery;
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
      private static volatile TokenKeyDelivery delivery = new CoreDelivery();

      /*******************************************************************************
       ** Utility holder.
       *******************************************************************************/
      private Holder()
      {
      }
   }



   /*******************************************************************************
    ** Core response-only delivery; credentials never enter process values.
    *******************************************************************************/
   final class CoreDelivery implements TokenKeyDelivery
   {
      /*******************************************************************************
       ** Add to core's response-only channel.
       *******************************************************************************/
      @Override
      public void deliver(RunBackendStepOutput output, OneTimeKey key)
      {
         output.addOneTimeSecret(new OneTimeSecret().withLabel(key.label()).withValue(key.value())
            .withMasked(key.masked()).withUsageText(key.usageText()));
      }
   }
}
