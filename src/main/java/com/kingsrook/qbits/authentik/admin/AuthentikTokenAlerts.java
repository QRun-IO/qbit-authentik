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


import com.kingsrook.qqq.backend.core.alerts.AlertSeverity;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.NotificationAudience;
import com.kingsrook.qqq.backend.core.alerts.NotificationSignal;
import com.kingsrook.qqq.backend.core.alerts.QAlerts;
import com.kingsrook.qqq.backend.core.logging.QLogger;


/*******************************************************************************
 ** Optional Alerts bridge. The qbit compiles on RC.2 without either Alerts API.
 ** No credentials enter this interface. Hosts and tests can supply a sink.
 *******************************************************************************/
public class AuthentikTokenAlerts
{
   private static final QLogger LOG = QLogger.getLogger(AuthentikTokenAlerts.class);

   /*******************************************************************************
    ** Safe notification envelope. A null recipient denotes the admin audience.
    *******************************************************************************/
   public record Notice(String key, String severity, String recipient, String message)
   {
   }



   /*******************************************************************************
    ** Return true only when delivery was accepted, so absence never dedupes.
    *******************************************************************************/
   @FunctionalInterface
   public interface Sink
   {
      /*******************************************************************************
       ** Accept a safe notification, returning false when delivery is unavailable.
       *******************************************************************************/
      boolean send(Notice notice);
   }



   /*******************************************************************************
    ** Constructor for the reflection adapter.
    *******************************************************************************/
   public AuthentikTokenAlerts()
   {
   }



   /*******************************************************************************
    ** Guard incidents are raised through core QAlerts; owner reminders through
    ** core QAlerts.notify (qqq#1125, QQQ 4.1.0-RC.6+). Never another qbit's API.
    *******************************************************************************/
   public boolean send(Notice notice)
   {
      try
      {
         if("high".equals(notice.severity()))
         {
            QAlerts.raise(new AlertSignal("authentik.token.guard-bypass")
               .withDedupKey(notice.key())
               .withTitle("Access token guard bypass")
               .withSummary(notice.message())
               .withSeverity(AlertSeverity.CRITICAL));
            return (true);
         }

         ///////////////////////////////////////////////////////////////////
         // owner reminders: core's notification SPI (bell and email via  //
         // whichever alerts producer the host installed; qqq#1125)       //
         ///////////////////////////////////////////////////////////////////
         QAlerts.notify(new NotificationSignal("Access token expiry reminder")
            .withBody(notice.message())
            .withSourceName("authentik")
            .withSourceKey(notice.key())
            .withAudience(NotificationAudience.user(notice.recipient())));
         return (true);
      }
      catch(RuntimeException e)
      {
         ///////////////////////////////////////////////////////////
         // never fail the caller; never log the notice payload   //
         ///////////////////////////////////////////////////////////
         LOG.info("Access-token notification delivery failed; notification skipped.");
         return (false);
      }
   }
}
