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


import java.lang.reflect.Method;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;


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
    ** RC.5 Alerts raises guard incidents. The installed qbit's notification
    ** API supplies owner-directed reminders until core ships notifications.
    *******************************************************************************/
   public boolean send(Notice notice)
   {
      try
      {
         Class<?> alerts = Class.forName("com.kingsrook.qqq.backend.core.alerts.QAlerts");
         if("high".equals(notice.severity()))
         {
            Class<?> signalType = Class.forName("com.kingsrook.qqq.backend.core.alerts.AlertSignal");
            Object signal = signalType.getConstructor(String.class).newInstance("authentik.token.guard-bypass");
            signalType.getMethod("withDedupKey", String.class).invoke(signal, notice.key());
            signalType.getMethod("withTitle", String.class).invoke(signal, "Access token guard bypass");
            signalType.getMethod("withSummary", String.class).invoke(signal, notice.message());
            Class<?> severity = Class.forName("com.kingsrook.qqq.backend.core.alerts.AlertSeverity");
            signalType.getMethod("withSeverity", severity).invoke(signal, severity.getField("CRITICAL").get(null));
            alerts.getMethod("raise", signalType).invoke(null, signal);
            return (true);
         }
         Class<?> runtimeType = Class.forName("com.kingsrook.qbits.alerts.AlertsRuntime");
         Object runtime = runtimeType.getMethod("find", QInstance.class).invoke(null, QContext.getQInstance());
         if(runtime != null)
         {
            Object sink = runtimeType.getMethod("sink").invoke(runtime);
            Class<?> signalType = Class.forName("com.kingsrook.qbits.alerts.spi.NotificationSignal");
            Class<?> audienceType = Class.forName("com.kingsrook.qbits.alerts.spi.NotificationAudience");
            Object signal = signalType.getConstructor(String.class).newInstance("Access token expiry reminder");
            signalType.getMethod("withBody", String.class).invoke(signal, notice.message());
            signalType.getMethod("withSourceName", String.class).invoke(signal, "authentik");
            signalType.getMethod("withSourceKey", String.class).invoke(signal, notice.key());
            signalType.getMethod("withAudience", audienceType).invoke(signal, audienceType.getMethod("user", String.class).invoke(null, notice.recipient()));
            Method notify = sink.getClass().getMethod("notify", signalType);
            notify.invoke(sink, signal);
            return (true);
         }
      }
      catch(ReflectiveOperationException | LinkageError e)
      {
         // Optional dependency absent or incompatible. Never log the payload.
      }
      LOG.info("Access-token notification delivery is unavailable; notification skipped.");
      return (false);
   }
}
