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

package com.kingsrook.qbits.authentik.sync;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.processes.BackendStep;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QBackendStepMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QFunctionInputMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.scheduleing.QScheduleMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;

/*******************************************************************************
 ** Native background processes; database ownership, not scheduler locality,
 ** fences publication. The QBit producer registers these when MIRROR is enabled.
 *******************************************************************************/
public class AuthentikSyncProcesses implements BackendStep
{
   public static final String INBOX = "syncInbox";
   public static final String INCREMENTAL = "syncIncremental";
   public static final String FULL = "syncFull";
   public static final String RETENTION = "syncRetention";

   /***************************************************************************
    ** No threads or extra scheduler are created. Ambiguous scheduler selection
    ** is a configuration error rather than silently scheduling on another host.
    ***************************************************************************/
   public static List<QProcessMetaData> processes(QInstance instance, AuthentikQBitConfig config)
   {
      if(!config.hasFeature(AuthentikFeature.MIRROR))
      {
         return (List.of());
      }
      String scheduler = config.getSchedulerName();
      if(scheduler == null && instance.getSchedulers().size() == 1)
      {
         scheduler = instance.getSchedulers().keySet().iterator().next();
      }
      if(scheduler == null || !instance.getSchedulers().containsKey(scheduler))
      {
         throw (new IllegalArgumentException("Mirror synchronization requires an unambiguous registered scheduler."));
      }
      if(!instance.getSchedulers().get(scheduler).supportsCronSchedules())
      {
         throw (new IllegalArgumentException("Mirror synchronization requires a scheduler supporting the nightly cron schedule."));
      }
      List<QProcessMetaData> processes = new ArrayList<>();
      // Reconcile before the fifteen-minute authorization snapshot expires.
      // The previous scan-start watermark stays authoritative until commit;
      // starting only at its expiry would deny access during every next scan.
      processes.add(process(config, INCREMENTAL, "Reconcile identity changes", new QScheduleMetaData()
         .withSchedulerName(scheduler).withRepeatSeconds(300).withInitialDelaySeconds(1)));
      processes.add(process(config, FULL, "Reconcile complete identity directory", new QScheduleMetaData()
         .withSchedulerName(scheduler).withCronExpression("0 0 2 * * ?").withCronTimeZoneId("UTC")));
      processes.add(process(config, RETENTION, "Expire identity synchronization history", new QScheduleMetaData()
         .withSchedulerName(scheduler).withRepeatSeconds(86400).withInitialDelaySeconds(3600)));
      if(config.hasFeature(AuthentikFeature.WEBHOOK))
      {
         var inbox = process(config, INBOX, "Process identity change events", new QScheduleMetaData()
            .withSchedulerName(scheduler).withRepeatSeconds(2).withInitialDelaySeconds(2));
         if(com.kingsrook.qqq.backend.core.utils.StringUtils.hasContent(config.getEsbDestinationName()))
         {
            com.kingsrook.qbits.authentik.esb.AuthentikEsbDelivery.attach(instance, config, inbox);
         }
         processes.add(inbox);
      }
      return (List.copyOf(processes));
   }

   /***************************************************************************
    ** Inputs contain routing names only, never credentials or event payloads.
    ***************************************************************************/
   private static QProcessMetaData process(AuthentikQBitConfig config, String operation, String label, QScheduleMetaData schedule)
   {
      return (new QProcessMetaData().withName(config.applyPrefix(operation)).withLabel(label).withIsHidden(true)
         .withPermissionRules(IdentityPermission.ADMIN.rules()).withSchedule(schedule)
         .withStep(new QBackendStepMetaData().withName("run").withCode(new QCodeReference(AuthentikSyncProcesses.class))
            .withInputData(new QFunctionInputMetaData()
               .withField(new QFieldMetaData("backendName", QFieldType.STRING).withDefaultValue(config.getApiBackendName()))
               .withField(new QFieldMetaData("operation", QFieldType.STRING).withDefaultValue(operation)))));
   }

   /***************************************************************************
    ** Only the host's internal scheduler/ESB context may run directory jobs.
    ** Never elevate an interactive caller. Feature disablement applies live.
    ***************************************************************************/
   @Override
   public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
   {
      if(!(QContext.getQSession() instanceof QSystemUserSession))
      {
         throw (new QPermissionDeniedException("Directory synchronization requires the internal session."));
      }
      var config = AuthentikRuntime.forBackend(input.getValueString("backendName")).getConfig();
      String operation = input.getValueString("operation");
      if(!config.hasFeature(AuthentikFeature.MIRROR) || (INBOX.equals(operation) && !config.hasFeature(AuthentikFeature.WEBHOOK)))
      {
         throw (new QPermissionDeniedException("Directory synchronization feature is disabled."));
      }
      try
      {
         // The refreshing OAuth adapter reads committed mirror permissions on
         // every request. Publication itself is its durable reevaluation signal;
         // there are no node-local session caches or separate markers to update.
         AuthentikMirrorWorker.Publication publication = (snapshot, transaction) -> { };
         switch(operation == null ? "" : operation)
         {
            case INBOX ->
            {
               var result = AuthentikApplyChangeEvents.forHost(config, publication).runBatch();
               output.addValue("succeeded", result.succeeded());
               output.addValue("retriedOrFailed", result.retriedOrFailed());
               output.addValue("lostLease", result.lostLease());
               output.addValue("deferred", result.deferred());
            }
            case INCREMENTAL, FULL ->
            {
               var worker = new AuthentikMirrorWorker(config, AuthentikActionUtil.forBackend(config.getApiBackendName()));
               boolean published = FULL.equals(operation) ? worker.fullRefresh(publication, null, null) : worker.incrementalRefresh(publication);
               output.addValue("published", published);
            }
            case RETENTION ->
            {
               output.addValue("eventsPurged", new AuthentikWebhookInbox(config, Duration.ofMinutes(15)).purge());
               output.addValue("bindingsPurged", new AuthentikSessionBindings(config).purgeExpired());
               output.addValue("invitationIntentsPurged", new AuthentikInvitationAssignments(config).purgeSettled());
            }
            default -> throw (new QException("Unknown directory synchronization operation."));
         }
      }
      catch(Exception failure)
      {
         if(failure instanceof InterruptedException)
         {
            Thread.currentThread().interrupt();
         }
         // Process persistence/logging must not capture upstream payloads or SQL.
         throw (new QException("Directory synchronization did not complete."));
      }
   }
}
