/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.sync;

import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData;

/*******************************************************************************
 ** Opt-in host registration. No database migrations or network calls run here;
 ** the host owns physical storage, audit metadata and scheduler startup.
 *******************************************************************************/
public final class AuthentikSyncRegistration
{
   /***************************************************************************
    ** Utility class.
    ***************************************************************************/
   private AuthentikSyncRegistration()
   {
   }

   /***************************************************************************
    ** Validate host dependencies; safe to repeat after registration for health.
    ***************************************************************************/
   public static void validate(QInstance instance, AuthentikQBitConfig config, List<String> errors)
   {
      if(instance == null || config.getLocalBackendName() == null
         || !(instance.getBackend(config.getLocalBackendName()) instanceof RDBMSBackendMetaData))
      {
         errors.add("feature MIRROR needs localBackendName naming a registered RDBMS backend");
      }
      if(instance == null)
      {
         errors.add("feature MIRROR needs a host instance with a registered scheduler");
         return;
      }
      try
      {
         AuthentikSyncProcesses.processes(instance, config);
      }
      catch(IllegalArgumentException invalid)
      {
         errors.add(invalid.getMessage());
      }
   }

   /***************************************************************************
    ** Producer-only collision checks, before any host metadata is mutated.
    ***************************************************************************/
   public static void validateNames(QInstance instance, AuthentikQBitConfig config, List<String> errors)
   {
      for(var table : AuthentikSyncTables.all(config))
      {
         if(instance.getTable(table.getName()) != null)
         {
            errors.add("Mirror table name already registered: " + table.getName());
         }
      }
      for(var process : AuthentikSyncProcesses.processes(instance, config))
      {
         if(instance.getProcess(process.getName()) != null)
         {
            errors.add("Mirror process name already registered: " + process.getName());
         }
      }
      if(config.hasFeature(AuthentikFeature.WEBHOOK))
      {
         com.kingsrook.qbits.authentik.webhook.AuthentikWebhookRouteProvider.validateRegistration(instance, config, errors);
      }
   }

   /***************************************************************************
    ** Add the complete storage set and native background processes. Features
    ** are opt-in; read-only controls upstream edits, not local synchronization.
    ***************************************************************************/
   public static void register(QInstance instance, AuthentikQBitConfig config)
   {
      AuthentikSyncTables.all(config).forEach(instance::addTable);
      AuthentikSyncProcesses.processes(instance, config).forEach(instance::addProcess);
      if(config.hasFeature(AuthentikFeature.WEBHOOK))
      {
         com.kingsrook.qbits.authentik.webhook.AuthentikWebhookRouteProvider.register(instance, config);
      }
   }
}
