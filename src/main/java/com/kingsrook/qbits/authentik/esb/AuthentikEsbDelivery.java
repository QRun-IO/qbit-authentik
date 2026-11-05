/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.esb;

import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.esb.model.EsbInstanceMetaData;
import com.kingsrook.qqq.esb.model.EsbProcessMetaData;
import com.kingsrook.qqq.esb.model.EsbTrigger;
import com.kingsrook.qqq.esb.model.EsbTriggerMode;
import com.kingsrook.qqq.esb.publish.EsbPublishAction;
import com.kingsrook.qqq.esb.publish.EsbPublishInput;

/*******************************************************************************
 ** Optional ESB types remain isolated from hosts using inline synchronization.
 ** The broker notification only wakes the durable inbox, the source of truth.
 *******************************************************************************/
public final class AuthentikEsbDelivery
{
   public static final String EVENT_TYPE = "qqq.authentik.inbox.ready";

   /***************************************************************************
    ** Utility class.
    ***************************************************************************/
   private AuthentikEsbDelivery()
   {
   }

   /***************************************************************************
    ** Register the approved bounded trigger on the existing inbox process.
    ** The scheduled poll remains enabled to recover failed/lost broker sends.
    ***************************************************************************/
   public static void attach(QInstance instance, AuthentikQBitConfig config, QProcessMetaData process)
   {
      requireDestination(instance, config);
      EsbProcessMetaData.ofOrWithNew(process).withTrigger(new EsbTrigger()
         .withDestinationName(config.getEsbDestinationName()).withMode(EsbTriggerMode.BATCH)
         .withBatchSize(50).withBatchWaitMs(2000).withConcurrency(1).withMaxAttempts(5));
   }

   /***************************************************************************
    ** Send only a routing hint after SQL commit. Never include event payloads.
    ***************************************************************************/
   public static void publish(AuthentikQBitConfig config) throws QException
   {
      if(!(QContext.getQSession() instanceof com.kingsrook.qqq.backend.core.model.session.QSystemUserSession)
         || !config.hasFeature(com.kingsrook.qbits.authentik.AuthentikFeature.MIRROR)
         || !config.hasFeature(com.kingsrook.qbits.authentik.AuthentikFeature.WEBHOOK))
      {
         throw (new com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException("Identity event publication requires internal enabled synchronization."));
      }
      requireDestination(QContext.getQInstance(), config);
      var result = new EsbPublishAction().execute(new EsbPublishInput().withDestinationName(config.getEsbDestinationName())
         .withType(EVENT_TYPE).withSourcePath("authentik/inbox").withData(Map.of()));
      if(!Boolean.TRUE.equals(result.getSuccess()))
      {
         throw (new QException("Identity inbox notification could not be published; polling will recover it."));
      }
   }

   /***************************************************************************
    ** Host owns broker metadata and credentials; no implicit destination setup.
    ***************************************************************************/
   private static void requireDestination(QInstance instance, AuthentikQBitConfig config)
   {
      if(!(instance.getSupplementalMetaData(EsbInstanceMetaData.NAME) instanceof EsbInstanceMetaData esb)
         || esb.getDestination(config.getEsbDestinationName()) == null)
      {
         throw (new IllegalArgumentException("Identity synchronization ESB destination is not registered."));
      }
   }
}
