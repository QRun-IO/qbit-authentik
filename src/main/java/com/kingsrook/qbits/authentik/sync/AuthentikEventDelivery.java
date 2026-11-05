/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.sync;

import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.utils.StringUtils;

/*******************************************************************************
 ** Wake processing after durable receipt. Polling recovers lost notifications;
 ** ESB carries no user profile, grants, credentials, or webhook payload.
 *******************************************************************************/
public final class AuthentikEventDelivery
{
   /***************************************************************************
    ** Utility class.
    ***************************************************************************/
   private AuthentikEventDelivery()
   {
   }

   /***************************************************************************
    ** Called only after inbox commit. A notification failure cannot roll back
    ** receipt; callers retain the scheduled recovery path.
    ***************************************************************************/
   public static void dispatch(AuthentikQBitConfig config) throws Exception
   {
      if(!(QContext.getQSession() instanceof QSystemUserSession) || !config.hasFeature(AuthentikFeature.MIRROR)
         || !config.hasFeature(AuthentikFeature.WEBHOOK))
      {
         throw (new QPermissionDeniedException("Event delivery requires internal enabled synchronization."));
      }
      if(StringUtils.hasContent(config.getEsbDestinationName()))
      {
         com.kingsrook.qbits.authentik.esb.AuthentikEsbDelivery.publish(config);
      }
      else
      {
         // The request-time mapper reads the committed mirror on every request.
         AuthentikApplyChangeEvents.forHost(config, (snapshot, transaction) -> { }).runBatch();
      }
   }
}
