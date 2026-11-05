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

import java.sql.SQLException;
import java.util.Objects;

/*******************************************************************************
 ** One bounded batch for either the scheduled worker, ESB trigger, or inline
 ** fallback. Delivery is at least once; handlers must re-read live state and
 ** must not apply permission values from the hint itself.
 *******************************************************************************/
public final class AuthentikApplyChangeEvents
{
   private final AuthentikWebhookInbox inbox;
   private final Handler handler;

   /*******************************************************************************
    ** Mirror refresh plus session invalidation; either failure retries the hint.
    *******************************************************************************/
   @FunctionalInterface
   public interface Handler
   {
      /***************************************************************************
       ** Read current Authentik state outside a database transaction. Use
       ** inbox.withClaim for local mirror/session-marker writes so a reclaimed
       ** worker cannot publish stale data. A failed ownership check must not
       ** perform any unfenced side effects.
       ***************************************************************************/
      void apply(AuthentikWebhookEnvelope event, AuthentikWebhookInbox.Claim claim) throws Exception;
   }

   /*******************************************************************************
    ** Counts only state transitions actually committed by this worker.
    *******************************************************************************/
   public record Result(int succeeded, int retriedOrFailed, int lostLease, int deferred)
   {
   }

   /*******************************************************************************
    ** Normal directory contention must not exhaust a durable event's attempts.
    *******************************************************************************/
   private static final class PublicationDeferred extends Exception
   {
      private static final long serialVersionUID = 1L;
   }

   /*******************************************************************************
    ** All callers share the same durable inbox implementation.
    *******************************************************************************/
   public AuthentikApplyChangeEvents(AuthentikWebhookInbox inbox, Handler handler)
   {
      this.inbox = Objects.requireNonNull(inbox);
      this.handler = Objects.requireNonNull(handler);
   }

   /*******************************************************************************
    ** Host processing path: current-state refresh and inbox fencing share the
    ** configured database. Contention is retried, never acknowledged as applied.
    *******************************************************************************/
   public static AuthentikApplyChangeEvents forHost(com.kingsrook.qbits.authentik.AuthentikQBitConfig config,
      AuthentikMirrorWorker.Publication publication) throws com.kingsrook.qqq.backend.core.exceptions.QException
   {
      var inbox = new AuthentikWebhookInbox(config, java.time.Duration.ofMinutes(15));
      var worker = new AuthentikMirrorWorker(config, com.kingsrook.qbits.authentik.client.AuthentikActionUtil.forBackend(config.getApiBackendName()));
      var invitations = new AuthentikInvitationEvents(com.kingsrook.qbits.authentik.client.AuthentikActionUtil.forBackend(config.getApiBackendName()),
         new AuthentikInvitationAssignments(config));
      return (new AuthentikApplyChangeEvents(inbox, (event, claim) ->
      {
         if(!invitations.apply(inbox, claim))
         {
            throw (new PublicationDeferred());
         }
         if("invitation_used".equals(event.action()))
         {
            // Consumption precedes account creation and has no enrollee to mirror.
            return;
         }
         if(!worker.applyEvent(publication, inbox, claim))
         {
            throw (new PublicationDeferred());
         }
      }));
   }

   /*******************************************************************************
    ** Process at most fifty hints. Exceptions are intentionally not persisted
    ** or logged because upstream messages may contain credentials or PII.
    *******************************************************************************/
   public Result runBatch() throws SQLException
   {
      int succeeded = 0;
      int failed = 0;
      int lost = 0;
      int deferred = 0;
      for(var claim : inbox.claim(AuthentikWebhookInbox.MAX_BATCH))
      {
         if(!inbox.renew(claim))
         {
            lost++;
            continue;
         }
         try
         {
            handler.apply(AuthentikWebhookEnvelope.fromStorage(claim.payload()), claim);
         }
         catch(PublicationDeferred contention)
         {
            if(inbox.defer(claim))
            {
               deferred++;
            }
            else
            {
               lost++;
            }
            continue;
         }
         catch(Exception failure)
         {
            if(inbox.fail(claim))
            {
               failed++;
            }
            else
            {
               lost++;
            }
            if(failure instanceof InterruptedException)
            {
               Thread.currentThread().interrupt();
               break;
            }
            continue;
         }
         if(inbox.complete(claim))
         {
            succeeded++;
         }
         else
         {
            lost++;
         }
      }
      return (new Result(succeeded, failed, lost, deferred));
   }
}
