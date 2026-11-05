/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.sync;

import java.util.UUID;
import com.kingsrook.qbits.authentik.admin.AuthentikInvitationEvidence;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import org.json.JSONObject;

/*******************************************************************************
 ** Re-fetch enrollment evidence and persist it under inbox ownership. This
 ** Paired intent is passed to the admin service for live authorization and
 ** audited, durable membership attempts.
 *******************************************************************************/
public final class AuthentikInvitationEvents
{
   private final AuthentikActionUtil client;
   private final AuthentikInvitationAssignments assignments;

   /***************************************************************************
    ** Share the configured directory and host database with the inbox processor.
    ***************************************************************************/
   public AuthentikInvitationEvents(AuthentikActionUtil client, AuthentikInvitationAssignments assignments)
   {
      this.client = java.util.Objects.requireNonNull(client);
      this.assignments = java.util.Objects.requireNonNull(assignments);
   }

   /***************************************************************************
    ** The envelope supplies only an event locator. All association, identity and
    ** chronology facts come from guarded authoritative API reads before locking.
    ** False means ownership was lost; rejected evidence must not be acknowledged.
    ***************************************************************************/
   public boolean apply(AuthentikWebhookInbox inbox, AuthentikWebhookInbox.Claim claim) throws Exception
   {
      if(!(QContext.getQSession() instanceof QSystemUserSession))
      {
         throw (new QPermissionDeniedException("Invitation events require the internal session."));
      }
      var hint = AuthentikWebhookEnvelope.fromStorage(claim.payload());
      if(!"invitation_used".equals(hint.action()) && !"user_write".equals(hint.action()))
      {
         return (true);
      }
      JSONObject event = client.syncEvent(hint.eventPk());
      if(event == null || !hint.eventPk().equals(event.optString("pk")) || !hint.action().equals(event.optString("action")))
      {
         throw (new QException("Invitation event could not be verified."));
      }
      JSONObject context = event.optJSONObject("context");
      boolean consumption = "invitation_used".equals(hint.action());
      String locator = identifier(context == null ? null : context.opt(consumption ? "invitation_uuid" : AuthentikInvitationEvidence.REFERENCE), consumption);
      if(locator == null)
      {
         // Ordinary account edits and invitations without saved assignments
         // are unrelated to this workflow. Never infer identity from email.
         return (true);
      }
      var intent = consumption ? assignments.findByInvitation(locator) : assignments.find(locator);
      if(intent == null || !java.util.List.of("WAITING", "READY").contains(intent.status()))
      {
         return (true);
      }
      var evidence = new AuthentikInvitationEvidence(client);
      if(consumption)
      {
         var fact = evidence.consumed(hint.eventPk(), intent.invitationId(), intent.flow(), intent.createdAt(), intent.expiresAt());
         boolean saved = inbox.withClaim(claim, connection ->
         {
            requireRecorded(assignments.recordConsumption(connection, intent.reference(), fact));
         });
         return (saved && new com.kingsrook.qbits.authentik.admin.AuthentikAdmin(client)
            .applyInvitationAssignments(intent.reference(), inbox, claim));
      }
      var fact = evidence.enrolled(hint.eventPk(), intent.reference(), intent.flow(), intent.createdAt(), intent.expiresAt());
      JSONObject user = client.syncUser(fact.userPk().toString());
      String userUuid = identifier(user == null ? null : user.opt("uuid"), false);
      if(userUuid == null || !Boolean.TRUE.equals(user.opt("is_active")))
      {
         throw (new QException("Invitation account is unavailable or inactive."));
      }
      boolean saved = inbox.withClaim(claim, connection ->
      {
         requireRecorded(assignments.recordEnrollment(connection, intent.reference(), fact, userUuid));
      });
      return (saved && new com.kingsrook.qbits.authentik.admin.AuthentikAdmin(client)
         .applyInvitationAssignments(intent.reference(), inbox, claim));
   }

   /***************************************************************************
    ** Refusal rolls back the inbox transaction and follows its bounded retries.
    ***************************************************************************/
   private static void requireRecorded(boolean recorded) throws QException
   {
      if(!recorded)
      {
         throw (new QException("Invitation evidence was not accepted by the saved intent."));
      }
   }

   /***************************************************************************
    ** Only canonical UUIDs or native invitation UUID.hex are lookup candidates.
    ** A candidate locates saved intent; it does not establish trust in the event.
    ***************************************************************************/
   private static String identifier(Object value, boolean allowHex)
   {
      if(!(value instanceof String text))
      {
         return (null);
      }
      if(allowHex && text.matches("[0-9a-fA-F]{32}"))
      {
         text = text.substring(0, 8) + "-" + text.substring(8, 12) + "-" + text.substring(12, 16) + "-" + text.substring(16, 20) + "-" + text.substring(20);
      }
      return (text.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}") ? UUID.fromString(text).toString() : null);
   }
}
