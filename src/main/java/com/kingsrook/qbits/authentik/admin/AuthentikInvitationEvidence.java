/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.admin;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import org.json.JSONObject;

/*******************************************************************************
 ** Read native enrollment facts from the guarded Authentik API, never from a
 ** webhook body. These facts are NOT write authorization: the caller must still
 ** match persisted intent, bind one user once and recheck current grant rights.
 *******************************************************************************/
public final class AuthentikInvitationEvidence
{
   public static final String REFERENCE = "qqq_invitation_reference";
   private final AuthentikActionUtil client;

   /***************************************************************************
    ** Use the configured directory's client and its normal read guard.
    ***************************************************************************/
   public AuthentikInvitationEvidence(AuthentikActionUtil client)
   {
      this.client = Objects.requireNonNull(client);
   }

   /***************************************************************************
    ** Minimal consumption fact; the event's actor is not the future enrollee.
    ***************************************************************************/
   public record Consumption(String eventId, String invitationId, Instant createdAt)
   {
   }

   /***************************************************************************
    ** Minimal creation fact. No mutable email/name, grants or raw context escape.
    ***************************************************************************/
   public record Enrollment(String eventId, String reference, Integer userPk, Instant createdAt)
   {
   }

   /***************************************************************************
    ** Confirm consumption of the exact saved invitation in its configured flow.
    ***************************************************************************/
   public Consumption consumed(String eventId, String invitationId, String flowSlug, Instant earliest, Instant latest) throws QException
   {
      try
      {
         String expected = uuid(invitationId, false);
         JSONObject event = event(eventId, "invitation_used", flowSlug, earliest, latest);
         String actual = uuid(event.getJSONObject("context").get("invitation_uuid"), true);
         if(!expected.equals(actual))
         {
            throw (new IllegalArgumentException());
         }
         return (new Consumption(uuid(eventId, false), actual, Instant.parse(event.getString("created"))));
      }
      catch(Exception invalid)
      {
         throw (new QException("Invitation consumption evidence could not be verified."));
      }
   }

   /***************************************************************************
    ** Confirm an actual new account, not a profile edit or impersonated actor.
    ** Expected correlation comes from saved intent, never from a webhook field.
    ***************************************************************************/
   public Enrollment enrolled(String eventId, String reference, String flowSlug, Instant earliest, Instant latest) throws QException
   {
      try
      {
         String expected = uuid(reference, false);
         JSONObject event = event(eventId, "user_write", flowSlug, earliest, latest);
         new AuthentikInvitationFlow(client).verify(flowSlug);
         JSONObject context = event.getJSONObject("context");
         JSONObject user = event.getJSONObject("user");
         Object pk = user.get("pk");
         if(!Boolean.TRUE.equals(context.get("created")) || !expected.equals(uuid(context.get(REFERENCE), false))
            || user.has("on_behalf_of") || user.has("authenticated_as") || user.has("is_agent")
            || !(pk instanceof Number))
         {
            throw (new IllegalArgumentException());
         }
         int userPk = new java.math.BigDecimal(pk.toString()).intValueExact();
         if(userPk < 1)
         {
            throw (new IllegalArgumentException());
         }
         return (new Enrollment(uuid(eventId, false), expected, userPk, Instant.parse(event.getString("created"))));
      }
      catch(Exception invalid)
      {
         throw (new QException("Invitation enrollment evidence could not be verified."));
      }
   }

   /***************************************************************************
    ** Match the event's immutable ID, native action, flow endpoint and bounded
    ** creation window. API failures and malformed records fail closed. The
    ** existing event table reader enforces audit-read permissions before I/O.
    ***************************************************************************/
   private JSONObject event(String eventId, String action, String flowSlug, Instant earliest, Instant latest) throws QException
   {
      String id = uuid(eventId, false);
      if(flowSlug == null || !flowSlug.matches("[A-Za-z0-9_-]{1,100}") || earliest == null || latest == null || latest.isBefore(earliest))
      {
         throw (new IllegalArgumentException());
      }
      JSONObject event = client.syncEvent(id);
      if(event == null || !id.equals(uuid(event.get("pk"), false)) || !action.equals(event.get("action"))
         || !(event.get("created") instanceof String timestamp))
      {
         throw (new IllegalArgumentException());
      }
      Instant created = Instant.parse(timestamp);
      Object path = event.getJSONObject("context").getJSONObject("http_request").get("path");
      if(created.isBefore(earliest) || created.isAfter(latest)
         || !("/api/v3/flows/executor/" + flowSlug + "/").equals(path))
      {
         throw (new IllegalArgumentException());
      }
      return (event);
   }

   /***************************************************************************
    ** Native invitation context uses UUID.hex; event IDs use canonical UUIDs.
    ** Reject Java UUID parsing's abbreviated forms and arbitrary coercions.
    ***************************************************************************/
   private static String uuid(Object value, boolean allowHex)
   {
      if(!(value instanceof String text))
      {
         throw (new IllegalArgumentException());
      }
      if(allowHex && text.matches("[0-9a-fA-F]{32}"))
      {
         text = text.substring(0, 8) + "-" + text.substring(8, 12) + "-" + text.substring(12, 16) + "-" + text.substring(16, 20) + "-" + text.substring(20);
      }
      UUID parsed = UUID.fromString(text);
      if(!parsed.toString().equalsIgnoreCase(text))
      {
         throw (new IllegalArgumentException());
      }
      return (parsed.toString());
   }
}
