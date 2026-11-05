/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.admin;

import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.module.api.model.metadata.APIBackendMetaData;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Native event facts fail closed on forged hints, wrong identities and edits.
 *******************************************************************************/
class AuthentikInvitationEvidenceTest
{
   private static final String EVENT = "61000000-0000-0000-0000-000000000001";
   private static final String INVITATION = "62000000-0000-0000-0000-000000000002";
   private static final String REFERENCE = "63000000-0000-0000-0000-000000000003";
   private static final Instant START = Instant.parse("2026-11-05T00:00:00Z");
   private FixtureActionUtil client;
   private AuthentikInvitationEvidence evidence;
   private JSONObject response;

   /***************************************************************************
    ** Production guarded client with only HTTP transport replaced.
    ***************************************************************************/
   @BeforeEach
   void setup() throws Exception
   {
      FixtureActionUtil.reset();
      var config = AuthentikTestSupport.unitConfig().withListCacheTtlSeconds(300);
      var instance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.loginWith(instance, IdentityPermission.AUDIT_READ);
      client = new FixtureActionUtil();
      client.setBackendMetaData((APIBackendMetaData) instance.getBackend(config.getApiBackendName()));
      evidence = new AuthentikInvitationEvidence(client);
      var configuration = AuthentikInvitationFlowTest.configuration();
      FixtureActionUtil.handler = request ->
      {
         var body = configuration.getOrDefault(request.getURI().getPath(), response);
         return (body == null ? FixtureActionUtil.response(404, "{}") : FixtureActionUtil.response(200, body.toString()));
      };
   }

   /***************************************************************************
    ** No authenticated context or test handler escapes this fixture.
    ***************************************************************************/
   @AfterEach
   void cleanup()
   {
      QContext.clear();
      FixtureActionUtil.reset();
   }

   /***************************************************************************
    ** Only native facts escape; arbitrary event permissions are never returned.
    ***************************************************************************/
   @Test
   void readsConsumptionAndNewUserFactsWithoutCaching() throws Exception
   {
      response = event("invitation_used");
      response.getJSONObject("context").put("invitation_uuid", INVITATION.replace("-", ""));
      assertThat(evidence.consumed(EVENT, INVITATION, "enroll", START, START.plusSeconds(60)).invitationId()).isEqualTo(INVITATION);
      response = event("user_write");
      response.getJSONObject("context").put("permissions", List.of("authentik.*"));
      var enrolled = evidence.enrolled(EVENT, REFERENCE, "enroll", START, START.plusSeconds(60));
      assertThat(enrolled.userPk()).isEqualTo(12);
      assertThat(enrolled.reference()).isEqualTo(REFERENCE);
      assertThat(enrolled.createdAt()).isEqualTo(START.plusSeconds(1));
      response = null;
      assertThatThrownBy(() -> evidence.enrolled(EVENT, REFERENCE, "enroll", START, START.plusSeconds(60))).isInstanceOf(QException.class);
   }

   /***************************************************************************
    ** Wrong source identity, action, flow, time, correlation and edited accounts
    ** must not be mistaken for the requested enrollment.
    ***************************************************************************/
   @Test
   void rejectsMismatchedAndAmbiguousEnrollment()
   {
      List<Consumer<JSONObject>> mutations = List.of(
         value -> value.put("pk", INVITATION),
         value -> value.put("action", "custom_user_write"),
         value -> value.put("created", START.minusSeconds(1).toString()),
         value -> value.put("created", START.plusSeconds(61).toString()),
         value -> value.getJSONObject("context").getJSONObject("http_request").put("path", "/api/v3/flows/executor/other/"),
         value -> value.getJSONObject("context").put(AuthentikInvitationEvidence.REFERENCE, INVITATION),
         value -> value.getJSONObject("context").put("created", false),
         value -> value.getJSONObject("context").put("created", "true"),
         value -> value.getJSONObject("user").put("pk", 1.5),
         value -> value.getJSONObject("user").put("pk", 0),
         value -> value.getJSONObject("user").put("pk", "12"),
         value -> value.getJSONObject("user").put("on_behalf_of", new JSONObject()),
         value -> value.getJSONObject("user").put("authenticated_as", new JSONObject()),
         value -> value.remove("context"));
      for(var mutation : mutations)
      {
         response = event("user_write");
         mutation.accept(response);
         assertThatThrownBy(() -> evidence.enrolled(EVENT, REFERENCE, "enroll", START, START.plusSeconds(60)))
            .isInstanceOf(QException.class).hasMessage("Invitation enrollment evidence could not be verified.").hasNoCause();
      }
   }

   /***************************************************************************
    ** Consumption must identify the saved invitation, not the event's actor.
    ***************************************************************************/
   @Test
   void rejectsWrongConsumptionAndInvalidLookupIds()
   {
      response = event("invitation_used");
      response.getJSONObject("context").put("invitation_uuid", REFERENCE);
      assertThatThrownBy(() -> evidence.consumed(EVENT, INVITATION, "enroll", START, START.plusSeconds(60)))
         .isInstanceOf(QException.class).hasNoCause();
      int requests = FixtureActionUtil.REQUESTS.size();
      assertThatThrownBy(() -> evidence.enrolled("1-1-1-1-1", REFERENCE, "enroll", START, START.plusSeconds(60)))
         .isInstanceOf(QException.class);
      assertThat(FixtureActionUtil.REQUESTS).hasSize(requests);
   }

   /***************************************************************************
    ** Direct client access checks audit permission before any network request.
    ***************************************************************************/
   @Test
   void directEventReadRetainsGuard() throws Exception
   {
      AuthentikTestSupport.loginWith(QContext.getQInstance(), IdentityPermission.USERS_READ);
      assertThatThrownBy(() -> client.syncEvent(EVENT)).isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException.class);
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
   }

   /***************************************************************************
    ** Synthetic form matching the pinned native event schema.
    ***************************************************************************/
   private JSONObject event(String action)
   {
      return (new JSONObject().put("pk", EVENT).put("action", action).put("created", START.plusSeconds(1).toString())
         .put("user", new JSONObject().put("pk", 12))
         .put("context", new JSONObject().put("created", true).put(AuthentikInvitationEvidence.REFERENCE, REFERENCE)
            .put("http_request", new JSONObject().put("path", "/api/v3/flows/executor/enroll/"))));
   }
}
