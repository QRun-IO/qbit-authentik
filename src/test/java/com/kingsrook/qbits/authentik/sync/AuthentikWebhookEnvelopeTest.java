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

import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Webhook authentication precedes parsing; persisted hints exclude context.
 *******************************************************************************/
class AuthentikWebhookEnvelopeTest
{
   /*******************************************************************************
    ** Synthetic transport payload using the pinned blueprint's shape.
    *******************************************************************************/
   private JSONObject payload()
   {
      return (new JSONObject().put("eventPk", "12e3a01f-5db1-4da9-a3a8-1b6acd198c21")
         .put("action", "model_updated").put("created", "2026-11-04T12:00:00-06:00")
         .put("username", "operator").put("app", "authentik_core")
         .put("model", new JSONObject().put("app", "authentik_core").put("model_name", "user").put("pk", 123)));
   }

   /*******************************************************************************
    ** Real mappings may include extra event/model fields; none reach storage.
    *******************************************************************************/
   @Test
   void stripsContextAndAcceptsNumericUserKeys()
   {
      JSONObject body = payload().put("context", new JSONObject().put("password", "do-not-retain")).put("client_ip", "192.0.2.1");
      body.getJSONObject("model").put("attributes", new JSONObject().put("secret", "do-not-retain"));
      var envelope = AuthentikWebhookEnvelope.receive("test-secret", "test-secret", body.toString().getBytes(StandardCharsets.UTF_8));
      assertThat(envelope.modelPk()).isEqualTo("123");
      assertThat(envelope.created().toString()).isEqualTo("2026-11-04T18:00:00Z");
      assertThat(envelope.storageJson()).doesNotContain("password", "secret", "context", "attributes", "client_ip", "192.0.2.1");
      assertThat(new JSONObject(envelope.storageJson()).getJSONObject("model").keySet()).containsExactlyInAnyOrder("app", "model_name", "pk");
   }

   /*******************************************************************************
    ** Wrong or absent secrets cannot reach JSON parsing, even with bad bodies.
    *******************************************************************************/
   @Test
   void rejectsAuthenticationBeforeParsing()
   {
      for(String supplied : new String[] { null, "", "wrong", "test-secret ", "x".repeat(4097) })
      {
         assertThatThrownBy(() -> AuthentikWebhookEnvelope.receive("test-secret", supplied, null))
            .isInstanceOf(SecurityException.class).hasMessage("Webhook authentication failed");
      }
      assertThatThrownBy(() -> AuthentikWebhookEnvelope.receive("", "", null)).isInstanceOf(IllegalStateException.class);
   }

   /*******************************************************************************
    ** Invalid envelopes report fixed errors without echoing input or causes.
    *******************************************************************************/
   @Test
   void rejectsInvalidUnboundedOrUnrelatedEvents()
   {
      for(JSONObject body : new JSONObject[] { payload().put("eventPk", "secret-value"), payload().put("action", "unknown"),
         payload().put("created", "secret-value"), payload().put("model", JSONObject.NULL), payload().put("username", new JSONObject()) })
      {
         assertThatThrownBy(() -> AuthentikWebhookEnvelope.receive("s", "s", body.toString().getBytes(StandardCharsets.UTF_8)))
            .isInstanceOf(IllegalArgumentException.class).hasMessage("Invalid webhook envelope").hasNoCause();
      }
      assertThatThrownBy(() -> AuthentikWebhookEnvelope.receive("s", "s", new byte[65537]))
         .isInstanceOf(IllegalArgumentException.class).hasMessage("Invalid webhook body size");
      JSONObject login = payload().put("action", "login");
      login.remove("model");
      assertThat(AuthentikWebhookEnvelope.receive("s", "s", login.toString().getBytes(StandardCharsets.UTF_8)).modelPk()).isNull();
      JSONObject invitation = payload().put("action", "invitation_used").put("model", new JSONObject()
         .put("app", "authentik_stages_invitation").put("model_name", "invitation").put("pk", "discard-this"));
      assertThat(AuthentikWebhookEnvelope.receive("s", "s", invitation.toString().getBytes(StandardCharsets.UTF_8)).storageJson())
         .doesNotContain("discard-this", "authentik_stages_invitation");
      invitation.put("action", "model_updated");
      assertThatThrownBy(() -> AuthentikWebhookEnvelope.receive("s", "s", invitation.toString().getBytes(StandardCharsets.UTF_8)))
         .isInstanceOf(IllegalArgumentException.class).hasMessage("Invalid webhook envelope");
   }
}
