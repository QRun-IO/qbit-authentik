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

package com.kingsrook.qbits.authentik.client;


import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Tests for AuthentikRedactor.
 *******************************************************************************/
class AuthentikRedactorTest
{

   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void tokenAndBearerValuesAreMasked()
   {
      String text = "auth failed for token abc123secret with header Authorization: Bearer xyz.789-other";
      String safe = AuthentikRedactor.redactText(text, "abc123secret");
      assertThat(safe).doesNotContain("abc123secret").doesNotContain("xyz.789-other").contains("Bearer ******");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void secretLookingJsonValuesAreMasked()
   {
      String body = "{\"identifier\":\"t\",\"key\":\"s3cr3t\",\"link\":\"https://x/recover?token=abc\",\"Password\":\"p\\\"w\",\"name\":\"ok\"}";
      String safe = AuthentikRedactor.redactText(body, null);
      assertThat(safe).doesNotContain("s3cr3t").doesNotContain("recover?token").doesNotContain("p\\\"w").contains("\"name\":\"ok\"").contains("\"key\":\"******\"");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void sensitiveEndpointBodiesAreDropped()
   {
      assertThat(AuthentikRedactor.redactBody("/api/v3/core/users/4/recovery_email/", "{\"email_stage\":\"x\"}", null)).doesNotContain("email_stage");
      assertThat(AuthentikRedactor.redactBody("/api/v3/core/tokens/abc/view_key/", "{\"key\":\"k\"}", null)).contains("omitted");
      assertThat(AuthentikRedactor.redactBody("/api/v3/core/users/", "{\"username\":\"u\"}", null)).contains("\"username\":\"u\"");
      assertThat(AuthentikRedactor.redactBody("/api/v3/core/users/", null, null)).isNull();
      assertThat(AuthentikRedactor.redactText(null, "t")).isNull();
      assertThat(AuthentikRedactor.isSensitivePath(null)).isFalse();
   }


   /*******************************************************************************
    ** Broker and one-time credential fields are masked even in unrelated text.
    *******************************************************************************/
   @Test
   void allTokenFieldsAreMasked()
   {
      for(String name : java.util.List.of("key", "token", "access_token", "subject_token", "client_secret"))
      {
         String json = new org.json.JSONObject().put(name, "credential-to-hide").toString();
         assertThat(AuthentikRedactor.redactText("prefix " + json + " suffix", null)).doesNotContain("credential-to-hide").contains("******");
      }
   }

}
