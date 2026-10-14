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

package com.kingsrook.qbits.authentik.admin;


import java.time.Instant;
import java.util.List;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Pin the fake's dangerous defaults independently of the qbit's safe requests.
 *******************************************************************************/
class FakeAuthentikTokenTest
{
   /*******************************************************************************
    ** Non-superuser create ignores an explicit other owner; keys are owner-only.
    *******************************************************************************/
   @Test
   void callerOwnsCreateAndKey()
   {
      FakeAuthentik fake = directory();
      HttpPost request = new HttpPost("https://example.test/api/v3/core/tokens/");
      request.setHeader("Authorization", "Bearer user-bearer:3");
      request.setEntity(new StringEntity(new JSONObject().put("identifier", "caller-owned").put("user", 6)
         .put("intent", "app_password").put("expires", Instant.now().plusSeconds(864000).toString()).toString(), ContentType.APPLICATION_JSON));
      JSONObject token = new JSONObject(fake.handle(request).getContent());
      assertThat(token.getInt("user")).isEqualTo(3);
      assertThat(Instant.parse(token.getString("expires"))).isBefore(Instant.now().plusSeconds(1801));
      HttpGet key = new HttpGet("https://example.test/api/v3/core/tokens/caller-owned/view_key/");
      assertThat(fake.handle(key).getStatusCode()).isEqualTo(403);
      key.setHeader("Authorization", "Bearer user-bearer:3");
      assertThat(fake.handle(key).getStatusCode()).isEqualTo(200);
      assertThat(token.has("key")).isFalse();
   }



   /*******************************************************************************
    ** Omitted PATCH intent/user really do cause a dangerous default transition.
    *******************************************************************************/
   @Test
   void patchDefaultsAndGroupLifetime()
   {
      FakeAuthentik fake = directory();
      fake.group("lifetime", false, List.of(), List.of());
      fake.groupByName("lifetime").getJSONObject("attributes").put("goauthentik.io/user/token-maximum-lifetime", "days=90");
      fake.groupByName("lifetime").getJSONArray("users").put(3);
      fake.seedToken("app-password", 3, "app_password", Instant.now().plusSeconds(86400).toString());
      HttpPatch patch = new HttpPatch("https://example.test/api/v3/core/tokens/app-password/");
      patch.setEntity(new StringEntity(new JSONObject().put("intent", "app_password").put("user", 3)
         .put("expires", Instant.now().plusSeconds(100 * 86400L).toString()).toString(), ContentType.APPLICATION_JSON));
      JSONObject updated = new JSONObject(fake.handle(patch).getContent());
      assertThat(updated.getInt("user")).isEqualTo(3);
      assertThat(updated.getString("intent")).isEqualTo("app_password");
      assertThat(Instant.parse(updated.getString("expires"))).isBefore(Instant.now().plusSeconds(90 * 86400L + 1));
      patch.setEntity(new StringEntity(new JSONObject().put("user", 6).toString(), ContentType.APPLICATION_JSON));
      assertThat(fake.handle(patch).getContent()).contains("User cannot be changed");
      patch.setEntity(new StringEntity("{}", ContentType.APPLICATION_JSON));
      updated = new JSONObject(fake.handle(patch).getContent());
      assertThat(updated.getInt("user")).isEqualTo(5);
      assertThat(updated.getString("intent")).isEqualTo("api");
      assertThat(Instant.parse(updated.getString("expires"))).isBefore(Instant.now().plusSeconds(1801));
   }



   /*******************************************************************************
    ** Minimal directory including the qbit's caller.
    *******************************************************************************/
   private FakeAuthentik directory()
   {
      return (new FakeAuthentik().user(3, "sam", "sam@example.test", "internal", true)
         .user(5, "qbit", "", "service_account", true).user(6, "service", "", "service_account", true));
   }
}
