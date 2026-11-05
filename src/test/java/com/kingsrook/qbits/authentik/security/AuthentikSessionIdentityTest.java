/*
 * Copyright 2026 Kingsrook, LLC
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kingsrook.qbits.authentik.security;

import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 ** Parsing cannot turn mutable references or coercible values into identities.
 ******************************************************************************/
class AuthentikSessionIdentityTest
{
   private static final String UUID = "00000000-0000-4000-8000-000000000abc";

   /***************************************************************************
    ** Both source identifiers are required; email/subject changes are irrelevant.
    ***************************************************************************/
   @Test
   void stableIdentityComesOnlyFromTheExplicitClaim()
   {
      JSONObject claims = new JSONObject().put("sub", "old@example.test").put("email", "old@example.test")
         .put(AuthentikSessionIdentity.CLAIM, new JSONObject().put("pk", 42).put("uuid", UUID.toUpperCase(java.util.Locale.ROOT)));
      var expected = new AuthentikSessionIdentity(42, UUID);
      assertThat(AuthentikSessionIdentity.fromVerifiedClaims(claims)).contains(expected);
      claims.put("sub", "new@example.test").put("email", "new@example.test").put("preferred_username", "renamed");
      assertThat(AuthentikSessionIdentity.fromVerifiedClaims(claims)).contains(expected);
      claims.remove(AuthentikSessionIdentity.CLAIM);
      assertThat(AuthentikSessionIdentity.fromVerifiedClaims(claims)).isEmpty();
      assertThat(AuthentikSessionIdentity.fromVerifiedClaims(null)).isEmpty();
   }

   /***************************************************************************
    ** No string/number coercion, truncation or permissive short UUID parsing.
    ***************************************************************************/
   @Test
   void malformedOrIncompleteClaimsFailClosed()
   {
      for(Object pk : List.of("42", 42.0, 0, -1, 2147483648L, true, JSONObject.NULL))
      {
         assertThat(AuthentikSessionIdentity.fromVerifiedClaims(new JSONObject().put(AuthentikSessionIdentity.CLAIM,
            new JSONObject().put("pk", pk).put("uuid", UUID)))).isEmpty();
      }
      for(Object uuid : List.of("", "1-1-1-1-1", " " + UUID, 42, JSONObject.NULL))
      {
         assertThat(AuthentikSessionIdentity.fromVerifiedClaims(new JSONObject().put(AuthentikSessionIdentity.CLAIM,
            new JSONObject().put("pk", 42).put("uuid", uuid)))).isEmpty();
      }
      for(Object claim : List.of("42", new JSONArray(), new JSONObject(), new JSONObject().put("pk", 42), JSONObject.NULL))
      {
         assertThat(AuthentikSessionIdentity.fromVerifiedClaims(new JSONObject().put(AuthentikSessionIdentity.CLAIM, claim))).isEmpty();
      }
   }
}
