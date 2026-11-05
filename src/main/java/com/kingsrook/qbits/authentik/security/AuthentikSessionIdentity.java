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
package com.kingsrook.qbits.authentik.security;

import java.util.Optional;
import java.util.UUID;
import org.json.JSONObject;

/*******************************************************************************
 ** Immutable source identity carried by the managed profile scope mapping.
 ** This parser does NOT authenticate a token. Only the OAuth module may supply
 ** claims after signature, issuer, audience and lifetime verification. Mutable
 ** sub/email/username claims are never used as an alternative identity source.
 ******************************************************************************/
public record AuthentikSessionIdentity(int pk, String uuid)
{
   public static final String CLAIM = "qqq_identity";

   /***************************************************************************
    ** Canonical identity shared with the mirror and persistent session binding.
    ***************************************************************************/
   public AuthentikSessionIdentity
   {
      if(pk < 1 || uuid == null || !UUID.fromString(uuid).toString().equalsIgnoreCase(uuid))
      {
         throw (new IllegalArgumentException("A positive Authentik pk and canonical UUID are required."));
      }
      uuid = UUID.fromString(uuid).toString();
   }

   /***************************************************************************
    ** Strict claim parsing: strings, floating point values, overflow, partial
    ** objects and unknown shapes cannot establish an identity. No coercion.
    ***************************************************************************/
   public static Optional<AuthentikSessionIdentity> fromVerifiedClaims(JSONObject claims)
   {
      if(claims == null || !(claims.opt(CLAIM) instanceof JSONObject identity))
      {
         return (Optional.empty());
      }
      Object pk = identity.opt("pk");
      Object uuid = identity.opt("uuid");
      if(!(pk instanceof Integer || pk instanceof Long) || !(uuid instanceof String text))
      {
         return (Optional.empty());
      }
      long number = ((Number) pk).longValue();
      if(number < 1 || number > Integer.MAX_VALUE)
      {
         return (Optional.empty());
      }
      try
      {
         return (Optional.of(new AuthentikSessionIdentity((int) number, text)));
      }
      catch(IllegalArgumentException malformed)
      {
         return (Optional.empty());
      }
   }
}
