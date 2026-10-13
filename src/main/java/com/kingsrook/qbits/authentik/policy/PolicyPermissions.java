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

package com.kingsrook.qbits.authentik.policy;


import java.util.Collections;
import java.util.Map;
import java.util.Set;
import org.json.JSONObject;


/*******************************************************************************
 ** Helpers a host's own authentication customizer can call to turn the policy
 ** claim of a sign-in token into QQQ permissions (docs/POLICY-FORMAT.md).
 *******************************************************************************/
public final class PolicyPermissions
{
   /** Customizer context key of the ID token claims (QQQ OAuth2 module). */
   public static final String ID_TOKEN_CONTEXT_KEY = "idToken";

   /** Customizer context key of the access token claims. */
   public static final String ACCESS_TOKEN_CONTEXT_KEY = "jwtPayloadJsonObject";



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private PolicyPermissions()
   {
   }



   /*******************************************************************************
    ** The permissions granted by the policy claim in these token claims; none
    ** when the claim is missing or invalid (fail closed).
    *******************************************************************************/
   public static Set<String> fromClaims(JSONObject claims, PolicyFormat format)
   {
      return (fromClaims(claims, format, null));
   }



   /*******************************************************************************
    ** Read a policy claim with the catalog of registered table features.
    *******************************************************************************/
   public static Set<String> fromClaims(JSONObject claims, PolicyFormat format, PolicyCatalog catalog)
   {
      PolicyFormat f = format == null ? PolicyFormat.DEFAULT : format;
      if(claims == null || !claims.has(f.claim()))
      {
         return (Collections.emptySet());
      }
      return (PolicyParser.parse(claims.opt(f.claim()), f, catalog));
   }



   /*******************************************************************************
    ** The claims that carry the policy in a customizer context: the ID token's
    ** when it has the claim (Authentik puts scope-mapping claims there), else the
    ** access token's (the only ones on a session resume). Null when neither has
    ** the claim.
    *******************************************************************************/
   public static JSONObject claimsWithPolicy(Map<String, Object> context, PolicyFormat format)
   {
      PolicyFormat f = format == null ? PolicyFormat.DEFAULT : format;
      if(context == null)
      {
         return (null);
      }
      for(String key : new String[] { ID_TOKEN_CONTEXT_KEY, ACCESS_TOKEN_CONTEXT_KEY })
      {
         JSONObject claims = asClaims(context.get(key));
         if(claims != null && claims.has(f.claim()))
         {
            return (claims);
         }
      }
      return (null);
   }



   /*******************************************************************************
    ** Claims as a JSONObject (QQQ passes a JSONObject; tests may pass a Map).
    *******************************************************************************/
   public static JSONObject asClaims(Object value)
   {
      if(value instanceof JSONObject object)
      {
         return (object);
      }
      if(value instanceof Map<?, ?> map)
      {
         return (new JSONObject(map));
      }
      return (null);
   }
}
