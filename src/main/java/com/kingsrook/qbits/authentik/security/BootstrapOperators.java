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


import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import org.json.JSONObject;


/*******************************************************************************
 ** Decides whether a person is a bootstrap operator (the lockout escape hatch).
 ** Users can change their own email in Authentik and emails are not unique, so
 ** an email is NEVER enough. Someone is a bootstrap operator only when:
 ** - the token sub is a configured subject (a hashed or opaque id; a sub that
 **   looks like an email is ignored, since Authentik's user_email sub mode makes
 **   it mutable); or
 ** - the email is verified, exactly ONE Authentik user has it, that user is
 **   active, and that user's pk or uuid is a configured subject.
 ** Anything else is denied.
 *******************************************************************************/
public final class BootstrapOperators
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private BootstrapOperators()
   {
   }



   /*******************************************************************************
    ** Whether a token (sub, email, email_verified) is a bootstrap operator.
    **
    ** @param subjects      the configured immutable subjects
    ** @param client        an Authentik client for the lookup
    ** @param sub           the sub claim (may be null)
    ** @param email         the email claim (may be null)
    ** @param emailVerified the email_verified claim
    *******************************************************************************/
   public static boolean matches(Set<String> subjects, AuthentikActionUtil client, String sub, String email, boolean emailVerified)
   {
      if(subjects == null || subjects.isEmpty())
      {
         return (false);
      }
      if(sub != null && !sub.isBlank() && !sub.contains("@") && subjects.contains(sub.trim()))
      {
         return (true);
      }
      if(!emailVerified || email == null || email.isBlank() || client == null)
      {
         return (false);
      }
      return (matchesUniqueUser(subjects, client, email.trim()));
   }



   /*******************************************************************************
    ** The email-based path without the verified claim (an admin session has no
    ** claims): still requires exactly one active user with that email whose pk
    ** or uuid is a configured subject.
    *******************************************************************************/
   public static boolean matchesUniqueUser(Set<String> subjects, AuthentikActionUtil client, String email)
   {
      if(subjects == null || subjects.isEmpty())
      {
         return (false);
      }
      try
      {
         JSONObject found = null;
         int        count = 0;
         for(JSONObject user : client.getAllPages("/core/users/?email=" + URLEncoder.encode(email, StandardCharsets.UTF_8) + "&include_groups=false&include_roles=false", 10))
         {
            if(email.equalsIgnoreCase(user.optString("email")))
            {
               found = user;
               count++;
            }
         }
         return (count == 1 && found.optBoolean("is_active", true)
            && (subjects.contains(String.valueOf(found.optInt("pk"))) || subjects.contains(found.optString("uuid", "-"))));
      }
      catch(Exception e)
      {
         return (false);
      }
   }

}
