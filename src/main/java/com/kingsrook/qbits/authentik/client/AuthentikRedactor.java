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


import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/*******************************************************************************
 ** Redaction for anything the qbit logs or stores about Authentik calls
 ** (DESIGN.md section 9.1):
 ** - the bearer token is never logged (it is replaced wherever it appears);
 ** - bodies of sensitive endpoints (recovery, tokens, passwords, service-account
 **   creation, user create) are dropped entirely;
 ** - in any other body, values of JSON keys that look like secrets (key, token,
 **   link, password, secret, client_secret) are masked.
 *******************************************************************************/
public final class AuthentikRedactor
{
   public static final String MASK = "******";

   /** Path fragments whose request and response bodies are never logged. */
   private static final List<String> SENSITIVE_PATH_FRAGMENTS = List.of(
      "/recovery", "/recovery_email", "/set_password", "/set_password_hash", "/core/tokens/", "/service_account", "/impersonate", "/view_key", "/set_key");

   private static final Pattern SECRET_JSON_VALUE = Pattern.compile(
      "(\"(?:key|token|link|password|secret|client_secret|password_hash|recovery_link)\"\\s*:\\s*)\"((?:[^\"\\\\]|\\\\.)*)\"", Pattern.CASE_INSENSITIVE);

   private static final Pattern BEARER = Pattern.compile("(?i)(bearer\\s+)[A-Za-z0-9._~+/=-]+");



   /*******************************************************************************
    ** Not instantiable.
    *******************************************************************************/
   private AuthentikRedactor()
   {
   }



   /*******************************************************************************
    ** Whether bodies for this path must never be logged.
    *******************************************************************************/
   public static boolean isSensitivePath(String path)
   {
      if(path == null)
      {
         return (false);
      }
      for(String fragment : SENSITIVE_PATH_FRAGMENTS)
      {
         if(path.contains(fragment))
         {
            return (true);
         }
      }
      return (false);
   }



   /*******************************************************************************
    ** Redact a request or response body for logging.
    **
    ** @param path  the request path (decides whether to drop the body)
    ** @param body  the body (may be null)
    ** @param token the bearer token in use (may be null)
    *******************************************************************************/
   public static String redactBody(String path, String body, String token)
   {
      if(body == null)
      {
         return (null);
      }
      if(isSensitivePath(path))
      {
         return ("[body omitted: sensitive endpoint]");
      }
      return (redactText(body, token));
   }



   /*******************************************************************************
    ** Redact free text (exception messages, log lines): the token, bearer
    ** values and secret-looking JSON values.
    *******************************************************************************/
   public static String redactText(String text, String token)
   {
      if(text == null)
      {
         return (null);
      }

      String safe = text;
      if(token != null && !token.isBlank())
      {
         safe = safe.replace(token, MASK);
      }
      safe = BEARER.matcher(safe).replaceAll("$1" + MASK);

      Matcher       matcher = SECRET_JSON_VALUE.matcher(safe);
      StringBuilder rs      = new StringBuilder();
      while(matcher.find())
      {
         matcher.appendReplacement(rs, Matcher.quoteReplacement(matcher.group(1) + "\"" + MASK + "\""));
      }
      matcher.appendTail(rs);
      return (rs.toString());
   }

}
