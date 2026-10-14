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
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.OAuth2AuthenticationMetaData;


/*******************************************************************************
 ** Usage instructions held exclusively inside the one-time response.
 *******************************************************************************/
public final class TokenUsageText
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private TokenUsageText()
   {
   }



   /*******************************************************************************
    ** Generate shell-quoted exchange and application requests from public URLs.
    *******************************************************************************/
   public static String build(AuthentikQBitConfig config, String username, String key, Instant expires, String scope)
   {
      String clientId = config.getAppClientId();
      if(clientId == null && QContext.getQInstance().getAuthentication() instanceof OAuth2AuthenticationMetaData oauth)
      {
         clientId = oauth.getClientId();
      }
      String endpoint = config.getAuthentikPublicUrl().replaceAll("/+$", "") + "/application/o/token/";
      String app = config.getAppPublicUrl() == null ? "{appPublicUrl}" : config.getAppPublicUrl().replaceAll("/+$", "");
      return ("Expires: " + expires + "\nScope: " + scope + "\n\n"
         + "curl -X POST " + quote(endpoint) + " --data-urlencode 'grant_type=client_credentials'"
         + " --data-urlencode " + quote("client_id=" + (clientId == null ? "{appClientId}" : clientId))
         + " --data-urlencode " + quote("username=" + username) + " --data-urlencode " + quote("password=" + key)
         + " --data-urlencode 'scope=openid profile email'\n\n"
         + "curl -H 'Authorization: Bearer {jwt}' " + quote(app + "/qqq/v1/metaData"));
   }



   /*******************************************************************************
    ** Quote literal shell arguments, including usernames containing apostrophes.
    *******************************************************************************/
   private static String quote(String value)
   {
      return ("'" + value.replace("'", "'\"'\"'") + "'");
   }
}
