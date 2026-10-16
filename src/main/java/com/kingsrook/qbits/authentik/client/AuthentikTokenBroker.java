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


import java.nio.charset.StandardCharsets;
import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.security.WriteAuthorization;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;


/*******************************************************************************
 ** RFC 8693 exchange for a two-minute API bearer, never cached or logged.
 *******************************************************************************/
public class AuthentikTokenBroker
{
   /*******************************************************************************
    ** Exchange the operator's JWT through the configured protected-user broker.
    *******************************************************************************/
   public String exchange(AuthentikActionUtil util, WriteAuthorization auth) throws QException
   {
      AuthentikQBitConfig config = util.getRuntime().getConfig();
      String subject = config.getSubjectTokenSource().subjectToken(QContext.getQSession());
      HttpPost request = new HttpPost(config.getTokenEndpointUrl());
      request.setEntity(new UrlEncodedFormEntity(List.of(
         new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
         new BasicNameValuePair("client_id", config.getTokenBrokerClientId()),
         new BasicNameValuePair("client_secret", config.getTokenBrokerClientSecret()),
         new BasicNameValuePair("subject_token", subject),
         new BasicNameValuePair("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
         new BasicNameValuePair("scope", "goauthentik.io/api")), StandardCharsets.UTF_8));
      JSONObject result = util.exchangeToken(auth, request);
      String bearer = result.optString("access_token", "");
      if(bearer.isBlank())
      {
         throw (new QUserFacingException("Authentik refused to act as you (invalid_response)"));
      }
      return (bearer);
   }



   /*******************************************************************************
    ** Prove the broker's client credentials with the grant it actually uses
    ** (token exchange), without a subject token, so nothing is issued and no
    ** user data is sent. Authentik checks the grant type, then the client
    ** secret, then the subject: invalid_request (missing subject) means both
    ** passed; invalid_client means a bad secret; invalid_grant means the
    ** provider does not allow token exchange.
    *******************************************************************************/
   public void probeCredentials(AuthentikActionUtil util) throws QException
   {
      AuthentikQBitConfig config = util.getRuntime().getConfig();
      HttpPost request = new HttpPost(config.getTokenEndpointUrl());
      request.setEntity(new UrlEncodedFormEntity(List.of(
         new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
         new BasicNameValuePair("client_id", config.getTokenBrokerClientId()),
         new BasicNameValuePair("client_secret", config.getTokenBrokerClientSecret())), StandardCharsets.UTF_8));
      String code;
      try
      {
         util.requestBrokerCredentials(request);
         code = "issued";
      }
      catch(BrokerRefusedException e)
      {
         code = e.getErrorCode();
      }
      switch(code)
      {
         case "invalid_request" ->
         {
            return;
         }
         case "invalid_client" -> throw (new QUserFacingException("Authentik rejected the token broker's client credentials"));
         case "invalid_grant", "unsupported_grant_type" -> throw (new QUserFacingException("The token broker's Authentik provider does not allow token exchange"));
         default -> throw (new QUserFacingException("Authentik answered the token broker probe unexpectedly (" + code + ")"));
      }
   }
}
