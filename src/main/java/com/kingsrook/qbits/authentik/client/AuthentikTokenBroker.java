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
    ** Request client credentials for health, then discard the bearer immediately.
    *******************************************************************************/
   public void probeClientCredentials(AuthentikActionUtil util) throws QException
   {
      AuthentikQBitConfig config = util.getRuntime().getConfig();
      HttpPost request = new HttpPost(config.getTokenEndpointUrl());
      request.setEntity(new UrlEncodedFormEntity(List.of(
         new BasicNameValuePair("grant_type", "client_credentials"),
         new BasicNameValuePair("client_id", config.getTokenBrokerClientId()),
         new BasicNameValuePair("client_secret", config.getTokenBrokerClientSecret()),
         new BasicNameValuePair("scope", "goauthentik.io/api")), StandardCharsets.UTF_8));
      if(util.requestBrokerCredentials(request).optString("access_token", "").isBlank())
      {
         throw (new QUserFacingException("Authentik broker returned no access token"));
      }
   }
}
