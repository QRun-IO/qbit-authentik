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

package com.kingsrook.qbits.authentik.contract;


import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.json.JSONObject;


/*******************************************************************************
 ** Signs a user in through Authentik's default authentication flow (flow
 ** executor API), creating a real AuthenticatedSession and login event in the
 ** disposable test instance. Test-only.
 *******************************************************************************/
public final class FlowLogin
{
   private static final String FLOW = "default-authentication-flow";



   /*******************************************************************************
    ** Not instantiable.
    *******************************************************************************/
   private FlowLogin()
   {
   }



   /*******************************************************************************
    ** Run identification + password; returns the final challenge component
    ** (e.g. "xak-flow-redirect" on success).
    *******************************************************************************/
   public static String login(String baseUrl, String username, String password) throws Exception
   {
      HttpClient client = HttpClient.newBuilder()
         .version(HttpClient.Version.HTTP_1_1)
         .cookieHandler(new CookieManager())
         .followRedirects(HttpClient.Redirect.NORMAL)
         .connectTimeout(Duration.ofSeconds(10))
         .build();
      String executor = baseUrl + "/api/v3/flows/executor/" + FLOW + "/?query=";

      JSONObject challenge = send(client, HttpRequest.newBuilder(URI.create(executor)).GET());
      challenge = send(client, post(executor, new JSONObject().put("component", "ak-stage-identification").put("uid_field", username)));
      if("ak-stage-password".equals(challenge.optString("component")))
      {
         challenge = send(client, post(executor, new JSONObject().put("component", "ak-stage-password").put("password", password)));
      }
      return (challenge.optString("component"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static HttpRequest.Builder post(String url, JSONObject body)
   {
      return (HttpRequest.newBuilder(URI.create(url)).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body.toString())));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static JSONObject send(HttpClient client, HttpRequest.Builder request) throws Exception
   {
      HttpResponse<String> response = client.send(request.header("Accept", "application/json").timeout(Duration.ofSeconds(30)).build(), HttpResponse.BodyHandlers.ofString());
      return (response.body() == null || response.body().isBlank() || !response.body().trim().startsWith("{") ? new JSONObject() : new JSONObject(response.body()));
   }

}
