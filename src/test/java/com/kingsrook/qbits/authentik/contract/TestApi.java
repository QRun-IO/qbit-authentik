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


import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Minimal Authentik API client for contract tests, acting as one token's
 ** user (the test-only bootstrap admin, or the qbit's service account). Used
 ** for setup and for asserting Authentik's own behaviour; the qbit's code
 ** path is AuthentikActionUtil.
 **
 ** Only ever points at the disposable Testcontainers instance.
 *******************************************************************************/
public class TestApi
{
   private static final HttpClient CLIENT = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(10)).build();

   private final String apiRoot;
   private final String token;



   /*******************************************************************************
    ** Response: status plus raw body.
    *******************************************************************************/
   public record Response(int status, String body)
   {
      /*******************************************************************************
       ** Body as a JSON object (empty object for an empty body).
       *******************************************************************************/
      public JSONObject json()
      {
         return (body == null || body.isBlank() ? new JSONObject() : new JSONObject(body));
      }



      /*******************************************************************************
       ** Shorthand for json().getJSONArray("results").
       *******************************************************************************/
      public JSONArray results()
      {
         return (json().getJSONArray("results"));
      }
   }



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   public TestApi(String apiRoot, String token)
   {
      this.apiRoot = apiRoot;
      this.token = token;
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   public Response get(String path)
   {
      return (send("GET", path, null));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   public Response post(String path, Object body)
   {
      return (send("POST", path, body));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   public Response patch(String path, Object body)
   {
      return (send("PATCH", path, body));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   public Response delete(String path)
   {
      return (send("DELETE", path, null));
   }



   /*******************************************************************************
    ** GET that must succeed, as JSON.
    *******************************************************************************/
   public JSONObject getOk(String path)
   {
      Response response = get(path);
      if(response.status() != 200)
      {
         throw (new IllegalStateException("GET " + path + " -> " + response.status() + ": " + response.body()));
      }
      return (response.json());
   }



   /*******************************************************************************
    ** The first result of a list GET, or null.
    *******************************************************************************/
   public JSONObject first(String path)
   {
      JSONArray results = getOk(path).getJSONArray("results");
      return (results.isEmpty() ? null : results.getJSONObject(0));
   }



   /*******************************************************************************
    ** pk of a group by name.
    *******************************************************************************/
   public String groupPk(String name)
   {
      JSONObject group = first("/core/groups/?name=" + encode(name));
      if(group == null)
      {
         throw (new IllegalStateException("No group " + name));
      }
      return (group.getString("pk"));
   }



   /*******************************************************************************
    ** pk of a user by username.
    *******************************************************************************/
   public int userPk(String username)
   {
      JSONObject user = first("/core/users/?username=" + encode(username));
      if(user == null)
      {
         throw (new IllegalStateException("No user " + username));
      }
      return (user.getInt("pk"));
   }



   /*******************************************************************************
    ** URL-encode a query value.
    *******************************************************************************/
   public static String encode(String value)
   {
      return (URLEncoder.encode(value, StandardCharsets.UTF_8));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private Response send(String method, String path, Object body)
   {
      try
      {
         HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(apiRoot + path))
            .timeout(Duration.ofSeconds(60))
            .header("Authorization", "Bearer " + token)
            .header("Accept", "application/json");
         if(body != null)
         {
            builder.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body.toString()));
         }
         else
         {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
         }
         HttpResponse<String> response = CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString());
         return (new Response(response.statusCode(), response.body()));
      }
      catch(Exception e)
      {
         throw (new IllegalStateException(method + " " + path + " failed: " + e.getMessage(), e));
      }
   }

}
