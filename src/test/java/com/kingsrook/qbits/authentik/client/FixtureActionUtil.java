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


import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qqq.backend.module.api.actions.QHttpResponse;
import org.apache.http.Header;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.message.BasicHeader;


/*******************************************************************************
 ** AuthentikActionUtil with the network replaced: requests are captured and
 ** answered by a handler (usually serving recorded 2026.8.3 fixtures).
 *******************************************************************************/
public class FixtureActionUtil extends AuthentikActionUtil
{
   public static final List<HttpRequestBase> REQUESTS = new ArrayList<>();

   public static Function<HttpRequestBase, QHttpResponse> handler = r -> response(404, "{\"detail\":\"Not found.\"}");



   /*******************************************************************************
    ** Reset captured requests and the handler.
    *******************************************************************************/
   public static void reset()
   {
      REQUESTS.clear();
      handler = r -> response(404, "{\"detail\":\"Not found.\"}");
      AuthentikActionUtil.resetVersionCheck();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   protected QHttpResponse send(HttpRequestBase request)
   {
      REQUESTS.add(request);
      if(request.getURI().getPath().endsWith("/admin/version/"))
      {
         return (response(200, AuthentikTestSupport.resource("fixtures/2026.8.3/admin-version.json")));
      }
      return (handler.apply(request));
   }



   /*******************************************************************************
    ** Build a response.
    *******************************************************************************/
   public static QHttpResponse response(int status, String body, Header... headers)
   {
      return (new QHttpResponse().withStatusCode(status).withContent(body).withHeaderList(List.of(headers)));
   }



   /*******************************************************************************
    ** A Retry-After header.
    *******************************************************************************/
   public static Header retryAfter(int seconds)
   {
      return (new BasicHeader("Retry-After", String.valueOf(seconds)));
   }



   /*******************************************************************************
    ** A recorded fixture.
    *******************************************************************************/
   public static String fixture(String name)
   {
      return (AuthentikTestSupport.resource("fixtures/2026.8.3/" + name + ".json"));
   }

}
