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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import com.fasterxml.jackson.databind.JsonNode;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import com.kingsrook.qbits.authentik.SchemaDriftTest;
import com.kingsrook.qbits.authentik.client.AuthentikApiSurface;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** The schema the running container serves (unauthenticated, as for the
 ** pinned file) has the same parameters as the pinned schema for every
 ** operation the qbit uses. Run with -Dauthentik.test.image=... to rehearse an
 ** upgrade: any difference fails with a list.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(20)
class SchemaDriftIT
{

   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void containerSchemaMatchesPinnedForUsedOperations() throws Exception
   {
      AuthentikTestStack stack = AuthentikTestStack.get();
      HttpResponse<String> response = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build().send(
         HttpRequest.newBuilder(URI.create(stack.apiRoot() + "/schema/")).header("Accept", "application/yaml").build(),
         HttpResponse.BodyHandlers.ofString());
      assertThat(response.statusCode()).isEqualTo(200);

      JsonNode live   = SchemaDriftTest.loadSchema(response.body());
      JsonNode pinned = SchemaDriftTest.loadSchema(AuthentikTestSupport.resource("authentik/schema-" + SchemaDriftTest.PINNED_VERSION + ".yml"));

      assertThat(SchemaDriftTest.findDrift(live)).isEmpty();

      List<String> differences = new ArrayList<>();
      for(AuthentikApiSurface.Operation operation : AuthentikApiSurface.operations())
      {
         Set<String> liveParams   = params(live, operation);
         Set<String> pinnedParams = params(pinned, operation);
         if(!liveParams.equals(pinnedParams))
         {
            differences.add(operation.path() + ": pinned " + pinnedParams + " vs running " + liveParams);
         }
      }
      assertThat(differences).as("parameter differences between the pinned and the running schema").isEmpty();
      assertThat(live.at("/info/version").asText()).isEqualTo(System.getProperty("authentik.expected.version", SchemaDriftTest.PINNED_VERSION));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static Set<String> params(JsonNode schema, AuthentikApiSurface.Operation operation)
   {
      String path = operation.path();
      JsonNode paths = schema.get("paths");
      for(java.util.Iterator<String> it = paths.fieldNames(); it.hasNext(); )
      {
         String candidate = it.next();
         if(candidate.equals(path) || candidate.matches(path.replace("{key}", "\\{[^/]+\\}")))
         {
            return (SchemaDriftTest.parameterNames(schema, paths.get(candidate).get(operation.method())));
         }
      }
      return (Set.of());
   }

}
