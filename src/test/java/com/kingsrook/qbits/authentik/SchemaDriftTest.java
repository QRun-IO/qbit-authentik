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

package com.kingsrook.qbits.authentik;


import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.kingsrook.qbits.authentik.client.AuthentikApiSurface;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.LoaderOptions;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Schema drift test (DESIGN.md section 10): every operation and query
 ** parameter the qbit uses exists in the Authentik OpenAPI schema.
 **
 ** By default it reads the pinned 2026.8.3 schema
 ** (src/test/resources/authentik/schema-2026.8.3.yml, fetched unauthenticated
 ** from https://auth.kof22.com/api/v3/schema/). The scheduled schema-drift
 ** workflow runs it with -Dauthentik.schema.file=<newer release schema>.
 *******************************************************************************/
public class SchemaDriftTest
{
   public static final String PINNED_VERSION = "2026.8.3";



   /*******************************************************************************
    ** Parse an OpenAPI YAML file (the schema is ~1.8 MB).
    *******************************************************************************/
   public static JsonNode loadSchema(String text) throws IOException
   {
      LoaderOptions options = new LoaderOptions();
      options.setCodePointLimit(64 * 1024 * 1024);
      YAMLFactory factory = YAMLFactory.builder().loaderOptions(options).build();
      return (new ObjectMapper(factory).readTree(text));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static JsonNode schemaUnderTest() throws IOException
   {
      String file = System.getProperty("authentik.schema.file");
      if(file != null && !file.isBlank())
      {
         return (loadSchema(java.nio.file.Files.readString(new File(file).toPath())));
      }
      return (loadSchema(AuthentikTestSupport.resource("authentik/schema-" + PINNED_VERSION + ".yml")));
   }



   /*******************************************************************************
    ** The pinned file is the version we claim.
    *******************************************************************************/
   @Test
   void pinnedSchemaIsTheTestedVersion() throws IOException
   {
      JsonNode schema = loadSchema(AuthentikTestSupport.resource("authentik/schema-" + PINNED_VERSION + ".yml"));
      assertThat(schema.at("/info/version").asText()).isEqualTo(PINNED_VERSION);
   }



   /*******************************************************************************
    ** Every used operation and parameter exists.
    *******************************************************************************/
   @Test
   void everyUsedOperationAndParameterExists() throws IOException
   {
      List<String> problems = findDrift(schemaUnderTest());
      assertThat(problems).as("Authentik API drift").isEmpty();
   }



   /*******************************************************************************
    ** Compare the used surface against a schema; returns human-readable problems.
    *******************************************************************************/
   public static List<String> findDrift(JsonNode schema)
   {
      List<String> problems = new ArrayList<>();
      JsonNode     paths    = schema.get("paths");
      for(AuthentikApiSurface.Operation operation : AuthentikApiSurface.operations())
      {
         String   schemaPath = findPath(paths, operation.path());
         JsonNode op         = schemaPath == null ? null : paths.get(schemaPath).get(operation.method());
         if(op == null)
         {
            problems.add("missing operation " + operation.method().toUpperCase() + " " + operation.path());
            continue;
         }
         Set<String> available = parameterNames(schema, op);
         for(String param : operation.params())
         {
            if(!available.contains(param))
            {
               problems.add("missing parameter " + param + " on " + operation.method().toUpperCase() + " " + schemaPath);
            }
         }
      }
      return (problems);
   }



   /*******************************************************************************
    ** Parameters of an operation, resolving $refs.
    *******************************************************************************/
   public static Set<String> parameterNames(JsonNode schema, JsonNode operation)
   {
      Set<String> rs = new LinkedHashSet<>();
      for(JsonNode parameter : operation.path("parameters"))
      {
         JsonNode resolved = parameter;
         if(parameter.has("$ref"))
         {
            String ref = parameter.get("$ref").asText();
            resolved = schema.at(ref.substring(1));
         }
         rs.add(resolved.path("name").asText());
      }
      return (rs);
   }



   /*******************************************************************************
    ** Find the schema path for a surface path; "{key}" matches any {param}.
    *******************************************************************************/
   static String findPath(JsonNode paths, String surfacePath)
   {
      if(paths.has(surfacePath))
      {
         return (surfacePath);
      }
      String         regex = surfacePath.replace("{key}", "\\{[^/]+\\}");
      Iterator<Map.Entry<String, JsonNode>> fields = paths.fields();
      while(fields.hasNext())
      {
         String candidate = fields.next().getKey();
         if(candidate.matches(regex))
         {
            return (candidate);
         }
      }
      return (null);
   }

   /*******************************************************************************
    ** Login aggregation uses only parameters documented by the pinned schema.
    *******************************************************************************/
   @Test
   void tokenActivitySurfacePinsLoginOrderingWithoutUnsupportedDateFilter()
   {
      assertThat(AuthentikApiSurface.operations()).anySatisfy(operation ->
      {
         assertThat(operation.path()).isEqualTo("/events/events/");
         assertThat(operation.method()).isEqualTo("get");
         assertThat(operation.params()).contains("action", "ordering", "page", "page_size").doesNotContain("created__gt");
      });
   }

}
