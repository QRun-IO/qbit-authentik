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


import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import com.kingsrook.qbits.authentik.client.AuthentikRedactor;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Records real Authentik responses from contract tests as unit-test fixtures
 ** (DESIGN.md section 10). Always writes to target/recorded-fixtures/<version>;
 ** with -Dauthentik.fixtures.record=true it also refreshes
 ** src/test/resources/fixtures/<version>, which the unit tests read.
 **
 ** Scrubbing: avatars (data URIs) blanked, secret-looking values masked,
 ** ids left as they are (they come from a throwaway container).
 *******************************************************************************/
public final class FixtureRecorder
{
   public static final String VERSION = "2026.8.3";



   /*******************************************************************************
    ** Not instantiable.
    *******************************************************************************/
   private FixtureRecorder()
   {
   }



   /*******************************************************************************
    ** Scrub and save a JSON response under a name.
    *******************************************************************************/
   public static void record(String name, String body)
   {
      String scrubbed = scrub(body);
      write(Path.of("target", "recorded-fixtures", VERSION, name + ".json"), scrubbed);
      if(Boolean.getBoolean("authentik.fixtures.record"))
      {
         write(Path.of("src", "test", "resources", "fixtures", VERSION, name + ".json"), scrubbed);
      }
   }



   /*******************************************************************************
    ** Scrub a response body.
    *******************************************************************************/
   static String scrub(String body)
   {
      Object parsed = body.trim().startsWith("[") ? new JSONArray(body) : new JSONObject(body);
      scrubValue(parsed);
      String text = parsed instanceof JSONObject object ? object.toString(2) : ((JSONArray) parsed).toString(2);
      return (AuthentikRedactor.redactText(text, null) + "\n");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void scrubValue(Object value)
   {
      if(value instanceof JSONObject object)
      {
         for(String key : object.keySet())
         {
            Object child = object.get(key);
            if(key.equals("avatar") && child instanceof String)
            {
               object.put(key, "");
            }
            else
            {
               scrubValue(child);
            }
         }
      }
      else if(value instanceof JSONArray array)
      {
         for(int i = 0; i < array.length(); i++)
         {
            scrubValue(array.get(i));
         }
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void write(Path path, String text)
   {
      try
      {
         Files.createDirectories(path.getParent());
         Files.writeString(path, text, StandardCharsets.UTF_8);
      }
      catch(IOException e)
      {
         throw (new IllegalStateException("Could not write fixture " + path, e));
      }
   }

}
