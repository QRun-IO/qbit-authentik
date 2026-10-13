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

package com.kingsrook.qbits.authentik.policy;


import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Unit tests for PolicyGenerator: canonical form and the round trip.
 *******************************************************************************/
class PolicyGeneratorTest
{

   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void canonicalForm() throws Exception
   {
      JSONObject doc = PolicyGenerator.generate(List.of("cms_page.edit", "contentApp.hasAccess", "cms_page.read", "cms_media.read"), PolicyFormat.DEFAULT);

      assertThat(PolicyGenerator.toCompact(doc)).isEqualTo("{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":["
         + "{\"Effect\":\"Allow\",\"Action\":[\"hasAccess\"],\"Resource\":[\"contentApp\"]},"
         + "{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"cms_media\",\"cms_page\"]},"
         + "{\"Effect\":\"Allow\",\"Action\":[\"edit\"],\"Resource\":[\"cms_page\"]}]}");

      assertThat(PolicyGenerator.toPretty(doc)).isEqualTo("""
         {
           "PolicySpec": "qqq-iam",
           "PolicyVersion": "1.0.0",
           "Statement": [
             {
               "Effect": "Allow",
               "Action": ["hasAccess"],
               "Resource": [
                 "contentApp"
               ]
             },
             {
               "Effect": "Allow",
               "Action": ["read"],
               "Resource": [
                 "cms_media",
                 "cms_page"
               ]
             },
             {
               "Effect": "Allow",
               "Action": ["edit"],
               "Resource": [
                 "cms_page"
               ]
             }
           ]
         }
         """);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void emptyDocument() throws Exception
   {
      JSONObject doc = PolicyGenerator.generate(List.of(), PolicyFormat.DEFAULT);
      assertThat(PolicyGenerator.toCompact(doc)).isEqualTo("{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[]}\n".trim());
      assertThat(PolicyGenerator.toPretty(doc)).isEqualTo("{\n  \"PolicySpec\": \"qqq-iam\",\n  \"PolicyVersion\": \"1.0.0\",\n  \"Statement\": []\n}\n");
      assertThat(PolicyParser.parseStrict(PolicyGenerator.toPretty(doc), PolicyFormat.DEFAULT).permissions()).isEmpty();
   }



   /*******************************************************************************
    ** parse(generate(x)) == x for many random permission sets, in both forms,
    ** and generate(parse(doc)) is stable (canonical).
    *******************************************************************************/
   @Test
   void roundTripRandomSets() throws Exception
   {
      Random       random    = new Random(20261013);
      List<String> resources = List.of("a", "B_2", "cms_page", "contentApp", "x9", "authentik_user", "publishPage");
      for(int run = 0; run < 500; run++)
      {
         Set<String> permissions = new TreeSet<>();
         for(String resource : resources)
         {
            for(PolicyAction action : PolicyAction.values())
            {
               if(random.nextInt(3) == 0)
               {
                  permissions.add(action.permission(resource));
               }
            }
         }
         JSONObject doc = PolicyGenerator.generate(permissions, PolicyFormat.DEFAULT);
         assertThat(PolicyParser.parseStrict(PolicyGenerator.toCompact(doc), PolicyFormat.DEFAULT).permissions()).isEqualTo(permissions);
         assertThat(PolicyParser.parseStrict(PolicyGenerator.toPretty(doc), PolicyFormat.DEFAULT).permissions()).isEqualTo(permissions);
         assertThat(PolicyGenerator.toCompact(PolicyGenerator.canonical(PolicyGenerator.toPretty(doc), PolicyFormat.DEFAULT))).isEqualTo(PolicyGenerator.toCompact(doc));
      }
   }



   /*******************************************************************************
    ** A hand-written document with "*" and repeated statements becomes the
    ** canonical one with the same grants.
    *******************************************************************************/
   @Test
   void canonicalizesHandWrittenDocuments() throws Exception
   {
      String hand = "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":["
         + "{\"Effect\":\"Allow\",\"Action\":[\"*\"],\"Resource\":[\"b\"]},"
         + "{\"Effect\":\"Allow\",\"Action\":[\"read\",\"read\"],\"Resource\":[\"a\",\"b\"]}]}";
      JSONObject canonical = PolicyGenerator.canonical(hand, PolicyFormat.DEFAULT);
      assertThat(PolicyParser.parse(canonical, PolicyFormat.DEFAULT)).isEqualTo(PolicyParser.parse(hand, PolicyFormat.DEFAULT));
      assertThat(PolicyGenerator.toCompact(canonical)).doesNotContain("\"*\"");
      assertThat(canonical.getJSONArray("Statement").length()).isEqualTo(5);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void rejectsWhatCannotRoundTrip()
   {
      assertThatThrownBy(() -> PolicyGenerator.generate(List.of("noaction"), PolicyFormat.DEFAULT)).isInstanceOf(PolicyParseException.class).hasMessageContaining("{resource}.{action}");
      assertThatThrownBy(() -> PolicyGenerator.generate(List.of("a."), PolicyFormat.DEFAULT)).isInstanceOf(PolicyParseException.class);
      assertThatThrownBy(() -> PolicyGenerator.generate(List.of(".read"), PolicyFormat.DEFAULT)).isInstanceOf(PolicyParseException.class);
      assertThatThrownBy(() -> PolicyGenerator.generate(List.of("a.write"), PolicyFormat.DEFAULT)).hasMessageContaining("unknown action \"write\"");
      assertThatThrownBy(() -> PolicyGenerator.generate(List.of("authentik.users.read"), PolicyFormat.DEFAULT)).hasMessageContaining("[A-Za-z0-9_]+");
      assertThatThrownBy(() -> PolicyGenerator.generate(java.util.Arrays.asList((String) null), PolicyFormat.DEFAULT)).isInstanceOf(PolicyParseException.class);
   }



   /*******************************************************************************
    ** The generator writes the host's spec and version.
    *******************************************************************************/
   @Test
   void customFormat() throws Exception
   {
      PolicyFormat custom = new PolicyFormat("acme-iam", "1.0.0", "policies", "policies");
      JSONObject   doc    = PolicyGenerator.generate(List.of("order.read"), custom);
      assertThat(doc.getString("PolicySpec")).isEqualTo("acme-iam");
      assertThat(PolicyParser.parse(PolicyGenerator.toCompact(doc), custom)).containsExactly("order.read");
      assertThat(PolicyGenerator.generate(List.of("order.read"), null).getString("PolicySpec")).isEqualTo("qqq-iam");
   }
}
