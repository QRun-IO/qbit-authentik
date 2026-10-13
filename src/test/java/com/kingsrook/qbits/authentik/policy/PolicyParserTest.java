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
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Unit tests for PolicyParser: the format and every fail-closed case.
 *******************************************************************************/
class PolicyParserTest
{
   private static final PolicyFormat FORMAT = PolicyFormat.DEFAULT;



   /*******************************************************************************
    ** A statement.
    *******************************************************************************/
   static JSONObject statement(String effect, List<String> actions, List<String> resources)
   {
      return (new JSONObject().put("Effect", effect).put("Action", new JSONArray(actions)).put("Resource", new JSONArray(resources)));
   }



   /*******************************************************************************
    ** A document with the default spec and version.
    *******************************************************************************/
   static JSONObject document(JSONObject... statements)
   {
      return (new JSONObject().put("PolicySpec", "qqq-iam").put("PolicyVersion", "1.0.0").put("Statement", new JSONArray(List.of(statements))));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void allowStatementsGrantResourceDotAction()
   {
      JSONObject doc = document(
         statement("Allow", List.of("hasAccess"), List.of("contentApp", "publishPage")),
         statement("Allow", List.of("read", "edit"), List.of("cms_page")));

      assertThat(PolicyParser.parse(doc, FORMAT)).containsExactlyInAnyOrder(
         "contentApp.hasAccess", "publishPage.hasAccess", "cms_page.read", "cms_page.edit");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void wildcardActionIsAllFive()
   {
      assertThat(PolicyParser.parse(document(statement("Allow", List.of("*"), List.of("cms_page"))), FORMAT)).containsExactlyInAnyOrder(
         "cms_page.hasAccess", "cms_page.read", "cms_page.insert", "cms_page.edit", "cms_page.delete");
   }



   /*******************************************************************************
    ** String (as stored in an attribute or claim), JSONObject and Map all parse.
    *******************************************************************************/
   @Test
   void acceptsStringObjectAndMap()
   {
      JSONObject doc = document(statement("Allow", List.of("read"), List.of("a")));
      assertThat(PolicyParser.parse(doc.toString(), FORMAT)).containsExactly("a.read");
      assertThat(PolicyParser.parse(doc, FORMAT)).containsExactly("a.read");
      assertThat(PolicyParser.parse(doc.toMap(), FORMAT)).containsExactly("a.read");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void emptyOrMissingStatementGrantsNothingWithoutError() throws Exception
   {
      assertThat(PolicyParser.parseStrict(document(), FORMAT).permissions()).isEmpty();
      assertThat(PolicyParser.parseStrict(new JSONObject().put("PolicySpec", "qqq-iam").put("PolicyVersion", "1.0.0"), FORMAT).permissions()).isEmpty();
      assertThat(PolicyParser.parseStrict(document(statement("Allow", List.of(), List.of("a"))), FORMAT).permissions()).isEmpty();
   }



   /*******************************************************************************
    ** Every malformed document grants nothing (fail closed), and parseStrict
    ** names the problem.
    *******************************************************************************/
   @ParameterizedTest
   @ValueSource(strings = {
      "",
      "   ",
      "not json",
      "[]",
      "{\"PolicyVersion\":\"1.0.0\",\"Statement\":[]}",
      "{\"PolicySpec\":\"other-spec\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[]}",
      "{\"PolicySpec\":\"qqq-iam\",\"Statement\":[]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"2.0.0\",\"Statement\":[]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":{}}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[\"x\"]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":[\"read\"],\"Resource\":[\"a\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"allow\",\"Action\":[\"read\"],\"Resource\":[\"a\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Action\":[\"read\"],\"Resource\":[\"a\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"read\",\"Resource\":[\"a\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":\"a\"}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"write\"],\"Resource\":[\"a\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"Read\"],\"Resource\":[\"a\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[1],\"Resource\":[\"a\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"*\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"authentik.users\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"\"]}]}",
      "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"cms_*\"]}]}",
   })
   void malformedDocumentsFailClosed(String text)
   {
      assertThat(PolicyParser.parse(text, FORMAT)).isEmpty();
      assertThatThrownBy(() -> PolicyParser.parseStrict(text, FORMAT)).isInstanceOf(PolicyParseException.class);
   }



   /*******************************************************************************
    ** One bad statement voids the whole document (no partial credit).
    *******************************************************************************/
   @Test
   void oneBadStatementVoidsAll()
   {
      JSONObject doc = document(
         statement("Allow", List.of("read"), List.of("good")),
         statement("Deny", List.of("read"), List.of("other")));
      assertThat(PolicyParser.parse(doc, FORMAT)).isEmpty();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void nullAndOtherTypesGrantNothing()
   {
      assertThat(PolicyParser.parse(null, FORMAT)).isEmpty();
      assertThat(PolicyParser.parse(JSONObject.NULL, FORMAT)).isEmpty();
      assertThat(PolicyParser.parse(42, FORMAT)).isEmpty();
      assertThat(PolicyParser.parse(new JSONArray(), FORMAT)).isEmpty();
   }



   /*******************************************************************************
    ** A host keeps its own spec name and version.
    *******************************************************************************/
   @Test
   void customSpecName()
   {
      PolicyFormat custom = new PolicyFormat("acme-iam", "2.1.0", "policies", "policies");
      JSONObject   doc    = new JSONObject().put("PolicySpec", "acme-iam").put("PolicyVersion", "2.1.0")
         .put("Statement", new JSONArray().put(statement("Allow", List.of("read"), List.of("order"))));

      assertThat(PolicyParser.parse(doc, custom)).containsExactly("order.read");
      assertThat(PolicyParser.parse(doc, FORMAT)).as("the default spec rejects another spec").isEmpty();
      assertThat(PolicyParser.parse(doc, null)).as("null format means the default").isEmpty();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void messagesNameTheProblem()
   {
      assertThatThrownBy(() -> PolicyParser.parseStrict(Map.of("PolicySpec", "x"), FORMAT)).hasMessageContaining("PolicySpec must be \"qqq-iam\"");
      assertThatThrownBy(() -> PolicyParser.parseStrict(document(statement("Allow", List.of("write"), List.of("a"))), FORMAT)).hasMessageContaining("unknown action \"write\"");
      assertThatThrownBy(() -> PolicyParser.parseStrict(document(statement("Deny", List.of("read"), List.of("a"))), FORMAT)).hasMessageContaining("Deny is not supported");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void formatProblems()
   {
      assertThat(PolicyFormat.DEFAULT.problem()).isNull();
      assertThat(new PolicyFormat("bad spec", "1.0.0", "a", "c").problem()).contains("policySpec");
      assertThat(new PolicyFormat("s", "1.0", "a", "c").problem()).contains("policyVersion");
      assertThat(new PolicyFormat("s", "1.0.0", " ", "c").problem()).contains("policyAttribute");
      assertThat(new PolicyFormat("s", "1.0.0", "a", "bad claim").problem()).contains("policyClaim");
   }
}
