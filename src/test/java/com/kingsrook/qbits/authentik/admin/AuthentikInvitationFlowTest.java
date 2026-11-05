/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.admin;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.module.api.model.metadata.APIBackendMetaData;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** The actual guarded client rejects incomplete and modified flow protection.
 *******************************************************************************/
public class AuthentikInvitationFlowTest
{
   static final String FLOW = "71000000-0000-0000-0000-000000000001";
   static final String WRITE = "71000000-0000-0000-0000-000000000002";
   static final String POLICY = "71000000-0000-0000-0000-000000000003";
   static final String WRITE_MODEL = "71000000-0000-0000-0000-000000000004";
   private FixtureActionUtil client;
   private Map<String, JSONObject> responses;

   /***************************************************************************
    ** Mock HTTP only; guards, cache behavior and pagination remain production.
    ***************************************************************************/
   @BeforeEach
   void setup() throws Exception
   {
      FixtureActionUtil.reset();
      var config = AuthentikTestSupport.unitConfig().withListCacheTtlSeconds(300);
      var instance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.loginWith(instance, IdentityPermission.AUDIT_READ);
      client = new FixtureActionUtil();
      client.setBackendMetaData((APIBackendMetaData) instance.getBackend(config.getApiBackendName()));
      responses = configuration();
      FixtureActionUtil.handler = request ->
      {
         var response = responses.get(request.getURI().getPath());
         return (FixtureActionUtil.response(response == null ? 404 : 200, response == null ? "{}" : response.toString()));
      };
   }

   /***************************************************************************
    ** Release the test's own context and HTTP fixture.
    ***************************************************************************/
   @AfterEach
   void cleanup()
   {
      QContext.clear();
      FixtureActionUtil.reset();
   }

   /***************************************************************************
    ** Shared native-shaped fixture for enrollment evidence tests.
    ***************************************************************************/
   public static Map<String, JSONObject> configuration() throws Exception
   {
      var result = new LinkedHashMap<String, JSONObject>();
      result.put("/api/v3/flows/instances/enroll/", new JSONObject().put("pk", FLOW).put("slug", "enroll").put("designation", "enrollment"));
      var invite = new JSONObject().put("pk", POLICY).put("stage", POLICY).put("target", FLOW).put("order", 10)
         .put("stage_obj", new JSONObject().put("pk", POLICY).put("meta_model_name", "authentik_stages_invitation.invitationstage"));
      var write = new JSONObject().put("pk", WRITE).put("stage", WRITE).put("target", FLOW).put("order", 20)
         .put("policybindingmodel_ptr_id", WRITE_MODEL).put("evaluate_on_plan", false).put("re_evaluate_policies", true).put("policy_engine_mode", "all")
         .put("stage_obj", new JSONObject().put("pk", WRITE).put("meta_model_name", "authentik_stages_user_write.userwritestage"));
      result.put("/api/v3/flows/bindings/", page(invite, write));
      result.put("/api/v3/policies/bindings/", page(new JSONObject().put("pk", POLICY).put("target", WRITE).put("policy", POLICY)
         .put("enabled", true).put("negate", false).put("failure_result", false).put("expiring", false).put("expires", JSONObject.NULL)
         .put("user", JSONObject.NULL).put("group", JSONObject.NULL)));
      result.put("/api/v3/policies/expression/" + POLICY + "/", new JSONObject().put("pk", POLICY).put("execution_logging", false)
         .put("expression", AuthentikInvitationFlow.expression()));
      return (result);
   }

   /***************************************************************************
    ** Complete native pagination metadata is mandatory, including empty lists.
    ***************************************************************************/
   private static JSONObject page(JSONObject... rows)
   {
      return (new JSONObject().put("results", new JSONArray(List.of(rows)))
         .put("pagination", new JSONObject().put("count", rows.length).put("current", 1).put("total_pages", 1)));
   }

   /***************************************************************************
    ** Changes on the provider must be noticed immediately despite configured TTL.
    ***************************************************************************/
   @Test
   void verifiesLiveProtectionAndRejectsPolicyChanges() throws Exception
   {
      var verifier = new AuthentikInvitationFlow(client);
      assertThat(verifier.verify("enroll")).isEqualTo(FLOW);
      assertThat(FixtureActionUtil.REQUESTS.stream().filter(request -> request.getURI().getPath().endsWith("/policies/bindings/"))
         .allMatch(request -> request.getURI().getRawQuery().contains("target=" + WRITE_MODEL))).isTrue();
      responses.get("/api/v3/policies/expression/" + POLICY + "/").put("expression", "return True");
      assertThatThrownBy(() -> verifier.verify("enroll")).isInstanceOf(QException.class).hasNoCause();
   }

   /***************************************************************************
    ** Unsupported bindings, bypasses, missing records and partial pages fail
    ** closed rather than accepting a plausible-looking policy name.
    ***************************************************************************/
   @Test
   void rejectsIncompleteAndAmbiguousProtection() throws Exception
   {
      List<Consumer<Map<String, JSONObject>>> mutations = List.of(
         values -> values.get("/api/v3/flows/instances/enroll/").put("slug", "other"),
         values -> values.get("/api/v3/flows/bindings/").remove("pagination"),
         values -> values.get("/api/v3/flows/bindings/").getJSONArray("results").getJSONObject(1).put("target", POLICY),
         values -> values.get("/api/v3/flows/bindings/").getJSONArray("results").getJSONObject(1).put("order", 10),
         values -> values.get("/api/v3/flows/bindings/").getJSONArray("results").getJSONObject(1).put("order", 5),
         values -> values.get("/api/v3/flows/bindings/").getJSONArray("results").getJSONObject(1).put("evaluate_on_plan", true),
         values -> values.get("/api/v3/flows/bindings/").getJSONArray("results").getJSONObject(1).put("re_evaluate_policies", false),
         values -> values.get("/api/v3/flows/bindings/").getJSONArray("results").getJSONObject(1).put("policy_engine_mode", "any"),
         values -> values.get("/api/v3/policies/bindings/").getJSONArray("results").getJSONObject(0).put("enabled", false),
         values -> values.get("/api/v3/policies/bindings/").getJSONArray("results").getJSONObject(0).put("negate", true),
         values -> values.get("/api/v3/policies/bindings/").getJSONArray("results").getJSONObject(0).put("failure_result", true),
         values -> values.get("/api/v3/policies/bindings/").getJSONArray("results").getJSONObject(0).put("expires", "2027-01-01T00:00:00Z"),
         values -> values.get("/api/v3/policies/bindings/").getJSONArray("results").getJSONObject(0).put("target", FLOW),
         values -> values.put("/api/v3/policies/bindings/", page()),
         values ->
         {
            var binding = values.get("/api/v3/policies/bindings/").getJSONArray("results").getJSONObject(0);
            values.put("/api/v3/policies/bindings/", page(binding, new JSONObject(binding.toString()).put("pk", FLOW)));
         },
         values -> values.get("/api/v3/policies/expression/" + POLICY + "/").put("execution_logging", true),
         values -> values.remove("/api/v3/policies/expression/" + POLICY + "/")
      );
      for(var mutation : mutations)
      {
         responses = configuration();
         mutation.accept(responses);
         assertThatThrownBy(() -> new AuthentikInvitationFlow(client).verify("enroll")).isInstanceOf(QException.class).hasNoCause();
      }
   }

   /***************************************************************************
    ** Unauthorized direct calls and bad flow names never reach HTTP.
    ***************************************************************************/
   @Test
   void guardsConfigurationReads() throws Exception
   {
      assertThatThrownBy(() -> client.invitationConfiguration("../elsewhere")).isInstanceOf(QException.class);
      AuthentikTestSupport.loginWith(QContext.getQInstance(), IdentityPermission.USERS_READ);
      assertThatThrownBy(() -> client.invitationConfiguration("enroll"))
         .isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException.class);
      assertThat(FixtureActionUtil.REQUESTS).isEmpty();
   }

   /***************************************************************************
    ** UUID configuration resolves to one exact flow; another UUID or incomplete
    ** response must never redirect intent to a different enrollment executor.
    ***************************************************************************/
   @Test
   void resolvesConfiguredUuidWithoutIdentityFallback() throws Exception
   {
      responses.put("/api/v3/flows/instances/", page(responses.get("/api/v3/flows/instances/enroll/")));
      assertThat(client.invitationFlowSlug(FLOW)).isEqualTo("enroll");
      responses.get("/api/v3/flows/instances/").getJSONArray("results").getJSONObject(0).put("pk", POLICY);
      assertThatThrownBy(() -> client.invitationFlowSlug(FLOW)).isInstanceOf(QException.class);
      responses.put("/api/v3/flows/instances/", page());
      assertThatThrownBy(() -> client.invitationFlowSlug(FLOW)).isInstanceOf(QException.class);
   }
}
