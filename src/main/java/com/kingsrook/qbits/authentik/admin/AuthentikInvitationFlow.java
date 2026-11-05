/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.admin;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import org.json.JSONObject;

/*******************************************************************************
 ** Validate the live provider configuration before trusting enrollment reference
 ** data. Configuration is read without caches; this is not grant authorization.
 *******************************************************************************/
public final class AuthentikInvitationFlow
{
   private final AuthentikActionUtil client;

   /***************************************************************************
    ** Use the same guarded provider client as enrollment evidence.
    ***************************************************************************/
   public AuthentikInvitationFlow(AuthentikActionUtil client)
   {
      this.client = java.util.Objects.requireNonNull(client);
   }

   /***************************************************************************
    ** Require one invitation before one write, with exactly the packaged policy
    ** on that write binding. Multiple policies can run concurrently, so numeric
    ** policy order alone does not establish which mutation wins.
    ***************************************************************************/
   public String verify(String slug) throws QException
   {
      String check = "configuration read";
      try
      {
         JSONObject configuration = client.invitationConfiguration(slug);
         JSONObject flow = configuration.getJSONObject("flow");
         check = "flow identity";
         require(slug.equals(flow.getString("slug")) && "enrollment".equals(flow.getString("designation")));
         var orders = new HashSet<Integer>();
         JSONObject invitation = null;
         JSONObject write = null;
         check = "stage identity and order";
         for(Object item : configuration.getJSONArray("bindings"))
         {
            JSONObject binding = (JSONObject) item;
            JSONObject stage = binding.getJSONObject("stage_obj");
            require(flow.getString("pk").equals(binding.getString("target"))
               && binding.getString("stage").equals(stage.getString("pk")) && orders.add(binding.getInt("order")));
            switch(stage.getString("meta_model_name"))
            {
               case "authentik_stages_invitation.invitationstage" ->
               {
                  require(invitation == null);
                  invitation = binding;
               }
               case "authentik_stages_user_write.userwritestage" ->
               {
                  require(write == null);
                  write = binding;
               }
               default -> { }
            }
         }
         require(invitation != null && write != null && invitation.getInt("order") < write.getInt("order"));
         check = "write-stage evaluation";
         require(Boolean.FALSE.equals(write.get("evaluate_on_plan")) && Boolean.TRUE.equals(write.get("re_evaluate_policies"))
            && "all".equals(write.getString("policy_engine_mode")));
         var policies = write.getJSONArray("qqqPolicies");
         check = "policy binding";
         require(policies.length() == 1);
         JSONObject binding = policies.getJSONObject(0);
         require(write.getString("pk").equals(binding.getString("target"))
            && Boolean.TRUE.equals(binding.get("enabled")) && Boolean.FALSE.equals(binding.get("negate"))
            && Boolean.FALSE.equals(binding.get("failure_result")) && Boolean.FALSE.equals(binding.get("expiring"))
            && binding.isNull("expires") && binding.isNull("user") && binding.isNull("group"));
         JSONObject definition = binding.getJSONObject("definition");
         check = "policy definition";
         require(binding.getString("policy").equals(definition.getString("pk"))
            && Boolean.FALSE.equals(definition.get("execution_logging"))
            && normalize(expression()).equals(normalize(definition.getString("expression"))));
         return (flow.getString("pk"));
      }
      catch(Exception invalid)
      {
         throw (new QException("Invitation flow protection could not be verified (" + check + "). Check the enrollment stage and policy configuration."));
      }
   }

   /***************************************************************************
    ** One packaged source is used for provider deployment and verification.
    ***************************************************************************/
   public static String expression() throws java.io.IOException
   {
      try(var input = AuthentikInvitationFlow.class.getResourceAsStream("/authentik/invitation-reference-policy.py"))
      {
         if(input == null)
         {
            throw (new java.io.IOException("Invitation policy resource is unavailable."));
         }
         return (new String(input.readAllBytes(), StandardCharsets.UTF_8));
      }
   }

   /***************************************************************************
    ** Permit platform newlines and surrounding whitespace, not code changes.
    ***************************************************************************/
   private static String normalize(String expression)
   {
      return (expression.replace("\r\n", "\n").strip());
   }

   /***************************************************************************
    ** Keep provider data out of diagnostic failures.
    ***************************************************************************/
   private static void require(boolean valid)
   {
      if(!valid)
      {
         throw (new IllegalArgumentException());
      }
   }
}
