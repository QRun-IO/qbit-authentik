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


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.authentik.policy.PolicyParserTest.document;
import static com.kingsrook.qbits.authentik.policy.PolicyParserTest.statement;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Unit tests for AuthentikPolicyClaimMapper and PolicyPermissions.
 *******************************************************************************/
class AuthentikPolicyClaimMapperTest
{
   private static final String READ_PAGE = document(statement("Allow", List.of("read"), List.of("cms_page"))).toString();



   /*******************************************************************************
    **
    *******************************************************************************/
   private static QSession run(AuthentikPolicyClaimMapper mapper, Map<String, Object> context)
   {
      QSession session = new QSession();
      session.setPermissions(Set.of("existing.hasAccess"));
      mapper.customizeSession(null, session, context);
      return (session);
   }



   /*******************************************************************************
    ** The claim as a string (the scope mapping's json.dumps) in the ID token.
    *******************************************************************************/
   @Test
   void stringClaimInIdToken()
   {
      QSession session = run(new AuthentikPolicyClaimMapper(), Map.of("idToken", new JSONObject().put("qqq_policy", READ_PAGE)));
      assertThat(session.getPermissions()).containsExactlyInAnyOrder("existing.hasAccess", "cms_page.read");
   }



   /*******************************************************************************
    ** An object claim in the access token (session resume: no ID token).
    *******************************************************************************/
   @Test
   void objectClaimInAccessToken()
   {
      QSession session = run(new AuthentikPolicyClaimMapper(), Map.of("jwtPayloadJsonObject", new JSONObject().put("qqq_policy", new JSONObject(READ_PAGE))));
      assertThat(session.getPermissions()).contains("cms_page.read");
   }



   /*******************************************************************************
    ** The ID token wins when both carry the claim; the access token is used when
    ** only it has the claim.
    *******************************************************************************/
   @Test
   void idTokenPreferred()
   {
      String other = document(statement("Allow", List.of("edit"), List.of("other"))).toString();
      Map<String, Object> context = new HashMap<>();
      context.put("idToken", new JSONObject().put("qqq_policy", READ_PAGE));
      context.put("jwtPayloadJsonObject", new JSONObject().put("qqq_policy", other));
      assertThat(run(new AuthentikPolicyClaimMapper(), context).getPermissions()).contains("cms_page.read").doesNotContain("other.edit");

      context.put("idToken", new JSONObject().put("email", "a@example.test"));
      assertThat(run(new AuthentikPolicyClaimMapper(), context).getPermissions()).contains("other.edit");
   }



   /*******************************************************************************
    ** Missing or invalid claims add nothing and keep what the session had.
    *******************************************************************************/
   @Test
   void failsClosed()
   {
      assertThat(run(new AuthentikPolicyClaimMapper(), Map.of()).getPermissions()).containsExactly("existing.hasAccess");
      assertThat(run(new AuthentikPolicyClaimMapper(), null).getPermissions()).containsExactly("existing.hasAccess");
      assertThat(run(new AuthentikPolicyClaimMapper(), Map.of("idToken", new JSONObject().put("qqq_policy", "{}"))).getPermissions()).containsExactly("existing.hasAccess");
      assertThat(run(new AuthentikPolicyClaimMapper(), Map.of("idToken", new JSONObject().put("qqq_policy", "garbage"))).getPermissions()).containsExactly("existing.hasAccess");
      assertThat(run(new AuthentikPolicyClaimMapper(), Map.of("idToken", "not claims")).getPermissions()).containsExactly("existing.hasAccess");
   }



   /*******************************************************************************
    ** A host's own names (spec, claim).
    *******************************************************************************/
   @Test
   void customFormat()
   {
      PolicyFormat custom = new PolicyFormat("acme-iam", "1.0.0", "policies", "policies");
      String       doc    = new JSONObject(READ_PAGE).put("PolicySpec", "acme-iam").toString();

      QSession session = run(new AuthentikPolicyClaimMapper().withFormat(custom), Map.of("idToken", Map.of("policies", doc)));
      assertThat(session.getPermissions()).contains("cms_page.read");
      assertThat(new AuthentikPolicyClaimMapper().withFormat(null).getFormat()).isEqualTo(PolicyFormat.DEFAULT);

      assertThat(PolicyPermissions.fromClaims(new JSONObject().put("policies", doc), custom)).containsExactly("cms_page.read");
      assertThat(PolicyPermissions.fromClaims(null, custom)).isEmpty();
      assertThat(PolicyPermissions.claimsWithPolicy(null, null)).isNull();
   }



   /*******************************************************************************
    ** The security-key hook runs before permissions, with the claims, even when
    ** the token has no policy claim.
    *******************************************************************************/
   @Test
   void securityKeyHook()
   {
      List<String> calls = new ArrayList<>();
      AuthentikPolicyClaimMapper mapper = new AuthentikPolicyClaimMapper()
      {
         @Override
         protected void applySecurityKeys(QSession qSession, JSONObject claims)
         {
            calls.add(claims.optString("tenant") + ":" + qSession.getPermissions().contains("cms_page.read"));
         }
      };
      run(mapper, Map.of("idToken", new JSONObject().put("tenant", "t1").put("qqq_policy", READ_PAGE)));
      run(mapper, Map.of("jwtPayloadJsonObject", new JSONObject().put("tenant", "t2")));
      assertThat(calls).containsExactly("t1:false", "t2:false");
   }
}
