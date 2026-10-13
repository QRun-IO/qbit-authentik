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


import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.modules.authentication.QAuthenticationModuleCustomizerInterface;
import org.json.JSONObject;
import static com.kingsrook.qqq.backend.core.logging.LogUtils.logPair;


/*******************************************************************************
 ** Authentication customizer that adds the QQQ permissions granted by the
 ** policy claim of the sign-in token (docs/POLICY-FORMAT.md). It needs no
 ** Authentik API access: Authentik merges the user's group policies into the
 ** claim at sign-in (the scope mapping in the format doc).
 **
 ** Order: applySecurityKeys (a no-op hook for hosts), then permissions. The
 ** permissions are added to whatever the session already holds. A missing or
 ** invalid claim adds nothing (fail closed).
 *******************************************************************************/
public class AuthentikPolicyClaimMapper implements QAuthenticationModuleCustomizerInterface
{
   private static final QLogger LOG = QLogger.getLogger(AuthentikPolicyClaimMapper.class);

   private PolicyFormat format = PolicyFormat.DEFAULT;



   /*******************************************************************************
    ** Use these names (the qbit config's getPolicyFormat()) instead of the
    ** defaults.
    *******************************************************************************/
   public AuthentikPolicyClaimMapper withFormat(PolicyFormat format)
   {
      this.format = format == null ? PolicyFormat.DEFAULT : format;
      return (this);
   }



   /*******************************************************************************
    ** Getter for format.
    *******************************************************************************/
   public PolicyFormat getFormat()
   {
      return (format);
   }



   /*******************************************************************************
    ** Add the permissions from the policy claim.
    *******************************************************************************/
   @Override
   public void customizeSession(QInstance qInstance, QSession qSession, Map<String, Object> context)
   {
      JSONObject claims = PolicyPermissions.claimsWithPolicy(context, format);
      JSONObject any    = claims;
      if(any == null && context != null)
      {
         any = PolicyPermissions.asClaims(context.get(PolicyPermissions.ID_TOKEN_CONTEXT_KEY));
         if(any == null)
         {
            any = PolicyPermissions.asClaims(context.get(PolicyPermissions.ACCESS_TOKEN_CONTEXT_KEY));
         }
      }
      if(any != null)
      {
         applySecurityKeys(qSession, any);
      }

      if(claims == null)
      {
         LOG.info("No policy claim in the token; no policy permissions added", logPair("claim", format.claim()));
         return;
      }

      Set<String> permissions = new TreeSet<>(PolicyPermissions.fromClaims(claims, format, qInstance == null ? null : PolicyCatalog.of(qInstance)));
      if(qSession.getPermissions() != null)
      {
         permissions.addAll(qSession.getPermissions());
      }
      qSession.setPermissions(permissions);
   }



   /*******************************************************************************
    ** Extension point for record locks (security keys); a no-op here. A host
    ** overrides it to set security key values from its OWN explicit claims, and
    ** must never infer them from group names.
    *******************************************************************************/
   protected void applySecurityKeys(QSession qSession, JSONObject claims)
   {
      ////////////////////////////////////////////////////////
      // no record locks in policy format 1.0.0 (by design) //
      ////////////////////////////////////////////////////////
   }
}
