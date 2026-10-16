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

package com.kingsrook.qbits.authentik.admin;


import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.policy.PolicyGenerator;
import com.kingsrook.qbits.authentik.policy.PolicyParseException;
import com.kingsrook.qbits.authentik.policy.PolicyParser;
import com.kingsrook.qbits.authentik.policy.PolicyPermissions;
import com.kingsrook.qqq.backend.core.context.CapturedContext;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.serviceidentity.ServiceIdentities;
import com.kingsrook.qqq.backend.core.utils.StringUtils;
import org.json.JSONObject;


/*******************************************************************************
 ** Audited policy maintenance for reviewed host Java code, typically a run-once
 ** job. This API deliberately creates its own authority; never expose it through
 ** an HTTP route or a user-invokable process. No route or process is registered.
 *******************************************************************************/
public final class AuthentikMaintenance
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikMaintenance()
   {
   }



   /*******************************************************************************
    ** Apply a policy to exactly one group by name through the normal Save Policy
    ** plan and execute path. Requires an initialized QContext with the host's
    ** QInstance. The caller's context is restored on success, refusal or failure.
    **
    ** Runs as the host's maintenance service principal (config
    ** maintenancePrincipal, default "maintenance"; docs/SERVICE-IDENTITY.md in
    ** qqq): under OAuth2 a real token for its Authentik service account, so its
    ** authority is exactly what the owner granted that account (policies.manage
    ** and every grant the document applies - the subset rule still holds). No
    ** authority is created here. The audit operator is service:{principal};
    ** the job name (maintenance: or run-once:, nonblank suffix) prefixes the
    ** required reason. Existing scope, protection, readOnly, feature and stale
    ** checks still apply. Equivalent policies return NO_CHANGE without a write
    ** or an audit row. With policyTwoPersonApproval enabled, a change queues an
    ** approval instead of writing to Authentik; this API never bypasses
    ** second-person approval.
    *******************************************************************************/
   public static AuthentikAdmin.AdminResult applyPolicy(String apiBackendName, String groupName, String policyJson, String operatorName, String reason) throws QException
   {
      if(operatorName == null || !(operatorName.startsWith("maintenance:") || operatorName.startsWith("run-once:"))
         || operatorName.substring(operatorName.indexOf(':') + 1).isBlank())
      {
         throw (new QUserFacingException("The operator name must start with maintenance: or run-once: and name the job."));
      }
      if(!StringUtils.hasContent(reason))
      {
         throw (new QUserFacingException("A reason is required for every change."));
      }
      if(!StringUtils.hasContent(groupName))
      {
         throw (new QUserFacingException("A group name is required."));
      }

      CapturedContext caller = QContext.capture();
      try
      {
         String principal = AuthentikRuntime.forBackend(apiBackendName).getConfig().getMaintenancePrincipal();
         QContext.init(caller.qInstance(), ServiceIdentities.session(caller.qInstance(), principal));

         AuthentikAdmin admin = AuthentikAdmin.forBackend(apiBackendName);
         AuthentikRuntime runtime = admin.getUtil().getRuntime();
         runtime.getGuard().authorize(AdminAction.SAVE_POLICY);
         if(StringUtils.hasContent(policyJson))
         {
            PolicyParser.parseStrict(policyJson, runtime.getConfig().getPolicyFormat(), runtime.getPolicyCatalog());
         }

         runtime.invalidateCache();
         List<JSONObject> groups = admin.getUtil().getAllPages("/core/groups/?name=" + URLEncoder.encode(groupName, StandardCharsets.UTF_8)
            + "&include_users=true&include_parents=true&include_children=true", 2);
         if(groups.size() != 1 || !groupName.equals(groups.get(0).optString("name")))
         {
            throw (new QUserFacingException("Expected exactly one Authentik group named " + groupName + "."));
         }
         JSONObject group = groups.get(0);
         AdminRequest request = AdminRequest.of(AdminAction.SAVE_POLICY, group.getString("pk"), operatorName + ": " + reason)
            .with(AuthentikAdmin.POLICY_DOCUMENT, policyJson)
            .with("expectedFingerprint", AuthentikSafety.groupFingerprint(group));
         return (admin.execute(request));
      }
      catch(PolicyParseException e)
      {
         throw (new QUserFacingException("The policy is not valid: " + e.getMessage()));
      }
      finally
      {
         QContext.init(caller);
      }
   }



   /*******************************************************************************
    ** Canonical compact full-access document using the host's spec and version.
    *******************************************************************************/
   public static String fullAccessDocument(AuthentikQBitConfig config) throws QException
   {
      try
      {
         return (PolicyGenerator.toCompact(PolicyGenerator.generate(Set.of(PolicyPermissions.FULL_ACCESS), config.getPolicyFormat())));
      }
      catch(PolicyParseException e)
      {
         throw (new QException("Could not generate the full-access policy.", e));
      }
   }
}
