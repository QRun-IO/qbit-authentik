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

package com.kingsrook.qbits.authentik.drift;


import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikJson;
import com.kingsrook.qbits.authentik.client.AuthentikRedactor;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import static com.kingsrook.qqq.backend.core.logging.LogUtils.logPair;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** The identity drift report (DESIGN.md sections 4.5, 5.1 and 8.2): checks
 ** that Authentik is in the shape the qbit relies on, using only the service
 ** account's read permissions. Each check is independent; a check that cannot
 ** run reports why and the rest still run.
 **
 ** Checks:
 ** 1. version: server major.minor = expectedServerVersion
 ** 2. blueprints: every blueprint instance applied successfully
 ** 3. service account: exists, is a service account, has no groups, is not a
 **    superuser, is protected; exactly one API token (it can mint its own)
 ** 4. break-glass: at least one active, protected superuser exists
 ** 5. identity admins: at least one active, unprotected human holds both
 **    authentik.memberships.manage and authentik.permissions.manage (last-admin)
 ** 6. group attributes: qqq.io/permissions entries that grant nothing known;
 **    qqq.io/app-access entries outside applicationsInScope; superuser groups
 **    (or their descendants) carrying qqq.io/permissions
 ** 7. service-account activity: events by the service account touching a
 **    superuser or protected user, or a superuser group (lockout detection)
 *******************************************************************************/
public class AuthentikDriftReport
{
   private static final QLogger LOG = QLogger.getLogger(AuthentikDriftReport.class);

   private final AuthentikActionUtil client;
   private final AuthentikQBitConfig config;
   private final AuthentikGuard      guard;



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   public AuthentikDriftReport(AuthentikActionUtil client, AuthentikQBitConfig config)
   {
      this.client = client;
      this.config = config;
      this.guard = new AuthentikGuard(config);
   }



   /*******************************************************************************
    ** Run every check; findings sorted by severity (errors first).
    *******************************************************************************/
   public List<DriftFinding> run()
   {
      List<DriftFinding> findings = new ArrayList<>();
      runCheck(findings, "version", this::checkVersion);
      runCheck(findings, "blueprints", this::checkBlueprints);
      runCheck(findings, "service account", this::checkServiceAccount);
      runCheck(findings, "break-glass", this::checkBreakGlass);
      runCheck(findings, "identity admins", this::checkIdentityAdmins);
      runCheck(findings, "group attributes", this::checkGroupAttributes);
      runCheck(findings, "service-account activity", this::checkServiceAccountActivity);
      findings.sort(Comparator.comparing(DriftFinding::severity));
      return (findings);
   }



   /*******************************************************************************
    ** A check.
    *******************************************************************************/
   @FunctionalInterface
   interface Check
   {
      /*******************************************************************************
       **
       *******************************************************************************/
      void run(List<DriftFinding> findings) throws QException;
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private void runCheck(List<DriftFinding> findings, String name, Check check)
   {
      try
      {
         check.run(findings);
      }
      catch(Exception e)
      {
         String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
         LOG.warn("Drift check could not run", logPair("check", name), logPair("error", AuthentikRedactor.redactText(message, config.getResolvedApiToken())));
         findings.add(DriftFinding.error(name, "-", "Check could not run, so its result is UNKNOWN: " + AuthentikRedactor.redactText(message, config.getResolvedApiToken())));
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String encode(String value)
   {
      return (java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8));
   }



   /*******************************************************************************
    ** 1
    *******************************************************************************/
   void checkVersion(List<DriftFinding> findings)
   {
      String expected = config.getExpectedServerVersion();
      String actual   = client.fetchServerVersion().orElse(null);
      if(expected == null || expected.isBlank())
      {
         findings.add(DriftFinding.info("version", actual == null ? "Authentik" : "Authentik " + actual, "No expectedServerVersion configured."));
      }
      else if(actual == null)
      {
         findings.add(DriftFinding.warning("version", "Authentik", "Server version unavailable (GET /admin/version/ failed)."));
      }
      else if(!(actual.equals(expected) || actual.startsWith(expected + ".")))
      {
         findings.add(DriftFinding.warning("version", "Authentik " + actual, "qbit-authentik was tested against " + expected + ". Run its contract tests against " + actual + " before relying on it."));
      }
      else
      {
         findings.add(DriftFinding.ok("version", "Authentik " + actual, "Matches the tested version " + expected + "."));
      }
   }



   /*******************************************************************************
    ** 2
    *******************************************************************************/
   void checkBlueprints(List<DriftFinding> findings) throws QException
   {
      int failing = 0;
      for(JSONObject blueprint : client.getAllPages("/managed/blueprints/", 1000))
      {
         String status = blueprint.optString("status", "unknown");
         if(!blueprint.optBoolean("enabled", true))
         {
            continue;
         }
         if(!"successful".equals(status))
         {
            failing++;
            findings.add(DriftFinding.error("blueprints", blueprint.optString("name"),
               "Blueprint status is \"" + status + "\" (last applied " + blueprint.optString("last_applied", "never") + "). A failed blueprint rolls back entirely; check the worker logs."));
         }
      }
      if(failing == 0)
      {
         findings.add(DriftFinding.ok("blueprints", "all", "Every enabled blueprint applied successfully."));
      }
   }



   /*******************************************************************************
    ** 3
    *******************************************************************************/
   void checkServiceAccount(List<DriftFinding> findings) throws QException
   {
      String     username = config.getEffectiveServiceAccountUsername();
      JSONArray  results  = client.getApiJson("/core/users/?include_groups=true&username=" + encode(username)).optJSONArray("results");
      JSONObject user     = results == null || results.isEmpty() ? null : results.getJSONObject(0);
      if(user == null)
      {
         findings.add(DriftFinding.error("service account", username, "Not found, or not visible to the API token's user. Is the token minted for this account?"));
         return;
      }

      List<String> problems = new ArrayList<>();
      if(!"service_account".equals(user.optString("type")))
      {
         problems.add("type is " + user.optString("type") + ", not service_account");
      }
      if(user.optBoolean("is_superuser", false))
      {
         problems.add("it is a SUPERUSER: remove it from every superuser group now");
      }
      JSONArray groups = user.optJSONArray("groups_obj");
      if(groups != null && !groups.isEmpty())
      {
         problems.add("it is in " + groups.length() + " group(s); it should be in none");
      }
      if(!user.optBoolean("is_active", true))
      {
         problems.add("it is inactive");
      }
      JSONObject attributes = user.optJSONObject("attributes");
      if(!AuthentikGuard.isMarkedProtected(user))
      {
         problems.add("qqq.io/protected is not true");
      }
      for(String problem : problems)
      {
         findings.add((problem.contains("SUPERUSER") ? DriftFinding.error("service account", username, problem) : DriftFinding.warning("service account", username, problem)));
      }

      ////////////////////////////////////////////////////////////////////////////
      // tokens: listing without view_token returns the caller's own tokens    //
      ////////////////////////////////////////////////////////////////////////////
      List<JSONObject> tokens   = client.getAllPages("/core/tokens/?intent=api&user__username=" + encode(username), 200);
      int              apiOwned = 0;
      if(tokens.size() >= 200)
      {
         findings.add(DriftFinding.error("service account", username, "200 or more API tokens for the service account; something is minting tokens."));
      }
      for(JSONObject token : tokens)
      {
         JSONObject owner = token.optJSONObject("user_obj");
         if(owner != null && username.equals(owner.optString("username")) && "api".equals(token.optString("intent")))
         {
            apiOwned++;
         }
      }
      if(apiOwned == 0)
      {
         findings.add(DriftFinding.warning("service account", username, "The service account's own API token is not visible, so extra tokens cannot be detected."));
      }
      else if(apiOwned > 1)
      {
         findings.add(DriftFinding.warning("service account", username, apiOwned + " API tokens exist for the service account; expected 1. It can mint its own tokens, so an extra one may be a leftover rotation or persistence after a compromise. Delete the ones not in Infisical."));
      }

      if(problems.isEmpty() && apiOwned == 1)
      {
         findings.add(DriftFinding.ok("service account", username, "Service account, no groups, not a superuser, protected, one API token."));
      }
   }



   /*******************************************************************************
    ** 4
    *******************************************************************************/
   void checkBreakGlass(List<DriftFinding> findings) throws QException
   {
      List<JSONObject> protectedUsers = client.getAllPages("/core/users/?attributes=" + java.net.URLEncoder.encode("{\"" + AuthentikJson.ATTR_PROTECTED + "\": true}", java.nio.charset.StandardCharsets.UTF_8), 200);
      List<String> breakGlass = new ArrayList<>();
      for(JSONObject user : protectedUsers)
      {
         if(user.optBoolean("is_superuser", false) && user.optBoolean("is_active", true) && AuthentikGuard.isMarkedProtected(user))
         {
            breakGlass.add(user.optString("username"));
         }
      }
      if(breakGlass.isEmpty())
      {
         findings.add(DriftFinding.error("break-glass", "-", "No active superuser marked qqq.io/protected. Without one, a lockout can only be undone from the cluster (ak shell)."));
      }
      else
      {
         findings.add(DriftFinding.ok("break-glass", String.join(", ", breakGlass), "Active, protected superuser present."));
      }
   }



   /*******************************************************************************
    ** 5
    *******************************************************************************/
   void checkIdentityAdmins(List<DriftFinding> findings) throws QException
   {
      List<JSONObject> groups = client.getAllPages("/core/groups/?include_users=true&ordering=name", AuthentikActionUtil.MAX_SWEEP_OBJECTS);
      GroupGraph       graph  = GroupGraph.fromGroups(groups);
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph, null);

      List<IdentityPermission> required = List.of(IdentityPermission.MEMBERSHIPS_MANAGE, IdentityPermission.PERMISSIONS_MANAGE);
      Set<Integer>             humans   = new HashSet<>();
      for(JSONObject human : client.getAllPages("/core/users/?type=internal&type=external", AuthentikActionUtil.MAX_SWEEP_OBJECTS))
      {
         humans.add(human.getInt("pk"));
      }
      Set<Integer>             checked  = new HashSet<>();
      List<String>             admins   = new ArrayList<>();
      for(JSONObject group : groups)
      {
         JSONArray users = group.optJSONArray("users_obj");
         for(int i = 0; users != null && i < users.length(); i++)
         {
            JSONObject user = users.getJSONObject(i);
            if(!checked.add(user.getInt("pk")) || !user.optBoolean("is_active", true) || !humans.contains(user.getInt("pk")))
            {
               continue;
            }

            //////////////////////////////////////////////////////////////////////
            // members are partial users (no is_superuser): derive it from the  //
            // groups, so superusers (who cannot be managed from QQQ) and other //
            // protected accounts are not counted                               //
            //////////////////////////////////////////////////////////////////////
            boolean superuser = graph.groupsOfUser(user.getInt("pk")).stream().anyMatch(graph::isSuperuserInherited);
            if(superuser || guard.protection(user).isProtected())
            {
               continue;
            }
            if(EffectivePermissionResolver.holdsAll(resolver.resolveUser(user.getInt("pk")), required))
            {
               admins.add(user.optString("username"));
            }
         }
      }

      if(admins.isEmpty())
      {
         String bootstrap = config.getResolvedBootstrapOperators().isEmpty() ? "" : " bootstrapOperators is set, which covers sign-in for now.";
         findings.add(DriftFinding.error("identity admins", "-", "Nobody can administer identities from QQQ: no active, unprotected human user holds authentik.memberships.manage and authentik.permissions.manage. Add an administrator to a group carrying authentik.* (e.g. identity-admins) in the Authentik UI." + bootstrap));
      }
      else if(admins.size() == 1)
      {
         findings.add(DriftFinding.info("identity admins", admins.get(0), "Only one identity administrator. Two-person approval of authentik.* grants needs a second one (or the Authentik UI)."));
      }
      else
      {
         findings.add(DriftFinding.ok("identity admins", String.join(", ", admins), admins.size() + " identity administrators."));
      }
   }



   /*******************************************************************************
    ** 6
    *******************************************************************************/
   void checkGroupAttributes(List<DriftFinding> findings) throws QException
   {
      GroupGraph                  graph    = client.groupGraph();
      EffectivePermissionResolver resolver = client.resolver();
      Set<String>                 inScope  = new HashSet<>(config.getApplicationsInScope() == null ? List.of() : config.getApplicationsInScope());
      int                         issues   = 0;

      for(GroupGraph.Node node : graph.nodes())
      {
         for(String bad : node.malformed())
         {
            issues++;
            findings.add(DriftFinding.warning("group attributes", node.name(), "Malformed entry ignored (" + bad + "); qqq.io/permissions and qqq.io/app-access must be lists of strings."));
         }
         for(String permission : node.permissions())
         {
            if(resolver.expand(permission).isEmpty())
            {
               issues++;
               findings.add(DriftFinding.warning("group attributes", node.name(), "qqq.io/permissions entry \"" + permission + "\" grants nothing in this app (unknown permission or empty wildcard)."));
            }
         }
         for(String app : node.appAccess())
         {
            if(!inScope.isEmpty() && !inScope.contains(app))
            {
               issues++;
               findings.add(DriftFinding.info("group attributes", node.name(), "qqq.io/app-access lists \"" + app + "\", which is not in applicationsInScope."));
            }
         }
         if(graph.isSuperuserInherited(node.pk()) && !node.permissions().isEmpty())
         {
            issues++;
            findings.add(DriftFinding.warning("group attributes", node.name(), "Superuser group (or under one) carries qqq.io/permissions. QQQ cannot manage it; keep QQQ grants on ordinary groups."));
         }
      }
      if(issues == 0)
      {
         findings.add(DriftFinding.ok("group attributes", graph.nodes().size() + " groups", "Every qqq.io/* attribute is valid."));
      }
   }



   /*******************************************************************************
    ** 7
    *******************************************************************************/
   void checkServiceAccountActivity(List<DriftFinding> findings) throws QException
   {
      String           username = config.getEffectiveServiceAccountUsername();
      List<JSONObject> events   = client.getAllPages("/events/events/?ordering=-created&username=" + encode(username), 200);
      GroupGraph       graph    = client.groupGraph();
      int              flagged  = 0;

      for(JSONObject event : events)
      {
         JSONObject context = event.optJSONObject("context");
         JSONObject model   = context == null ? null : context.optJSONObject("model");
         if(model == null)
         {
            continue;
         }
         String modelName = model.optString("model_name");
         String pk        = model.optString("pk");
         boolean sensitive = false;
         if(!"user".equals(modelName) && !"group".equals(modelName))
         {
            continue;
         }
         if("model_deleted".equals(event.optString("action")))
         {
            sensitive = true;
         }
         else if("group".equals(modelName))
         {
            sensitive = graph.byPk(pk) == null || graph.isSuperuserInherited(pk);
         }
         else if(pk.matches("[0-9]+"))
         {
            JSONObject user = client.getApiJsonOrNull("/core/users/" + pk + "/");
            sensitive = user == null || (guard.protection(user).isProtected() && !username.equals(user.optString("username")));
         }
         if(sensitive)
         {
            flagged++;
            findings.add(DriftFinding.error("service-account activity", model.optString("name", pk),
               "The qbit's service account changed a protected or superuser object, deleted one, or changed one that no longer exists (" + event.optString("action") + " at " + event.optString("created") + "). QQQ never does this; investigate as a possible compromise."));
         }
      }
      if(flagged == 0)
      {
         findings.add(DriftFinding.ok("service-account activity", username, "No changes to protected or superuser objects in the last " + events.size() + " service-account events."));
      }
   }

}
