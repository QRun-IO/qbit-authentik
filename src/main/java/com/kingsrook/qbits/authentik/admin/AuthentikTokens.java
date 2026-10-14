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


import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikTokenBroker;
import com.kingsrook.qbits.authentik.client.OAuth2SubjectTokenSource;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.processes.TokenKeyDelivery;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qbits.authentik.security.WriteAuthorization;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Access-token actions (DESIGN section 13). All target checks run at Review and
 ** again at execution; credentials exist only in the action and one-time result.
 *******************************************************************************/
public class AuthentikTokens
{
   public static final String DELIVERY_UNAVAILABLE = "This QQQ version cannot show a key once; upgrade QQQ (4.1.0-RC.7+)";
   public static final String TOKEN_MOVED = "Token moved: owner or intent changed after the update; investigate in Authentik.";
   private static final QLogger LOG = QLogger.getLogger(AuthentikTokens.class);
   private static final SecureRandom RANDOM = new SecureRandom();
   private final AuthentikAdmin admin;
   private final AuthentikActionUtil util;
   private final AuthentikQBitConfig config;
   private final TokenScopeStore scopes;

   /*******************************************************************************
    ** Delegate with the existing admin's live operator and subset checks.
    *******************************************************************************/
   public AuthentikTokens(AuthentikAdmin admin)
   {
      this.admin = admin;
      util = admin.getUtil();
      config = util.getRuntime().getConfig();
      scopes = new TokenScopeStore(config);
   }



   /*******************************************************************************
    ** Review all constraints, without exchanging or creating a credential.
    *******************************************************************************/
   public AdminPlan plan(AdminPlan plan) throws QException
   {
      AdminRequest request = plan.getRequest();
      AdminAction action = request.action();
      util.getRuntime().invalidateCache();
      try
      {
         if(action == AdminAction.CREATE_SERVICE_ACCOUNT)
         {
            if(!request.str("name").matches("[A-Za-z0-9][A-Za-z0-9._-]{0,99}"))
            {
               return (plan.refuse("A service-account name (letters, numbers, dot, dash or underscore) is required."));
            }
            if(admin.userPkByUsername(request.str("name")) != null)
            {
               return (plan.refuse("That username already exists."));
            }
            JSONObject candidate = new JSONObject().put("username", request.str("name")).put("type", "service_account");
            checkProtected(candidate);
            expiry(request, true);
            if(!TokenKeyDelivery.get().available())
            {
               return (plan.refuse(DELIVERY_UNAVAILABLE));
            }
            for(GroupGraph.Node group : serviceGroups(request))
            {
               String problem = admin.checkGroupGrantable(group);
               if(problem != null)
               {
                  return (plan.refuse(problem));
               }
               checkProtectedGroup(group);
            }
            plan.withTargetLabel(request.str("name"));
            return (approval(plan));
         }

         JSONObject token = action == AdminAction.CREATE_TOKEN ? null : token(request.targetKey());
         Integer operatorPk = admin.operator().pk();
         int ownerPk = token == null ? (operatorPk == null ? -1 : operatorPk) : ownerPk(token);
         if(action == AdminAction.CREATE_TOKEN && (!request.targetKey().isBlank() && !request.targetKey().equals(String.valueOf(operatorPk))))
         {
            return (plan.refuse("Create Token only creates a token for you."));
         }
         if(ownerPk < 0)
         {
            return (plan.refuse(OAuth2SubjectTokenSource.UNAVAILABLE));
         }
         JSONObject owner = owner(ownerPk);
         boolean own = Objects.equals(operatorPk, ownerPk);
         boolean service = "service_account".equals(owner.optString("type"));
         boolean manager = AuthentikGuard.has(QContext.getQSession(), IdentityPermission.TOKENS_MANAGE);
         if(service && action == AdminAction.CREATE_TOKEN)
         {
            return (plan.refuse("Service accounts have one app password. Use Rotate Token or Create Service Account."));
         }
         if(!own && !manager || service && !manager)
         {
            return (plan.refuse("You may only manage your own tokens; service accounts need authentik.tokens.manage."));
         }
         if(!own && !service && action != AdminAction.REVOKE_TOKEN)
         {
            return (plan.refuse("You cannot create, rotate or extend another person's token."));
         }
         checkProtected(owner);
         plan.withTargetLabel(token == null ? owner.getString("username") : request.targetKey());
         if(action != AdminAction.REVOKE_TOKEN && token != null && !"app_password".equals(token.optString("intent")))
         {
            return (plan.refuse("Only app-password tokens can be rotated or extended here. API tokens can be revoked."));
         }
         if(action == AdminAction.CREATE_TOKEN || action == AdminAction.EXTEND_TOKEN)
         {
            expiry(request, service);
         }
         if(action == AdminAction.ROTATE_TOKEN)
         {
            checkExpiry(token, service);
         }
         if(action == AdminAction.CREATE_TOKEN)
         {
            if(request.str("description").isBlank())
            {
               return (plan.refuse("A description is required."));
            }
            if(!Boolean.TRUE.equals(config.getTokenScopesEnabled()) && TokenScopeStore.SCOPE_FIELDS.stream().anyMatch(request.params()::containsKey))
            {
               return (plan.refuse("Scopes are not enabled on this app yet."));
            }
         }
         if(action == AdminAction.CREATE_TOKEN && Boolean.TRUE.equals(config.getTokenScopesEnabled()))
         {
            com.kingsrook.qbits.authentik.security.AuthentikTokenScopes.validate(request);
            QRecord scope = new QRecord();
            request.params().forEach(scope::setValue);
            plan.withChange(null, TokenScopeStore.summary(scope));
         }
         if(action == AdminAction.CREATE_TOKEN || action == AdminAction.ROTATE_TOKEN)
         {
            if(!TokenKeyDelivery.get().available())
            {
               return (plan.refuse(DELIVERY_UNAVAILABLE));
            }
         }
         if(own && !service)
         {
            if(blank(config.getTokenBrokerClientId()) || blank(config.getTokenBrokerClientSecret()))
            {
               return (plan.refuse("Self-service tokens need a configured Authentik token broker."));
            }
            if(config.getSubjectTokenSource() == null || blank(config.getSubjectTokenSource().subjectToken(QContext.getQSession())))
            {
               return (plan.refuse(OAuth2SubjectTokenSource.UNAVAILABLE));
            }
         }
         return (service && action == AdminAction.ROTATE_TOKEN ? approval(plan) : plan);
      }
      catch(QUserFacingException e)
      {
         return (plan.refuse(e.getMessage()));
      }
   }



   /*******************************************************************************
    ** Optional approval for new service accounts and service-account rotation.
    *******************************************************************************/
   private AdminPlan approval(AdminPlan plan)
   {
      if(Boolean.TRUE.equals(config.getTokenTwoPersonApproval()) && !plan.getRequest().bool("approved"))
      {
         plan.withState(AdminPlan.State.NEEDS_APPROVAL).withMessage("Service-account tokens require a second person's approval.");
      }
      return (plan);
   }



   /*******************************************************************************
    ** Resolve requested groups with the same subset rules used for membership.
    *******************************************************************************/
   private List<GroupGraph.Node> serviceGroups(AdminRequest request) throws QException
   {
      Set<String> names = new LinkedHashSet<>(AuthentikSafety.parseList(request.str("groups")));
      GroupGraph graph = util.groupGraph();
      List<GroupGraph.Node> groups = new ArrayList<>();
      for(String name : names)
      {
         GroupGraph.Node node = graph.byName(name);
         if(node == null)
         {
            throw (new QUserFacingException("Group not found: " + name));
         }
         groups.add(node);
      }
      return (groups);
   }



   /*******************************************************************************
    ** Required expiry measured from now, with separate human and service caps.
    *******************************************************************************/
   private Instant expiry(AdminRequest request, boolean service) throws QUserFacingException
   {
      int maximum = service ? config.getTokenMaxDaysServiceAccount() : config.getTokenMaxDaysUser();
      try
      {
         int days = Integer.parseInt(request.str("expiresInDays"));
         if(days >= 1 && days <= maximum)
         {
            return (Instant.now().plus(days, ChronoUnit.DAYS));
         }
      }
      catch(NumberFormatException ignored)
      {
         // Missing, fractional and malformed values are all refused.
      }
      throw (new QUserFacingException("Expiry is required: expiresInDays must be between 1 and " + maximum + "."));
   }



   /*******************************************************************************
    ** Rotation preserves a valid existing expiry, never a non-expiring token.
    *******************************************************************************/
   private Instant checkExpiry(JSONObject token, boolean service) throws QUserFacingException
   {
      try
      {
         Instant expires = Instant.parse(token.getString("expires"));
         if(token.optBoolean("expiring") && expires.isAfter(Instant.now())
            && !expires.isAfter(Instant.now().plus(service ? config.getTokenMaxDaysServiceAccount() : config.getTokenMaxDaysUser(), ChronoUnit.DAYS)))
         {
            return (expires);
         }
      }
      catch(RuntimeException ignored)
      {
         // No expiry is never acceptable for a new credential.
      }
      throw (new QUserFacingException("Token expiry is missing, expired or exceeds the maximum lifetime."));
   }



   /*******************************************************************************
    ** Built-in protected groups cannot be removed by configuration.
    *******************************************************************************/
   private void checkProtectedGroup(GroupGraph.Node group) throws QException
   {
      Set<String> protectedNames = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
      protectedNames.addAll(List.of("authentik Admins", "identity-admins"));
      if(config.getTokenProtectedGroups() != null)
      {
         protectedNames.addAll(config.getTokenProtectedGroups());
      }
      for(GroupGraph.Node ancestor : util.groupGraph().selfAndAncestors(group.pk()))
      {
         if(ancestor.ownSuperuser() || protectedNames.contains(ancestor.name()))
         {
            throw (protectedAccount("member of " + ancestor.name()));
         }
      }
   }



   /*******************************************************************************
    ** Reuse account protection, adding inherited protected-group membership.
    *******************************************************************************/
   private void checkProtected(JSONObject owner) throws QException
   {
      AuthentikGuard.ProtectionResult protection = util.getRuntime().getGuard().protection(owner);
      if(protection.isProtected())
      {
         throw (protectedAccount(protection.reason()));
      }
      JSONArray groups = owner.optJSONArray("groups_obj");
      for(int i = 0; groups != null && i < groups.length(); i++)
      {
         GroupGraph.Node node = util.groupGraph().byPk(groups.getJSONObject(i).getString("pk"));
         if(node == null)
         {
            throw (protectedAccount("group protection could not be verified"));
         }
         checkProtectedGroup(node);
      }
   }



   /*******************************************************************************
    ** Consistent protected-owner refusal, including service-account set_key.
    *******************************************************************************/
   private static QUserFacingException protectedAccount(String reason)
   {
      return (new QUserFacingException("Protected account (" + reason + "): tokens for it are managed in the Authentik admin UI."));
   }



   /*******************************************************************************
    ** Fetch token metadata without retaining a bearer or key.
    *******************************************************************************/
   private JSONObject token(String identifier) throws QException
   {
      util.getRuntime().invalidateCache();
      JSONObject token = util.getApiJsonOrNull(path(identifier));
      if(token == null)
      {
         throw (new QUserFacingException("That token no longer exists."));
      }
      return (token);
   }



   /*******************************************************************************
    ** Token owner pk from the pinned schema.
    *******************************************************************************/
   private static int ownerPk(JSONObject token)
   {
      return (token.has("user") ? token.getInt("user") : token.getJSONObject("user_obj").getInt("pk"));
   }



   /*******************************************************************************
    ** Fetch live owner facts, refusing missing owners.
    *******************************************************************************/
   private JSONObject owner(int pk) throws QException
   {
      util.getRuntime().invalidateCache();
      JSONObject owner = util.getApiJsonOrNull("/core/users/" + pk + "/");
      if(owner == null)
      {
         throw (new QUserFacingException("The token's owner no longer exists."));
      }
      return (owner);
   }



   /*******************************************************************************
    ** Validated token URL component.
    *******************************************************************************/
   private static String path(String identifier) throws QException
   {
      return ("/core/tokens/" + AuthentikAdmin.safeKey(identifier) + "/");
   }



   /*******************************************************************************
    ** Whether a resolved config string is absent.
    *******************************************************************************/
   private static boolean blank(String value)
   {
      return (value == null || value.isBlank());
   }



   /*******************************************************************************
    ** Execute only after auditing has begun; return the key outside audit data.
    *******************************************************************************/
   public AuthentikAdmin.AdminResult perform(AdminPlan plan, WriteAuthorization auth) throws QException
   {
      AdminRequest request = plan.getRequest();
      if((request.action() == AdminAction.CREATE_TOKEN || request.action() == AdminAction.ROTATE_TOKEN || request.action() == AdminAction.CREATE_SERVICE_ACCOUNT)
         && !TokenKeyDelivery.get().available())
      {
         throw (new QUserFacingException(DELIVERY_UNAVAILABLE));
      }
      if(request.action() == AdminAction.CREATE_SERVICE_ACCOUNT)
      {
         return (createServiceAccount(plan, auth));
      }
      JSONObject before = request.action() == AdminAction.CREATE_TOKEN ? null : token(request.targetKey());
      JSONObject owner = owner(before == null ? admin.operator().pk() : ownerPk(before));
      checkProtectedAfterRead(owner);
      boolean service = "service_account".equals(owner.optString("type"));
      boolean own = Objects.equals(admin.operator().pk(), owner.getInt("pk"));
      boolean manager = AuthentikGuard.has(QContext.getQSession(), IdentityPermission.TOKENS_MANAGE);
      if((!own || service) && !manager || !own && !service && request.action() != AdminAction.REVOKE_TOKEN)
      {
         throw (new QUserFacingException("Token ownership changed; review again."));
      }
      String bearer = own && !service ? new AuthentikTokenBroker().exchange(util, auth) : config.getResolvedApiToken();
      switch(request.action())
      {
         case CREATE_TOKEN:
            return (createPersonal(request, owner, expiry(request, false), null, bearer, auth));
         case REVOKE_TOKEN:
            util.writeAs(bearer, auth, "DELETE", path(request.targetKey()), null);
            scopes.delete(request.targetKey());
            return (success("Token revoked."));
         case EXTEND_TOKEN:
            util.writeAs(bearer, auth, "PATCH", path(request.targetKey()), new JSONObject().put("intent", before.getString("intent"))
               .put("user", owner.getInt("pk")).put("expires", expiry(request, service).toString()).put("expiring", true));
            raceGuard(before, token(request.targetKey()));
            scopes.resetReminders(request.targetKey());
            return (success("Token expiry updated."));
         case ROTATE_TOKEN:
            if(!service)
            {
               return (createPersonal(request, owner, checkExpiry(before, false), before, bearer, auth));
            }
            String scope = scopeSummary(request.targetKey());
            Instant expires = checkExpiry(before, true);
            byte[] random = new byte[48];
            RANDOM.nextBytes(random);
            String key = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
            util.writeAs(bearer, auth, "POST", path(request.targetKey()) + "set_key/", new JSONObject().put("key", key));
            JSONObject after = token(request.targetKey());
            raceGuard(before, after);
            return (success("Service-account token rotated. The old key no longer works.")
               .withSecret(oneTime(request.targetKey(), key, owner, expires, scope), () ->
               {
                  throw (new QUserFacingException("The old key no longer works and the new key is lost. Rotate it in the Authentik admin UI."));
               }));
         default:
            throw (new QException("Unsupported token action"));
      }
   }



   /*******************************************************************************
    ** Guard owner and intent after every PATCH or set_key, with a safe warning.
    *******************************************************************************/
   private void raceGuard(JSONObject before, JSONObject after) throws QException
   {
      if(ownerPk(before) != ownerPk(after) || !before.getString("intent").equals(after.getString("intent")))
      {
         alertGuardBypass();
         LOG.warn(TOKEN_MOVED);
         throw (new QUserFacingException(TOKEN_MOVED));
      }
      checkProtectedAfterRead(owner(ownerPk(after)));
   }



   /*******************************************************************************
    ** Create as the operator, fetch their key, and optionally replace the old id.
    ** On partial failure discard the new credential; the old one stays usable.
    *******************************************************************************/
   private AuthentikAdmin.AdminResult createPersonal(AdminRequest request, JSONObject owner, Instant expires, JSONObject old,
      String bearer, WriteAuthorization auth) throws QException
   {
      String identifier = identifier(owner.getString("username"));
      String description = old == null ? request.str("description") : old.optString("description");
      util.writeAs(bearer, auth, "POST", "/core/tokens/", new JSONObject().put("identifier", identifier).put("intent", "app_password")
         .put("description", description).put("expiring", true).put("expires", expires.toString()));
      try
      {
         JSONObject created = util.getAs(bearer, auth, path(identifier));
         checkProtectedAfterRead(owner(ownerPk(created)));
         if(ownerPk(created) != owner.getInt("pk") || !"app_password".equals(created.optString("intent")))
         {
            throw (new QUserFacingException(TOKEN_MOVED));
         }
         String key = util.getAs(bearer, auth, path(identifier) + "view_key/").getString("key");
         Instant actualExpiry = checkExpiry(created, false);
         if(old == null)
         {
            scopes.create(identifier, owner, request, admin.operator().email());
         }
         else
         {
            QRecord previous = scopes.find(request.targetKey());
            if(previous == null)
            {
               scopes.create(identifier, owner, AdminRequest.of(request.action(), identifier, request.reason()), admin.operator().email());
            }
            else
            {
               scopes.move(request.targetKey(), identifier);
            }
         }
         OneTimeKey secret = oneTime(identifier, key, owner, actualExpiry, scopeSummary(identifier));
         if(old != null)
         {
            try
            {
               util.writeAs(bearer, auth, "DELETE", path(request.targetKey()), null);
            }
            catch(QException e)
            {
               scopes.move(identifier, request.targetKey());
               throw (new QUserFacingException("Rotation failed: the old token could not be deleted and remains listed."));
            }
         }
         return (success(old == null ? "Token created. The key is shown once." : "Token rotated. The old token was deleted.")
            .withSecret(secret, () -> revokeIssued(identifier, bearer, auth)));
      }
      catch(Exception e)
      {
         revokeIssued(identifier, bearer, auth);
         if(e instanceof QUserFacingException facing)
         {
            throw (facing);
         }
         throw (new QUserFacingException("The new token could not be completed and was revoked."));
      }
   }



   /*******************************************************************************
    ** Create the single service-account app password and grant checked groups.
    *******************************************************************************/
   private AuthentikAdmin.AdminResult createServiceAccount(AdminPlan plan, WriteAuthorization auth) throws QException
   {
      AdminRequest request = plan.getRequest();
      String identifier = "service-account-" + request.str("name") + "-password";
      JSONObject created = util.write(auth, "POST", "/core/users/service_account/", new JSONObject().put("name", request.str("name"))
         .put("create_group", false).put("expiring", true).put("expires", expiry(request, true).toString()));
      try
      {
         Integer pk = created.has("user_pk") ? created.getInt("user_pk") : admin.userPkByUsername(created.optString("username", request.str("name")));
         if(pk == null)
         {
            throw (new QException("The service account could not be found."));
         }
         JSONObject current = owner(pk);
         JSONObject attributes = new JSONObject(current.optJSONObject("attributes") == null ? "{}" : current.getJSONObject("attributes").toString());
         attributes.put("goauthentik.io/user/token-maximum-lifetime", config.getServiceAccountTokenLifetime());
         util.write(auth, "PATCH", "/core/users/" + pk + "/", new JSONObject().put("attributes", attributes));
         for(GroupGraph.Node group : serviceGroups(request))
         {
            checkProtectedGroup(group);
            String problem = admin.checkGroupGrantable(group);
            if(problem != null)
            {
               throw (new QUserFacingException(problem));
            }
            util.write(auth, "POST", "/core/groups/" + AuthentikAdmin.safeKey(group.pk()) + "/add_user/", new JSONObject().put("pk", pk));
         }
         JSONObject owner = owner(pk);
         checkProtectedAfterRead(owner);
         JSONObject after = token(identifier);
         checkProtectedAfterRead(owner(ownerPk(after)));
         scopes.create(identifier, owner, request, admin.operator().email());
         return (success("Service account created. " + String.join(" ", plan.getNotes()))
            .withSecret(oneTime(identifier, created.getString("token"), owner, checkExpiry(after, true), "Owner permissions"),
               () -> revokeIssued(identifier, config.getResolvedApiToken(), auth)));
      }
      catch(Exception e)
      {
         revokeIssued(identifier, config.getResolvedApiToken(), auth);
         throw (new QUserFacingException("The service account was created, but setup failed. Its token was revoked; finish setup in Authentik."));
      }
   }



   /*******************************************************************************
    ** Emergency revocation for a newly created token whose key cannot be shown.
    *******************************************************************************/
   private void revokeIssued(String identifier, String bearer, WriteAuthorization auth) throws QException
   {
      try
      {
         util.writeAs(bearer, auth, "DELETE", path(identifier), null);
         scopes.delete(identifier);
      }
      catch(QException e)
      {
         throw (new QUserFacingException("The new key could not be delivered and token revocation failed. Revoke it in the Authentik admin UI."));
      }
   }



   /*******************************************************************************
    ** Scope summary contains metadata only.
    *******************************************************************************/
   private String scopeSummary(String identifier) throws QException
   {
      QRecord row = scopes.find(identifier);
      List<String> parts = new ArrayList<>();
      for(String field : TokenScopeStore.SCOPE_FIELDS)
      {
         if(row != null && row.getValue(field) != null)
         {
            parts.add(field + ": " + row.getValueString(field));
         }
      }
      return (parts.isEmpty() ? "Owner permissions" : String.join("; ", parts));
   }



   /*******************************************************************************
    ** Build the isolated one-time object, including its response-only usage text.
    *******************************************************************************/
   private OneTimeKey oneTime(String identifier, String key, JSONObject owner, Instant expires, String scope)
   {
      return (new OneTimeKey(identifier, key, TokenUsageText.build(config, owner.getString("username"), key, expires, scope)));
   }



   /*******************************************************************************
    ** Non-secret result text.
    *******************************************************************************/
   private static AuthentikAdmin.AdminResult success(String message)
   {
      return (new AuthentikAdmin.AdminResult(true, false, false, message, null));
   }



   /*******************************************************************************
    ** Collision-resistant identifier, independent of the secret value.
    *******************************************************************************/
   private static String identifier(String username)
   {
      String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
      StringBuilder suffix = new StringBuilder();
      for(int i = 0; i < 6; i++)
      {
         suffix.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
      }
      String slug = username.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9-]+", "-");
      return ("qqq-pat-" + slug + "-" + DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC).format(Instant.now()) + "-" + suffix);
   }
   /*******************************************************************************
    ** A protected owner observed after Review or a write is a guard incident.
    *******************************************************************************/
   private void checkProtectedAfterRead(JSONObject owner) throws QException
   {
      try
      {
         checkProtected(owner);
      }
      catch(QUserFacingException e)
      {
         alertGuardBypass();
         throw (e);
      }
   }

   /*******************************************************************************
    ** Safe incident payload: no response bodies, credentials or owner details.
    *******************************************************************************/
   private void alertGuardBypass()
   {
      try
      {
         util.getRuntime().getTokenAlerts().send(new AuthentikTokenAlerts.Notice("authentik_token_guard_bypass", "high", null,
            "An access token changed owner or intent, or a protected owner was observed after Review. Investigate in Authentik."));
      }
      catch(RuntimeException e)
      {
         LOG.warn("Access-token guard alert delivery failed.");
      }
   }

}
