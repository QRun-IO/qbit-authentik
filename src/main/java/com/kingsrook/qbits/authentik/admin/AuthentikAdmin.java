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


import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.regex.Pattern;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikJson;
import com.kingsrook.qbits.authentik.client.AuthentikRedactor;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qbits.authentik.security.WriteAuthorization;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.utils.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import static com.kingsrook.qqq.backend.core.logging.LogUtils.logPair;


/*******************************************************************************
 ** Plans and performs every change the qbit makes to Authentik (DESIGN.md
 ** sections 5 and 6.3).
 **
 ** plan() applies the guardrails of section 5.4 against LIVE Authentik data and
 ** the operator's LIVE effective permissions: feature and permission, protected
 ** accounts and groups, no self-edits, the subset (no escalation) rule,
 ** last-admin protection, stale checks, and two-person approval. execute()
 ** plans again (so the rules are checked at preview and again at execute),
 ** writes the audit row BEFORE calling Authentik, sends the change, posts a
 ** custom event naming the human operator, and finishes the audit row. QQQ
 ** never sets, shows or sends a credential: new users and resets go through
 ** Authentik's own emails.
 *******************************************************************************/
public class AuthentikAdmin
{
   private static final QLogger LOG = QLogger.getLogger(AuthentikAdmin.class);

   public static final int  MAX_BULK        = 100;
   public static final int  TYPED_ABOVE     = 25;
   public static final int  APPROVAL_HOURS  = 24;

   private static final Pattern UUID_PATTERN = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
   private static final Pattern USERNAME     = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._@+-]{0,149}");
   private static final Pattern EMAIL        = Pattern.compile("[^@\\s]+@[^@\\s]+\\.[^@\\s]+");

   private final AuthentikActionUtil  util;
   private final AuthentikRuntime     runtime;
   private final AuthentikQBitConfig  config;
   private final AuthentikGuard       guard;
   private final AdminActionAuditor   auditor;

   private Operator       operator;
   private GroupGraph     graph;
   private GroupGraph     membersGraph;
   private List<AuthentikSafety.UserFacts> userFacts;



   /*******************************************************************************
    ** The operator performing the request: who they are in Authentik and what
    ** they may grant (live, from their current groups).
    **
    ** @param email       the QQQ user (an email in Authentik-signed-in apps)
    ** @param pk          the operator's Authentik user pk, or null when not found
    ** @param permissions effective QQQ permissions (session form)
    ** @param appAccess   app keys the operator can sign in to
    ** @param bootstrap   listed in bootstrapOperatorSubjects
    *******************************************************************************/
   public record Operator(String email, Integer pk, Set<String> permissions, Set<String> appAccess, boolean bootstrap)
   {
   }



   /*******************************************************************************
    ** The result of executing one plan.
    **
    ** @param ok       whether the change was made (or queued)
    ** @param pending  true when queued for a second person
    ** @param noChange true when the target was already in the wanted state
    ** @param message  what happened, for the operator
    ** @param eventPk  the Authentik audit event, when posted
    *******************************************************************************/
   public record AdminResult(boolean ok, boolean pending, boolean noChange, String message, String eventPk)
   {
   }



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   public AuthentikAdmin(AuthentikActionUtil util)
   {
      this.util = util;
      this.runtime = util.getRuntime();
      this.config = runtime.getConfig();
      this.guard = runtime.getGuard();
      this.auditor = new AdminActionAuditor(config);
   }



   /*******************************************************************************
    ** An admin for the current instance's qbit backend.
    *******************************************************************************/
   public static AuthentikAdmin forBackend(String backendName) throws QException
   {
      return (new AuthentikAdmin(AuthentikActionUtil.forBackend(backendName)));
   }



   /*******************************************************************************
    ** Getter for util (readers that need raw Authentik reads).
    *******************************************************************************/
   public AuthentikActionUtil getUtil()
   {
      return (util);
   }



   /*******************************************************************************
    ** The operator, resolved once per instance from live Authentik data. When
    ** the operator is not an Authentik user (static or development sessions),
    ** the session's own permissions stand in. bootstrapOperatorSubjects additionally
    ** hold every authentik.* permission.
    *******************************************************************************/
   public Operator operator() throws QException
   {
      if(operator != null)
      {
         return (operator);
      }

      String      email       = guard.operatorEmail();
      boolean     bootstrap   = email != null && com.kingsrook.qbits.authentik.security.BootstrapOperators.matchesUniqueUser(config.getResolvedBootstrapSubjects(), util, email);
      Integer     pk          = null;
      Set<String> permissions = new TreeSet<>();
      Set<String> appAccess   = new TreeSet<>();

      JSONObject user = email == null ? null : findUserByEmail(email);
      if(user != null)
      {
         pk = user.optInt("pk");
         List<String> groupPks = new ArrayList<>();
         JSONArray    groups   = user.optJSONArray("groups_obj");
         for(int i = 0; groups != null && i < groups.length(); i++)
         {
            groupPks.add(groups.getJSONObject(i).optString("pk"));
         }
         EffectivePermissionResolver.Resolution resolution = resolver().resolveGroups(groupPks);
         permissions.addAll(resolution.sessionPermissions());
         appAccess.addAll(resolution.appAccess());
      }
      else if(QContext.getQSession() != null && QContext.getQSession().getPermissions() != null)
      {
         permissions.addAll(QContext.getQSession().getPermissions());
      }

      if(bootstrap)
      {
         for(IdentityPermission permission : IdentityPermission.values())
         {
            permissions.add(permission.getSessionPermission());
         }
      }
      operator = new Operator(email, pk, permissions, appAccess, bootstrap);
      return (operator);
   }



   /*******************************************************************************
    ** Plan a request: apply every rule against live data and say what would
    ** happen. Never changes anything.
    *******************************************************************************/
   public AdminPlan plan(AdminRequest request) throws QException
   {
      AdminPlan   plan   = new AdminPlan(request);
      AdminAction action = request.action();

      try
      {
         guard.authorize(action);
      }
      catch(QPermissionDeniedException e)
      {
         return (plan.refuse(e.getMessage()));
      }

      if(!StringUtils.hasContent(request.reason()))
      {
         return (plan.refuse("A reason is required for every change."));
      }

      return switch(action)
      {
         case CREATE_USER -> planCreateUser(plan, request);
         case INVITE_USER -> planInvite(plan, request);
         case CANCEL_INVITATION -> planCancelInvitation(plan, request);
         case EDIT_USER -> planEditUser(plan, request);
         case DEACTIVATE_USER, REACTIVATE_USER -> planActive(plan, request);
         case ADD_MEMBER, REMOVE_MEMBER -> planMembership(plan, request);
         case CREATE_GROUP -> planCreateGroup(plan, request);
         case EDIT_GROUP -> planEditGroup(plan, request);
         case EDIT_PERMISSIONS -> planEditPermissions(plan, request);
         case SEND_RECOVERY_EMAIL -> planRecovery(plan, request);
         case RESET_MFA -> planResetMfa(plan, request);
         case REVOKE_APP_PASSWORDS -> planAppPasswords(plan, request);
         case REVOKE_SESSIONS -> planSessions(plan, request);
      };
   }



   /*******************************************************************************
    ** Plan again against live data, then perform. Refusals and failures are
    ** audited; a change that needs a second person is queued instead.
    *******************************************************************************/
   public AdminResult execute(AdminRequest request) throws QException
   {
      runtime.invalidateCache();
      graph = null;
      membersGraph = null;
      userFacts = null;
      return (execute(plan(request), null));
   }



   /*******************************************************************************
    ** Perform a plan. approver is the second person when this is the
    ** application of an approved request, else null.
    *******************************************************************************/
   public AdminResult execute(AdminPlan plan, String approver) throws QException
   {
      String      correlationId = UUID.randomUUID().toString();
      String      operatorName  = guard.operatorEmail();
      AdminAction action        = plan.getRequest().action();

      switch(plan.getState())
      {
         case REFUSED:
            tryAudit(plan, correlationId, operatorName, AuthentikLocalTables.ActionStatus.REFUSED, approver);
            return (new AdminResult(false, false, false, plan.getMessage(), null));
         case NO_CHANGE:
            return (new AdminResult(true, false, true, plan.getMessage(), null));
         case NEEDS_APPROVAL:
            return (queueApproval(plan, correlationId, operatorName));
         default:
            break;
      }

      WriteAuthorization authorization = guard.authorize(action);
      Serializable       auditId       = auditor.begin(plan, correlationId, operatorName, AuthentikLocalTables.ActionStatus.RUNNING, approver);

      String message;
      try
      {
         message = perform(plan, authorization, correlationId);
      }
      catch(Exception e)
      {
         String text = AuthentikRedactor.redactText(e.getMessage(), config.getResolvedApiToken());
         LOG.warn("Authentik change failed", logPair("action", action.name()), logPair("target", plan.getTargetLabel()), logPair("error", text));
         try
         {
            auditor.finish(auditId, AuthentikLocalTables.ActionStatus.FAILED, text, null, approver);
         }
         catch(Exception auditException)
         {
            LOG.warn("Could not mark the audit row failed", logPair("id", auditId));
         }
         return (new AdminResult(false, false, false, text, null));
      }

      String eventPk = postEvent(authorization, plan, correlationId, operatorName, approver);
      try
      {
         auditor.finish(auditId, AuthentikLocalTables.ActionStatus.SUCCEEDED, null, eventPk, approver);
      }
      catch(Exception e)
      {
         LOG.warn("Could not mark the audit row succeeded", logPair("id", auditId));
      }
      return (new AdminResult(true, false, false, message, eventPk));
   }



   /*******************************************************************************
    ** Store a change that needs a second person: an approval request plus a
    ** PENDING_APPROVAL audit row. Nothing is sent to Authentik.
    *******************************************************************************/
   private AdminResult queueApproval(AdminPlan plan, String correlationId, String operatorName) throws QException
   {
      auditor.begin(plan, correlationId, operatorName, AuthentikLocalTables.ActionStatus.PENDING_APPROVAL, null);

      QRecord record = new QRecord()
         .withValue("actionName", plan.getRequest().action().name())
         .withValue("targetKey", plan.getRequest().targetKey())
         .withValue("targetLabel", plan.getTargetLabel())
         .withValue("summary", plan.describe())
         .withValue("reason", plan.getRequest().reason())
         .withValue("payloadJson", plan.getRequest().toJson())
         .withValue("requester", operatorName)
         .withValue("status", AuthentikLocalTables.ApprovalStatus.PENDING.name())
         .withValue("expiresDate", Instant.now().plus(APPROVAL_HOURS, ChronoUnit.HOURS))
         .withValue("createDate", Instant.now())
         .withValue("modifyDate", Instant.now());
      InsertInput insertInput = new InsertInput();
      insertInput.setTableName(config.applyTablePrefix(AuthentikLocalTables.APPROVAL_REQUEST));
      insertInput.setRecords(List.of(record));
      new InsertAction().execute(insertInput);
      return (new AdminResult(true, true, false, "Waiting for approval by a second person (" + plan.getMessage() + ").", null));
   }



   /*******************************************************************************
    ** Apply a stored approval request as the approver: a different person who
    ** holds authentik.approve. The change is planned again against live data
    ** under the approver's own permissions.
    *******************************************************************************/
   public AdminResult approve(Serializable approvalId) throws QException
   {
      QRecord request = loadApproval(approvalId);
      String  approver = guard.operatorEmail();
      AdminResult refusal = checkApprover(request, approver);
      if(refusal != null)
      {
         return (refusal);
      }

      AdminRequest stored = AdminRequest.fromJson(request.getValueString("payloadJson")).with("approved", true);
      runtime.invalidateCache();
      AdminPlan plan = plan(stored);
      AdminResult result;
      if(plan.getState() == AdminPlan.State.NEEDS_APPROVAL)
      {
         result = new AdminResult(false, false, false, "The change still needs approval after re-checking.", null);
      }
      else
      {
         result = execute(plan, approver);
      }
      decide(approvalId, result.ok() ? AuthentikLocalTables.ApprovalStatus.APPROVED : AuthentikLocalTables.ApprovalStatus.FAILED, approver, result.ok() ? null : result.message());
      return (result);
   }



   /*******************************************************************************
    ** Reject a stored approval request (a different person with authentik.approve).
    *******************************************************************************/
   public AdminResult reject(Serializable approvalId) throws QException
   {
      QRecord     request  = loadApproval(approvalId);
      String      approver = guard.operatorEmail();
      AdminResult refusal  = checkApprover(request, approver);
      if(refusal != null)
      {
         return (refusal);
      }
      decide(approvalId, AuthentikLocalTables.ApprovalStatus.REJECTED, approver, null);
      return (new AdminResult(true, false, false, "Rejected. Nothing was changed in Authentik.", null));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private QRecord loadApproval(Serializable id) throws QException
   {
      QueryInput queryInput = new QueryInput();
      queryInput.setTableName(config.applyTablePrefix(AuthentikLocalTables.APPROVAL_REQUEST));
      queryInput.setFilter(new QQueryFilter(new QFilterCriteria("id", QCriteriaOperator.EQUALS, id)));
      List<QRecord> records = new QueryAction().execute(queryInput).getRecords();
      if(records.isEmpty())
      {
         throw (new QUserFacingException("That approval request no longer exists."));
      }
      return (records.get(0));
   }



   /*******************************************************************************
    ** Whether the current session may decide a request: not the requester, holds
    ** authentik.approve, still pending and not expired. Returns the refusal, or
    ** null when allowed.
    *******************************************************************************/
   private AdminResult checkApprover(QRecord request, String approver)
   {
      if(!AuthentikLocalTables.ApprovalStatus.PENDING.name().equals(request.getValueString("status")))
      {
         return (new AdminResult(false, false, false, "This request was already decided.", null));
      }
      if(approver == null || !AuthentikGuard.has(QContext.getQSession(), IdentityPermission.APPROVE))
      {
         return (new AdminResult(false, false, false, "You need the authentik.approve permission to decide requests.", null));
      }
      if(approver.equalsIgnoreCase(request.getValueString("requester")))
      {
         return (new AdminResult(false, false, false, "A second person must approve this: you cannot approve your own request.", null));
      }
      Instant expires = request.getValueInstant("expiresDate");
      if(expires != null && expires.isBefore(Instant.now()))
      {
         try
         {
            decide(request.getValue("id"), AuthentikLocalTables.ApprovalStatus.EXPIRED, approver, "expired");
         }
         catch(Exception e)
         {
            LOG.warn("Could not mark an approval request expired");
         }
         return (new AdminResult(false, false, false, "This request expired (" + APPROVAL_HOURS + " hours). Ask for it again.", null));
      }
      return (null);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private void decide(Serializable id, AuthentikLocalTables.ApprovalStatus status, String approver, String error) throws QException
   {
      UpdateInput updateInput = new UpdateInput();
      updateInput.setTableName(config.applyTablePrefix(AuthentikLocalTables.APPROVAL_REQUEST));
      updateInput.setRecords(List.of(new QRecord().withValue("id", id).withValue("status", status.name()).withValue("approver", approver)
         .withValue("decidedDate", Instant.now()).withValue("modifyDate", Instant.now()).withValue("errorMessage", error)));
      new UpdateAction().execute(updateInput);
   }



   /*******************************************************************************
    ** Best-effort audit row for a refusal (the refusal itself is returned
    ** regardless).
    *******************************************************************************/
   private void tryAudit(AdminPlan plan, String correlationId, String operatorName, AuthentikLocalTables.ActionStatus status, String approver)
   {
      try
      {
         auditor.begin(plan, correlationId, operatorName, status, approver);
      }
      catch(Exception e)
      {
         LOG.warn("Could not audit a refused change", logPair("action", plan.getRequest().action().name()));
      }
   }



   /*******************************************************************************
    ** Post the custom event to Authentik so its own event log names the human
    ** operator (the service account is the actor of the model events).
    ** Best effort: a failure is logged, never undoes the change.
    *******************************************************************************/
   private String postEvent(WriteAuthorization authorization, AdminPlan plan, String correlationId, String operatorName, String approver)
   {
      JSONObject context = new JSONObject()
         .put("correlationId", correlationId)
         .put("operator", operatorName == null ? "" : operatorName)
         .put("operatorEmail", operatorName == null ? "" : operatorName)
         .put("reason", plan.getRequest().reason())
         .put("action", plan.getRequest().action().name())
         .put("target", plan.getTargetLabel() == null ? plan.getRequest().targetKey() : plan.getTargetLabel())
         .put("appKey", config.getAppKey());
      if(approver != null)
      {
         context.put("approver", approver);
      }

      for(String action : List.of("custom_qqq_admin_action", "custom_"))
      {
         try
         {
            JSONObject response = util.write(authorization, "POST", "/events/events/", new JSONObject().put("action", action).put("app", "qqq").put("context", context));
            return (response.optString("pk", null));
         }
         catch(Exception e)
         {
            LOG.info("Could not post the Authentik audit event", logPair("action", action), logPair("error", AuthentikRedactor.redactText(e.getMessage(), config.getResolvedApiToken())));
         }
      }
      return (null);
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // planning
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Create a user. Groups are checked like memberships; no password is set.
    *******************************************************************************/
   private AdminPlan planCreateUser(AdminPlan plan, AdminRequest request) throws QException
   {
      String username = request.str("username");
      String email    = request.str("email");
      String name     = request.str("name");

      if(!USERNAME.matcher(username).matches())
      {
         return (plan.refuse("Enter a username (letters, digits and . _ @ + -)."));
      }
      if(!EMAIL.matcher(email).matches())
      {
         return (plan.refuse("Enter a valid email address: the person sets their own password from a link sent there."));
      }
      if(!StringUtils.hasContent(name))
      {
         return (plan.refuse("Enter the person's name."));
      }
      if(findUserByUsername(username) != null)
      {
         return (plan.refuse("A user named " + username + " already exists."));
      }
      if(findUserByEmail(email) != null)
      {
         return (plan.refuse("A user with the email " + email + " already exists."));
      }

      plan.withTargetLabel(username);
      List<String> groupNames = AuthentikSafety.parseList(request.str("groups"));
      List<String> labels     = new ArrayList<>();
      for(String groupName : groupNames)
      {
         GroupGraph.Node node = graph().byName(groupName);
         if(node == null)
         {
            return (plan.refuse("No group named " + groupName + "."));
         }
         String problem = checkGroupGrantable(node);
         if(problem != null)
         {
            return (plan.refuse(problem));
         }
         labels.add(groupName);
      }

      boolean recovery = !request.params().containsKey("sendRecovery") || request.bool("sendRecovery");
      if(recovery && !StringUtils.hasContent(config.getRecoveryEmailStage()))
      {
         return (plan.refuse("The password email is not configured (recoveryEmailStage)."));
      }
      plan.withChange("(new)", username + " <" + email + ">" + (labels.isEmpty() ? "" : ", in " + String.join(", ", labels)));
      plan.getNotes().add(recovery ? email + " receives an email from Authentik to set their own password. QQQ never sees it." : "No password email is sent; use Send password reset email later.");
      return (plan);
   }



   /*******************************************************************************
    ** Invite a user: an Authentik invitation (single use, 7 days) and its email.
    *******************************************************************************/
   private AdminPlan planInvite(AdminPlan plan, AdminRequest request) throws QException
   {
      if(!StringUtils.hasContent(config.getInvitationFlow()))
      {
         return (plan.refuse("Invitations are not configured (invitationFlow)."));
      }
      String email = request.str("email");
      if(!EMAIL.matcher(email).matches())
      {
         return (plan.refuse("Enter a valid email address."));
      }
      if(findUserByEmail(email) != null)
      {
         return (plan.refuse("A user with the email " + email + " already exists."));
      }
      plan.withTargetLabel(email).withChange(null, "invitation to " + email + " (single use, expires in 7 days)");
      plan.getNotes().add("Group memberships are added after the person has signed up (Add to group).");
      return (plan);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AdminPlan planCancelInvitation(AdminPlan plan, AdminRequest request) throws QException
   {
      JSONObject invitation = util.getApiJsonOrNull("/stages/invitation/invitations/" + safeKey(request.targetKey()) + "/");
      if(invitation == null)
      {
         return (plan.noChange("The invitation no longer exists."));
      }
      return (plan.withTargetLabel(invitation.optString("name", request.targetKey())).withChange("invitation open", "cancelled"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AdminPlan planEditUser(AdminPlan plan, AdminRequest request) throws QException
   {
      JSONObject user = targetUser(plan, request.targetKey(), false);
      if(user == null)
      {
         return (plan);
      }
      String name  = request.params().containsKey("name") ? request.str("name") : user.optString("name");
      String email = request.params().containsKey("email") ? request.str("email") : user.optString("email");
      String path  = request.params().containsKey("path") ? request.str("path") : user.optString("path");
      if(!StringUtils.hasContent(name))
      {
         return (plan.refuse("The name cannot be empty."));
      }
      if(StringUtils.hasContent(email) && !EMAIL.matcher(email).matches())
      {
         return (plan.refuse("Enter a valid email address."));
      }
      if(StringUtils.hasContent(email) && !email.equalsIgnoreCase(user.optString("email")))
      {
         JSONObject other = findUserByEmail(email);
         if(other != null && other.optInt("pk") != user.optInt("pk"))
         {
            return (plan.refuse("Another user already has the email " + email + "."));
         }
      }
      if(!StringUtils.hasContent(path))
      {
         return (plan.refuse("The path cannot be empty."));
      }
      String fingerprint = request.str("expectedFingerprint");
      if(StringUtils.hasContent(fingerprint) && !fingerprint.equals(AuthentikSafety.userFingerprint(user)))
      {
         return (plan.refuse("This user was changed (for example in the Authentik admin UI) since you opened it. Review it again."));
      }

      String before = user.optString("name") + " <" + user.optString("email") + ">, " + user.optString("path");
      String after  = name + " <" + email + ">, " + path;
      if(before.equals(after))
      {
         return (plan.noChange("Nothing to change."));
      }
      return (plan.withChange(before, after));
   }



   /*******************************************************************************
    ** Deactivate or reactivate.
    *******************************************************************************/
   private AdminPlan planActive(AdminPlan plan, AdminRequest request) throws QException
   {
      boolean    deactivate = request.action() == AdminAction.DEACTIVATE_USER;
      JSONObject user       = targetUser(plan, request.targetKey(), true);
      if(user == null)
      {
         return (plan);
      }
      boolean active = user.optBoolean("is_active", true);
      if(deactivate && !active)
      {
         return (plan.noChange("Already inactive."));
      }
      if(!deactivate && active)
      {
         return (plan.noChange("Already active."));
      }

      if(deactivate)
      {
         String typed = typedProblem(request, user.optString("username"));
         if(typed != null)
         {
            return (plan.refuse(typed));
         }
         Set<Integer> before = adminsNow();
         if(before.contains(user.optInt("pk")))
         {
            List<AuthentikSafety.UserFacts> changed = new ArrayList<>();
            for(AuthentikSafety.UserFacts facts : userFacts())
            {
               changed.add(facts.pk() == user.optInt("pk") ? new AuthentikSafety.UserFacts(facts.pk(), false, facts.human(), facts.protectedAccount()) : facts);
            }
            if(AuthentikSafety.removesLastAdmin(before, AuthentikSafety.qualifyingAdmins(membersGraph(), new EffectivePermissionResolver(membersGraph(), runtime.getPermissionCatalog()), changed)))
            {
               return (plan.refuse("This is the last active person who can manage memberships and permissions. Add another administrator first."));
            }
         }
         plan.getNotes().add("Their sessions end now" + (request.bool("revokeAppPasswords") ? " and their app passwords are revoked." : "."));
      }
      return (plan.withChange(active ? "active" : "inactive", deactivate ? "inactive" : "active"));
   }



   /*******************************************************************************
    ** Add or remove one membership; the key is "groupPk:userPk".
    *******************************************************************************/
   private AdminPlan planMembership(AdminPlan plan, AdminRequest request) throws QException
   {
      boolean add   = request.action() == AdminAction.ADD_MEMBER;
      String[] parts = request.targetKey().split(":", 2);
      if(parts.length != 2)
      {
         return (plan.refuse("Bad membership key."));
      }
      JSONObject user = targetUser(plan, parts[1], false);
      if(user == null)
      {
         return (plan);
      }
      GroupGraph.Node node = graph().byPk(parts[0]);
      if(node == null)
      {
         return (plan.refuse("That group no longer exists."));
      }
      plan.withTargetLabel(user.optString("username") + " / " + node.name());

      boolean member = false;
      JSONArray groups = user.optJSONArray("groups_obj");
      for(int i = 0; groups != null && i < groups.length(); i++)
      {
         if(parts[0].equals(groups.getJSONObject(i).optString("pk")))
         {
            member = true;
         }
      }

      if(add)
      {
         if(member)
         {
            return (plan.noChange("Already a member."));
         }
         String problem = checkGroupGrantable(node);
         if(problem != null)
         {
            return (plan.refuse(problem));
         }
         return (plan.withChange("not a member", "member of " + node.name()));
      }

      if(!member)
      {
         return (plan.noChange("Not a member."));
      }
      if(graph().isSuperuserInherited(node.pk()))
      {
         return (plan.refuse("Superuser groups cannot be managed here (use the Authentik admin UI)."));
      }
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(membersGraph(), runtime.getPermissionCatalog());
      Set<String> conferred = resolver.resolveGroups(List.of(node.pk())).sessionPermissions();
      if(conferred.contains(IdentityPermission.MEMBERSHIPS_MANAGE.getSessionPermission()) || conferred.contains(IdentityPermission.PERMISSIONS_MANAGE.getSessionPermission()))
      {
         Set<Integer> before = adminsNow();
         GroupGraph.Node current = membersGraph().byPk(node.pk());
         Set<Integer> after = AuthentikSafety.qualifyingAdmins(AuthentikSafety.withNodes(membersGraph(), AuthentikSafety.withoutMember(current, user.optInt("pk"))),
            new EffectivePermissionResolver(AuthentikSafety.withNodes(membersGraph(), AuthentikSafety.withoutMember(current, user.optInt("pk"))), runtime.getPermissionCatalog()), userFacts());
         if(AuthentikSafety.removesLastAdmin(before, after))
         {
            return (plan.refuse("This is the last person who can manage memberships and permissions. Add another administrator first."));
         }
      }
      return (plan.withChange("member of " + node.name(), "not a member"));
   }



   /*******************************************************************************
    ** Create a group: name, parents (names), permissions and app access.
    *******************************************************************************/
   private AdminPlan planCreateGroup(AdminPlan plan, AdminRequest request) throws QException
   {
      String name = request.str("name");
      if(!StringUtils.hasContent(name) || name.length() > 200)
      {
         return (plan.refuse("Enter a group name."));
      }
      plan.withTargetLabel(name);
      if(graph().byName(name) != null)
      {
         return (plan.refuse("A group named " + name + " already exists."));
      }

      List<String> parentPks = new ArrayList<>();
      for(String parentName : AuthentikSafety.parseList(request.str("parents")))
      {
         GroupGraph.Node parent = graph().byName(parentName);
         if(parent == null)
         {
            return (plan.refuse("No parent group named " + parentName + "."));
         }
         String problem = checkParentAllowed(parent);
         if(problem != null)
         {
            return (plan.refuse(problem));
         }
         parentPks.add(parent.pk());
      }

      List<String> permissions = AuthentikSafety.parseList(request.str("permissions"));
      List<String> appAccess   = AuthentikSafety.parseList(request.str("appAccess"));
      String       problem     = checkAttributeAdditions(plan, request, permissions, appAccess, List.of(), List.of());
      if(problem != null)
      {
         return (plan.refuse(problem));
      }

      plan.withChange(null, name + (parentPks.isEmpty() ? "" : ", under " + request.str("parents")) + (permissions.isEmpty() ? "" : ", permissions " + String.join(", ", permissions)));
      return (plan);
   }



   /*******************************************************************************
    ** Edit a group's name and parents.
    *******************************************************************************/
   private AdminPlan planEditGroup(AdminPlan plan, AdminRequest request) throws QException
   {
      JSONObject group = targetGroup(plan, request.targetKey());
      if(group == null)
      {
         return (plan);
      }
      GroupGraph.Node node = graph().byPk(request.targetKey());

      String newName = request.str("name");
      if(!StringUtils.hasContent(newName))
      {
         newName = group.optString("name");
      }
      else if(!newName.equals(group.optString("name")) && graph().byName(newName) != null)
      {
         return (plan.refuse("A group named " + newName + " already exists."));
      }

      List<String> currentParents = new ArrayList<>(node.parentPks());
      List<String> newParents     = currentParents;
      String       parentsText    = request.str("parents");
      if(StringUtils.hasContent(parentsText))
      {
         newParents = new ArrayList<>();
         if(!parentsText.equalsIgnoreCase("none"))
         {
            Set<String> descendants = AuthentikSafety.descendantPks(graph(), node.pk());
            for(String parentName : AuthentikSafety.parseList(parentsText))
            {
               GroupGraph.Node parent = graph().byName(parentName);
               if(parent == null)
               {
                  return (plan.refuse("No parent group named " + parentName + "."));
               }
               if(parent.pk().equals(node.pk()) || descendants.contains(parent.pk()))
               {
                  return (plan.refuse(parentName + " is below this group; that would make a loop."));
               }
               if(!currentParents.contains(parent.pk()))
               {
                  String problem = checkParentAllowed(parent);
                  if(problem != null)
                  {
                     return (plan.refuse(problem));
                  }
               }
               newParents.add(parent.pk());
            }
         }
      }

      String fingerprint = request.str("expectedFingerprint");
      if(StringUtils.hasContent(fingerprint) && !fingerprint.equals(AuthentikSafety.groupFingerprint(group)))
      {
         return (plan.refuse("This group was changed (for example in the Authentik admin UI) since you opened it. Review it again."));
      }
      if(newName.equals(group.optString("name")) && new LinkedHashSet<>(newParents).equals(new LinkedHashSet<>(currentParents)))
      {
         return (plan.noChange("Nothing to change."));
      }

      if(!new LinkedHashSet<>(newParents).equals(new LinkedHashSet<>(currentParents)))
      {
         GroupGraph.Node current = membersGraph().byPk(node.pk());
         GroupGraph simulated = AuthentikSafety.withNodes(membersGraph(), AuthentikSafety.withParents(current, newParents));
         Set<Integer> before = adminsNow();
         if(AuthentikSafety.removesLastAdmin(before, AuthentikSafety.qualifyingAdmins(simulated, new EffectivePermissionResolver(simulated, runtime.getPermissionCatalog()), userFacts())))
         {
            return (plan.refuse("Changing the parents would leave nobody able to manage memberships and permissions."));
         }
      }

      plan.getRequest().params().put("resolvedParentPks", String.join(",", newParents));
      return (plan.withChange(group.optString("name") + ", parents " + names(currentParents), newName + ", parents " + names(newParents)));
   }



   /*******************************************************************************
    ** Edit a group's qqq.io/permissions and qqq.io/app-access: the subset rule,
    ** unknown-name rejection, stale check, last-admin protection and (for
    ** authentik.*) two-person approval.
    *******************************************************************************/
   private AdminPlan planEditPermissions(AdminPlan plan, AdminRequest request) throws QException
   {
      JSONObject group = targetGroup(plan, request.targetKey());
      if(group == null)
      {
         return (plan);
      }
      GroupGraph.Node node = graph().byPk(request.targetKey());

      List<String> newPermissions = AuthentikSafety.parseList(request.str("permissions"));
      List<String> newAppAccess   = AuthentikSafety.parseList(request.str("appAccess"));
      List<String> oldPermissions = nonNull(AuthentikJson.stringList(group.optJSONObject("attributes"), AuthentikJson.ATTR_PERMISSIONS));
      List<String> oldAppAccess   = nonNull(AuthentikJson.stringList(group.optJSONObject("attributes"), AuthentikJson.ATTR_APP_ACCESS));

      String fingerprint = request.str("expectedFingerprint");
      if(StringUtils.hasContent(fingerprint) && !fingerprint.equals(AuthentikSafety.groupFingerprint(group)))
      {
         return (plan.refuse("This group was changed (for example in the Authentik admin UI) since you opened it. Review it again."));
      }
      if(new LinkedHashSet<>(newPermissions).equals(new LinkedHashSet<>(oldPermissions)) && new LinkedHashSet<>(newAppAccess).equals(new LinkedHashSet<>(oldAppAccess)))
      {
         return (plan.noChange("Nothing to change."));
      }

      String problem = checkAttributeAdditions(plan, request, newPermissions, newAppAccess, oldPermissions, oldAppAccess);
      if(problem != null)
      {
         return (plan.refuse(problem));
      }

      GroupGraph.Node current   = membersGraph().byPk(node.pk());
      GroupGraph      simulated = AuthentikSafety.withNodes(membersGraph(), AuthentikSafety.withPermissions(current, newPermissions, newAppAccess));
      Set<Integer>    before    = adminsNow();
      if(AuthentikSafety.removesLastAdmin(before, AuthentikSafety.qualifyingAdmins(simulated, new EffectivePermissionResolver(simulated, runtime.getPermissionCatalog()), userFacts())))
      {
         return (plan.refuse("Removing these permissions would leave nobody able to manage memberships and permissions."));
      }

      int members = current == null ? 0 : current.memberPks().size();
      plan.withChange("permissions: " + joinOrNone(oldPermissions) + "; app access: " + joinOrNone(oldAppAccess),
         "permissions: " + joinOrNone(newPermissions) + "; app access: " + joinOrNone(newAppAccess));
      plan.getNotes().add(members + " member(s) get the change at their next session refresh.");

      if(config.getTwoPersonApproval() && !request.bool("approved") && addsIdentityPermission(newPermissions, oldPermissions))
      {
         plan.withState(AdminPlan.State.NEEDS_APPROVAL).withMessage("granting authentik.* needs a second person");
      }
      return (plan);
   }



   /*******************************************************************************
    ** Send the password-reset email (Authentik's own email; no link is shown).
    *******************************************************************************/
   private AdminPlan planRecovery(AdminPlan plan, AdminRequest request) throws QException
   {
      JSONObject user = targetUser(plan, request.targetKey(), false);
      if(user == null)
      {
         return (plan);
      }
      if(!user.optBoolean("is_active", true))
      {
         return (plan.refuse("The user is inactive. Reactivate them first."));
      }
      if(!StringUtils.hasContent(user.optString("email")))
      {
         return (plan.refuse("The user has no email address."));
      }
      if(!StringUtils.hasContent(config.getRecoveryEmailStage()))
      {
         return (plan.refuse("The password email is not configured (recoveryEmailStage)."));
      }
      return (plan.withChange(null, "password reset email to " + user.optString("email")));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AdminPlan planResetMfa(AdminPlan plan, AdminRequest request) throws QException
   {
      JSONObject user = targetUser(plan, request.targetKey(), false);
      if(user == null)
      {
         return (plan);
      }
      String typed = typedProblem(request, user.optString("username"));
      if(typed != null)
      {
         return (plan.refuse(typed));
      }
      int devices = mfaDevices(user.optInt("pk")).size();
      if(devices == 0)
      {
         return (plan.noChange("No MFA devices."));
      }
      return (plan.withChange(devices + " MFA device(s)", "none (they set up MFA again)"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AdminPlan planAppPasswords(AdminPlan plan, AdminRequest request) throws QException
   {
      JSONObject user = targetUser(plan, request.targetKey(), true);
      if(user == null)
      {
         return (plan);
      }
      String typed = typedProblem(request, user.optString("username"));
      if(typed != null)
      {
         return (plan.refuse(typed));
      }
      int tokens = appPasswords(user.optString("username")).size();
      if(tokens == 0)
      {
         return (plan.noChange("No app passwords."));
      }
      return (plan.withChange(tokens + " app password(s)", "none"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AdminPlan planSessions(AdminPlan plan, AdminRequest request) throws QException
   {
      JSONObject user = targetUser(plan, request.targetKey(), false);
      if(user == null)
      {
         return (plan);
      }
      int sessions = sessions(user.optString("username")).size();
      if(sessions == 0)
      {
         return (plan.noChange("No active sessions."));
      }
      return (plan.withChange(sessions + " session(s)", "none (signed out)"));
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // shared rule checks
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Load a target user and apply the user rules: it exists, is in scope, is
    ** not protected, is not the operator, and (unless allowed) is not a service
    ** account. Refuses the plan and returns null when a rule fails.
    **
    ** @param serviceAccountsOk whether service accounts may be targeted
    *******************************************************************************/
   private JSONObject targetUser(AdminPlan plan, String pk, boolean serviceAccountsOk) throws QException
   {
      JSONObject user = util.getObject(AuthentikTables.get(AuthentikTables.USER), pk);
      if(user == null)
      {
         plan.refuse("That user no longer exists.");
         return (null);
      }
      plan.withTargetLabel(user.optString("username"));
      if(!guard.isUserInScope(user))
      {
         plan.refuse("That user is outside the users this app manages.");
         return (null);
      }
      AuthentikGuard.ProtectionResult protection = guard.protection(user);
      if(protection.isProtected())
      {
         plan.refuse("Protected account (" + protection.reason() + "). Use the Authentik admin UI.");
         return (null);
      }
      Operator op = operator();
      if((op.pk() != null && op.pk() == user.optInt("pk")) || (op.email() != null && op.email().equalsIgnoreCase(user.optString("email"))))
      {
         plan.refuse("You cannot change your own account.");
         return (null);
      }
      if("service_account".equals(user.optString("type")) && !serviceAccountsOk)
      {
         plan.refuse("Service accounts can only be deactivated or have their app passwords revoked.");
         return (null);
      }
      return (user);
   }



   /*******************************************************************************
    ** Load a target group (with members) and refuse superuser groups and groups
    ** that inherit superuser status.
    *******************************************************************************/
   private JSONObject targetGroup(AdminPlan plan, String pk) throws QException
   {
      JSONObject group = util.getApiJsonOrNull("/core/groups/" + safeKey(pk) + "/?include_users=true&include_parents=true&include_children=true");
      if(group == null)
      {
         plan.refuse("That group no longer exists.");
         return (null);
      }
      plan.withTargetLabel(group.optString("name"));
      if(graph().byPk(pk) == null)
      {
         plan.refuse("That group is not in this app's scope.");
         return (null);
      }
      if(graph().isSuperuserInherited(pk))
      {
         plan.refuse("Superuser groups (and their descendants) cannot be managed here. Use the Authentik admin UI.");
         return (null);
      }
      return (group);
   }



   /*******************************************************************************
    ** Whether the operator may put people in a group: it is not a superuser
    ** group, and the operator holds everything it confers (the subset rule),
    ** including app access. Returns the refusal text, or null.
    *******************************************************************************/
   private String checkGroupGrantable(GroupGraph.Node node) throws QException
   {
      if(graph().isSuperuserInherited(node.pk()))
      {
         return ("Superuser groups cannot be managed here (use the Authentik admin UI): " + node.name());
      }
      EffectivePermissionResolver.Resolution conferred = resolver().resolveGroups(List.of(node.pk()));
      Set<String> missing = AuthentikSafety.missing(conferred.sessionPermissions(), operator().permissions());
      if(!missing.isEmpty())
      {
         return ("You cannot add people to " + node.name() + " because it grants permissions you do not hold yourself: " + String.join(", ", missing));
      }
      Set<String> apps = AuthentikSafety.missing(conferred.appAccess(), operator().appAccess());
      if(!apps.isEmpty() && !operator().bootstrap())
      {
         return ("You cannot add people to " + node.name() + " because it gives sign-in access to apps you cannot access yourself: " + String.join(", ", apps));
      }
      return (null);
   }



   /*******************************************************************************
    ** Whether a group may become a parent: not a superuser group or descendant,
    ** and its permissions are ones the operator holds. Returns the refusal, or
    ** null.
    *******************************************************************************/
   private String checkParentAllowed(GroupGraph.Node parent) throws QException
   {
      if(graph().isSuperuserInherited(parent.pk()))
      {
         return ("A group cannot be placed under a superuser group (or one of its descendants): " + parent.name());
      }
      Set<String> missing = AuthentikSafety.missing(resolver().resolveGroups(List.of(parent.pk())).sessionPermissions(), operator().permissions());
      if(!missing.isEmpty())
      {
         return ("The parent group " + parent.name() + " grants permissions you do not hold yourself: " + String.join(", ", missing));
      }
      return (null);
   }



   /*******************************************************************************
    ** Check new qqq.io/permissions and qqq.io/app-access values: every entry
    ** must be a known permission (or authentik.*), and every ADDED entry must be
    ** held by the operator (the subset rule); added app keys must be apps the
    ** operator can access. Returns the refusal, or null.
    *******************************************************************************/
   private String checkAttributeAdditions(AdminPlan plan, AdminRequest request, List<String> permissions, List<String> appAccess,
      List<String> oldPermissions, List<String> oldAppAccess) throws QException
   {
      EffectivePermissionResolver resolver = resolver();
      Set<String>                 needed   = new TreeSet<>();
      for(String raw : permissions)
      {
         Set<String> expanded = resolver.expand(raw);
         if(expanded.isEmpty())
         {
            if(!oldPermissions.contains(raw))
            {
               return ("Unknown permission: " + raw + ". Pick a permission this app defines, or authentik.*.");
            }
            continue;
         }
         if(!oldPermissions.contains(raw))
         {
            needed.addAll(expanded);
         }
      }
      Set<String> missing = AuthentikSafety.missing(needed, operator().permissions());
      if(!missing.isEmpty())
      {
         return ("You cannot grant permissions you do not hold yourself: " + String.join(", ", missing));
      }

      for(String app : appAccess)
      {
         if(!oldAppAccess.contains(app) && !operator().appAccess().contains(app) && !operator().bootstrap())
         {
            return ("You cannot give sign-in access to " + app + " because you cannot sign in to it yourself.");
         }
      }
      return (null);
   }



   /*******************************************************************************
    ** Whether the new permission list adds an entry that expands to any
    ** authentik.* permission.
    *******************************************************************************/
   private boolean addsIdentityPermission(List<String> newPermissions, List<String> oldPermissions) throws QException
   {
      EffectivePermissionResolver resolver = resolver();
      for(String raw : newPermissions)
      {
         if(oldPermissions.contains(raw))
         {
            continue;
         }
         for(String expanded : resolver.expand(raw))
         {
            if(expanded.startsWith("authentik."))
            {
               return (true);
            }
         }
      }
      return (false);
   }



   /*******************************************************************************
    ** The typed-confirmation rule: the operator types the target's name.
    ** Returns the refusal, or null.
    *******************************************************************************/
   private String typedProblem(AdminRequest request, String expected)
   {
      if(request.str("confirmText").equalsIgnoreCase(expected) || request.bool("approved"))
      {
         return (null);
      }
      return ("Type the username (" + expected + ") to confirm.");
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // performing
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Send the change to Authentik. Returns the message for the Result step.
    *******************************************************************************/
   private String perform(AdminPlan plan, WriteAuthorization auth, String correlationId) throws QException
   {
      AdminRequest request = plan.getRequest();
      switch(request.action())
      {
         case CREATE_USER:
            return (performCreateUser(plan, auth));
         case INVITE_USER:
         {
            JSONObject body = new JSONObject()
               .put("name", "qqq-" + correlationId.substring(0, 8))
               .put("single_use", true)
               .put("expires", Instant.now().plus(7, ChronoUnit.DAYS).toString())
               .put("fixed_data", new JSONObject().put("email", request.str("email")));
            if(StringUtils.hasContent(request.str("name")))
            {
               body.getJSONObject("fixed_data").put("name", request.str("name"));
            }
            String flow = flowUuid(config.getInvitationFlow());
            if(flow != null)
            {
               body.put("flow", flow);
            }
            JSONObject invitation = util.write(auth, "POST", "/stages/invitation/invitations/", body);
            util.write(auth, "POST", "/stages/invitation/invitations/" + invitation.optString("pk") + "/send_email/",
               new JSONObject().put("email_addresses", new JSONArray().put(request.str("email"))));
            return ("Invitation sent to " + request.str("email") + ".");
         }
         case CANCEL_INVITATION:
            util.write(auth, "DELETE", "/stages/invitation/invitations/" + safeKey(request.targetKey()) + "/", null);
            return ("Invitation cancelled.");
         case EDIT_USER:
         {
            JSONObject body = new JSONObject();
            for(String key : List.of("name", "email", "path"))
            {
               if(request.params().containsKey(key))
               {
                  body.put(key, request.str(key));
               }
            }
            util.write(auth, "PATCH", "/core/users/" + safeKey(request.targetKey()) + "/", body);
            return ("User updated.");
         }
         case DEACTIVATE_USER:
         {
            util.write(auth, "PATCH", "/core/users/" + safeKey(request.targetKey()) + "/", new JSONObject().put("is_active", false));
            String suffix = "";
            if(request.bool("revokeAppPasswords"))
            {
               int revoked = revokeAppPasswords(auth, plan.getTargetLabel());
               suffix = " " + revoked + " app password(s) revoked.";
            }
            return ("User deactivated; their sessions were ended." + suffix);
         }
         case REACTIVATE_USER:
            util.write(auth, "PATCH", "/core/users/" + safeKey(request.targetKey()) + "/", new JSONObject().put("is_active", true));
            return ("User reactivated.");
         case ADD_MEMBER:
         {
            String[] parts = request.targetKey().split(":", 2);
            util.write(auth, "POST", "/core/groups/" + safeKey(parts[0]) + "/add_user/", new JSONObject().put("pk", Integer.parseInt(parts[1])));
            return ("Added to the group.");
         }
         case REMOVE_MEMBER:
         {
            String[] parts = request.targetKey().split(":", 2);
            util.write(auth, "POST", "/core/groups/" + safeKey(parts[0]) + "/remove_user/", new JSONObject().put("pk", Integer.parseInt(parts[1])));
            return ("Removed from the group.");
         }
         case CREATE_GROUP:
         {
            JSONArray parents = new JSONArray();
            for(String parentName : AuthentikSafety.parseList(request.str("parents")))
            {
               parents.put(graph().byName(parentName).pk());
            }
            JSONObject attributes = new JSONObject();
            putList(attributes, AuthentikJson.ATTR_PERMISSIONS, AuthentikSafety.parseList(request.str("permissions")));
            putList(attributes, AuthentikJson.ATTR_APP_ACCESS, AuthentikSafety.parseList(request.str("appAccess")));
            util.write(auth, "POST", "/core/groups/", new JSONObject().put("name", request.str("name")).put("is_superuser", false).put("parents", parents).put("attributes", attributes));
            return ("Group created.");
         }
         case EDIT_GROUP:
         {
            JSONObject body = new JSONObject();
            if(StringUtils.hasContent(request.str("name")))
            {
               body.put("name", request.str("name"));
            }
            if(request.params().containsKey("resolvedParentPks"))
            {
               JSONArray parents = new JSONArray();
               for(String pk : AuthentikSafety.parseList(request.str("resolvedParentPks")))
               {
                  parents.put(pk);
               }
               body.put("parents", parents);
            }
            util.write(auth, "PATCH", "/core/groups/" + safeKey(request.targetKey()) + "/", body);
            return ("Group updated.");
         }
         case EDIT_PERMISSIONS:
         {
            ///////////////////////////////////////////////////////////////////////////
            // read the group again right before writing, and merge only the two    //
            // qqq.io keys into its CURRENT attributes, so other attributes (and    //
            // edits made in the Authentik UI) survive                              //
            ///////////////////////////////////////////////////////////////////////////
            runtime.invalidateCache();
            JSONObject fresh = util.getApiJsonOrNull("/core/groups/" + safeKey(request.targetKey()) + "/?include_users=false&include_parents=false&include_children=false");
            if(fresh == null)
            {
               throw (new QUserFacingException("That group no longer exists."));
            }
            JSONObject attributes = fresh.optJSONObject("attributes") == null ? new JSONObject() : new JSONObject(fresh.getJSONObject("attributes").toString());
            putList(attributes, AuthentikJson.ATTR_PERMISSIONS, AuthentikSafety.parseList(request.str("permissions")));
            putList(attributes, AuthentikJson.ATTR_APP_ACCESS, AuthentikSafety.parseList(request.str("appAccess")));
            util.write(auth, "PATCH", "/core/groups/" + safeKey(request.targetKey()) + "/", new JSONObject().put("attributes", attributes));
            return ("Permissions and app access updated.");
         }
         case SEND_RECOVERY_EMAIL:
            sendRecovery(auth, request.targetKey());
            return ("Password reset email sent by Authentik.");
         case RESET_MFA:
         {
            int removed = 0;
            for(JSONObject device : mfaDevices(Integer.parseInt(request.targetKey())))
            {
               String path = devicePath(device);
               if(path != null)
               {
                  util.write(auth, "DELETE", path, null);
                  removed++;
               }
            }
            return (removed + " MFA device(s) removed; they set up MFA again at next sign-in.");
         }
         case REVOKE_APP_PASSWORDS:
            return (revokeAppPasswords(auth, plan.getTargetLabel()) + " app password(s) revoked.");
         case REVOKE_SESSIONS:
            util.write(auth, "DELETE", "/core/authenticated_sessions/bulk_delete/?user_pks=" + safeKey(request.targetKey()), null);
            return ("Sessions revoked.");
         default:
            throw (new QException("Unsupported action " + request.action()));
      }
   }



   /*******************************************************************************
    ** Create the user (no password), add them to their groups, send the
    ** password email. A failure after the user exists says so.
    *******************************************************************************/
   private String performCreateUser(AdminPlan plan, WriteAuthorization auth) throws QException
   {
      AdminRequest request = plan.getRequest();
      JSONObject   body    = new JSONObject()
         .put("username", request.str("username"))
         .put("name", request.str("name"))
         .put("email", request.str("email"))
         .put("is_active", true)
         .put("type", "internal")
         .put("path", config.getNewUserPath())
         .put("attributes", new JSONObject().put("qqq.io/created-by", guard.operatorEmail() == null ? "" : guard.operatorEmail()));
      JSONObject created = util.write(auth, "POST", "/core/users/", body);
      int        pk      = created.optInt("pk", -1);
      if(pk < 0)
      {
         throw (new QException("Authentik did not return the new user's id."));
      }

      try
      {
         for(String groupName : AuthentikSafety.parseList(request.str("groups")))
         {
            util.write(auth, "POST", "/core/groups/" + safeKey(graph().byName(groupName).pk()) + "/add_user/", new JSONObject().put("pk", pk));
         }
         if(!request.params().containsKey("sendRecovery") || request.bool("sendRecovery"))
         {
            sendRecovery(auth, String.valueOf(pk));
         }
      }
      catch(Exception e)
      {
         throw (new QException("The user " + request.str("username") + " was created, but a later step failed: " + e.getMessage()
            + " Finish with Add to group and Send password reset email.", e));
      }
      return ("User created. They set their own password from the email Authentik sent.");
   }



   /*******************************************************************************
    ** Authentik's recovery email (the user gets the link; QQQ never does).
    *******************************************************************************/
   private void sendRecovery(WriteAuthorization auth, String userPk) throws QException
   {
      String stage = flowOrStageUuid("/stages/email/", config.getRecoveryEmailStage());
      if(stage == null)
      {
         throw (new QUserFacingException("The recovery email stage was not found in Authentik: " + config.getRecoveryEmailStage()));
      }
      util.write(auth, "POST", "/core/users/" + safeKey(userPk) + "/recovery_email/", new JSONObject().put("email_stage", stage).put("token_duration", "minutes=30"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private int revokeAppPasswords(WriteAuthorization auth, String username) throws QException
   {
      int revoked = 0;
      for(JSONObject token : appPasswords(username))
      {
         util.write(auth, "DELETE", "/core/tokens/" + safeKey(token.optString("identifier")) + "/", null);
         revoked++;
      }
      return (revoked);
   }



   /*******************************************************************************
    ** The user's app passwords only (intent app_password): never API tokens,
    ** recovery or verification tokens.
    *******************************************************************************/
   private List<JSONObject> appPasswords(String username) throws QException
   {
      return (util.getAllPages("/core/tokens/?user__username=" + enc(username) + "&intent=app_password", 1000));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<JSONObject> sessions(String username) throws QException
   {
      return (util.getAllPages("/core/authenticated_sessions/?user__username=" + enc(username), 1000));
   }



   /*******************************************************************************
    ** A user's MFA devices (metadata only).
    *******************************************************************************/
   private List<JSONObject> mfaDevices(int userPk) throws QException
   {
      JSONArray devices = util.getApiArray("/authenticators/admin/all/?user=" + userPk);
      List<JSONObject> rs = new ArrayList<>();
      if(devices != null)
      {
         for(int i = 0; i < devices.length(); i++)
         {
            rs.add(devices.getJSONObject(i));
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** The delete path of an MFA device from its type and pk.
    *******************************************************************************/
   public static String devicePath(JSONObject device)
   {
      String type = (device.optString("type", "") + " " + device.optString("meta_model_name", "")).toLowerCase(Locale.ROOT);
      String pk   = device.has("pk") ? String.valueOf(device.get("pk")) : null;
      if(pk == null)
      {
         return (null);
      }
      for(String kind : List.of("totp", "webauthn", "static", "email", "sms", "duo"))
      {
         if(type.contains(kind))
         {
            return ("/authenticators/admin/" + kind + "/" + pk + "/");
         }
      }
      return (null);
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // reads
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** The pk of the user with a username (within the qbit's user scope), or
    ** null.
    *******************************************************************************/
   public Integer userPkByUsername(String username) throws QException
   {
      JSONObject user = findUserByUsername(username);
      return (user == null || !guard.isUserInScope(user) ? null : user.optInt("pk"));
   }



   /*******************************************************************************
    ** The group graph without members (cached by the util).
    *******************************************************************************/
   private GroupGraph graph() throws QException
   {
      if(graph == null)
      {
         graph = util.groupGraph();
      }
      return (graph);
   }



   /*******************************************************************************
    ** The group graph with members.
    *******************************************************************************/
   private GroupGraph membersGraph() throws QException
   {
      if(membersGraph == null)
      {
         membersGraph = util.groupGraphWithMembers();
      }
      return (membersGraph);
   }



   /*******************************************************************************
    ** A resolver over the plain graph.
    *******************************************************************************/
   private EffectivePermissionResolver resolver() throws QException
   {
      return (new EffectivePermissionResolver(graph(), runtime.getPermissionCatalog()));
   }



   /*******************************************************************************
    ** Facts about every user, for last-admin protection.
    *******************************************************************************/
   private List<AuthentikSafety.UserFacts> userFacts() throws QException
   {
      if(userFacts == null)
      {
         userFacts = new ArrayList<>();
         for(JSONObject user : util.allUsers())
         {
            String type = user.optString("type");
            userFacts.add(new AuthentikSafety.UserFacts(user.optInt("pk"), user.optBoolean("is_active", true),
               "internal".equals(type) || "external".equals(type), guard.protection(user).isProtected()));
         }
      }
      return (userFacts);
   }



   /*******************************************************************************
    ** pks of the people who can administer memberships and permissions now.
    *******************************************************************************/
   private Set<Integer> adminsNow() throws QException
   {
      return (AuthentikSafety.qualifyingAdmins(membersGraph(), new EffectivePermissionResolver(membersGraph(), runtime.getPermissionCatalog()), userFacts()));
   }



   /*******************************************************************************
    ** A user by exact email (case-insensitive match on the result), or null.
    *******************************************************************************/
   private JSONObject findUserByEmail(String email) throws QException
   {
      for(JSONObject user : util.getAllPages("/core/users/?email=" + enc(email) + "&include_groups=true&include_roles=false", 10))
      {
         if(email.equalsIgnoreCase(user.optString("email")))
         {
            return (user);
         }
      }
      return (null);
   }



   /*******************************************************************************
    ** A user by exact username, or null.
    *******************************************************************************/
   private JSONObject findUserByUsername(String username) throws QException
   {
      for(JSONObject user : util.getAllPages("/core/users/?username=" + enc(username) + "&include_groups=false&include_roles=false", 10))
      {
         if(username.equalsIgnoreCase(user.optString("username")))
         {
            return (user);
         }
      }
      return (null);
   }



   /*******************************************************************************
    ** The uuid of a stage or flow given by uuid or by name/slug.
    *******************************************************************************/
   private String flowOrStageUuid(String listPath, String nameOrUuid) throws QException
   {
      if(!StringUtils.hasContent(nameOrUuid))
      {
         return (null);
      }
      if(UUID_PATTERN.matcher(nameOrUuid).matches())
      {
         return (nameOrUuid);
      }
      for(JSONObject stage : util.getAllPages(listPath + "?name=" + enc(nameOrUuid), 10))
      {
         if(nameOrUuid.equals(stage.optString("name")))
         {
            return (stage.optString("pk"));
         }
      }
      return (null);
   }



   /*******************************************************************************
    ** The uuid of the invitation flow (by uuid or slug).
    *******************************************************************************/
   private String flowUuid(String slugOrUuid) throws QException
   {
      if(UUID_PATTERN.matcher(slugOrUuid).matches())
      {
         return (slugOrUuid);
      }
      for(JSONObject flow : util.getAllPages("/flows/instances/?slug=" + enc(slugOrUuid), 10))
      {
         if(slugOrUuid.equals(flow.optString("slug")))
         {
            return (flow.optString("pk"));
         }
      }
      return (null);
   }



   //////////////////////////////////////////////////////////////////////////////////////////
   // small helpers
   //////////////////////////////////////////////////////////////////////////////////////////



   /*******************************************************************************
    ** Put a list attribute, or remove the key when empty.
    *******************************************************************************/
   private static void putList(JSONObject attributes, String key, List<String> values)
   {
      if(values.isEmpty())
      {
         attributes.remove(key);
      }
      else
      {
         attributes.put(key, new JSONArray(values));
      }
   }



   /*******************************************************************************
    ** Group names for pks, for before/after text.
    *******************************************************************************/
   private String names(List<String> pks) throws QException
   {
      List<String> names = new ArrayList<>();
      for(String pk : pks)
      {
         GroupGraph.Node node = graph().byPk(pk);
         names.add(node == null ? pk : node.name());
      }
      return (names.isEmpty() ? "none" : String.join(", ", names));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String joinOrNone(List<String> values)
   {
      return (values.isEmpty() ? "none" : String.join(", ", values));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static List<String> nonNull(List<String> list)
   {
      return (list == null ? List.of() : list);
   }



   /*******************************************************************************
    ** A path segment that is a plain key (digits, letters, dashes, dots, colons).
    *******************************************************************************/
   static String safeKey(String key) throws QUserFacingException
   {
      if(key == null || !key.matches("[A-Za-z0-9._-]{1,150}"))
      {
         throw (new QUserFacingException("Bad key: " + key));
      }
      return (key);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String enc(String value)
   {
      return (URLEncoder.encode(value, StandardCharsets.UTF_8));
   }

}
