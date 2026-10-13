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

package com.kingsrook.qbits.authentik.processes;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.AdminAction;
import com.kingsrook.qbits.authentik.admin.AdminPlan;
import com.kingsrook.qbits.authentik.admin.AdminRequest;
import com.kingsrook.qbits.authentik.admin.AuthentikAdmin;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qbits.authentik.admin.AuthentikSafety;
import com.kingsrook.qbits.authentik.client.AuthentikJson;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.policy.PolicyEditorWidget;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.processes.BackendStep;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLine;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLineInterface;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.actions.processes.Status;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QBackendStepMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QComponentType;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QFrontendComponentMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QFrontendStepMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QFunctionInputMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QRecordListMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractExtractStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractLoadStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractTransformStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ExtractViaQueryStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ProcessSummaryProviderInterface;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.StreamedETLWithFrontendProcess;
import com.kingsrook.qqq.backend.core.utils.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Every change the qbit makes is a table or record action (DESIGN.md section
 ** 6.3); none is ever in the nav. Each is a standard streamed-ETL process with
 ** an optional details screen first, a Review step (the dry run: what each
 ** target would become, and which are refused and why) and a Result step
 ** (summary lines per outcome). The rules live in AuthentikAdmin; these steps
 ** only ask it to plan (Review) and to execute (Result).
 *******************************************************************************/
public final class AuthentikProcesses
{
   /** What the process is launched on. */
   public enum Kind
   {
      /** Selected users (authentik_user). */
      USERS,
      /** Selected groups, each with a list of usernames (members actions). */
      GROUP_USERNAMES,
      /** Selected groups (authentik_group). */
      GROUPS,
      /** No records: a form creates something (table action). */
      CREATE,
      /** Selected invitations. */
      INVITATIONS,
      /** Selected approval requests. */
      APPROVALS,
      /** Selected policy records (authentik_policy); the target is the record's group. */
      POLICIES
   }

   /*******************************************************************************
    ** One process definition.
    **
    ** @param key      short key; the process is named applyPrefix("&lt;key&gt;")
    ** @param label    plain label shown in the Actions menu
    ** @param action   what it does (null for approvals)
    ** @param kind     what it is launched on
    ** @param table    unprefixed table name it is bound to
    ** @param icon     material icon
    ** @param prefill  whether a prepare step fills the form from the record
    ** @param fields   details screen fields
    ** @param help     help text on the details screen
    *******************************************************************************/
   public record Def(String key, String label, AdminAction action, Kind kind, String table, String icon, boolean prefill, List<QFieldMetaData> fields, String help)
   {
   }

   private static final Map<String, Def>                 DEFS_BY_PROCESS   = new HashMap<>();
   private static final Map<String, AuthentikQBitConfig> CONFIGS_BY_PROCESS = new HashMap<>();



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikProcesses()
   {
   }



   /*******************************************************************************
    ** The definitions enabled by the config's features.
    *******************************************************************************/
   public static List<Def> definitions(AuthentikQBitConfig config)
   {
      List<Def> defs = new ArrayList<>();
      QFieldMetaData reason = new QFieldMetaData("reason", QFieldType.TEXT).withLabel("Reason").withIsRequired(true);
      QFieldMetaData typed  = new QFieldMetaData("confirmText", QFieldType.STRING).withLabel("Type the username to confirm").withIsRequired(true);
      QFieldMetaData group  = new QFieldMetaData("group", QFieldType.STRING).withLabel("Group").withIsRequired(true)
         .withPossibleValueSourceName(config.applyTablePrefix(AuthentikTables.GROUP));

      String users  = AuthentikTables.USER;
      String groups = AuthentikTables.GROUP;

      defs.add(new Def("createUser", "Create User", AdminAction.CREATE_USER, Kind.CREATE, users, "person_add", false, List.of(
         new QFieldMetaData("username", QFieldType.STRING).withLabel("Username").withIsRequired(true),
         new QFieldMetaData("name", QFieldType.STRING).withLabel("Full Name").withIsRequired(true),
         new QFieldMetaData("email", QFieldType.STRING).withLabel("Email").withIsRequired(true),
         new QFieldMetaData("groups", QFieldType.TEXT).withLabel("Groups (names, one per line)"),
         new QFieldMetaData("sendRecovery", QFieldType.BOOLEAN).withLabel("Email them a link to set their own password").withDefaultValue(true),
         reason), "No password is set here. Authentik emails the person a link to set their own."));
      defs.add(new Def("inviteUser", "Invite User", AdminAction.INVITE_USER, Kind.CREATE, users, "mail", false, List.of(
         new QFieldMetaData("email", QFieldType.STRING).withLabel("Email").withIsRequired(true),
         new QFieldMetaData("name", QFieldType.STRING).withLabel("Full Name"),
         reason), "Authentik emails a single-use sign-up invitation that expires in 7 days."));
      QFieldMetaData otherAttributes = new QFieldMetaData(AuthentikAdmin.OTHER_ATTRIBUTES, QFieldType.TEXT).withLabel("Other attributes (JSON; leave blank to keep them)");
      defs.add(new Def("editUser", "Edit User", AdminAction.EDIT_USER, Kind.USERS, users, "edit", true, List.of(
         new QFieldMetaData("username", QFieldType.STRING).withLabel("Username"),
         new QFieldMetaData("name", QFieldType.STRING).withLabel("Full Name"),
         new QFieldMetaData("email", QFieldType.STRING).withLabel("Email"),
         new QFieldMetaData("path", QFieldType.STRING).withLabel("Path"),
         otherAttributes,
         hidden("expectedFingerprint"), reason), "Change a person's username, name, email, path or other attributes. "
            + "Attributes starting with qqq.io/ or goauthentik.io/ are set elsewhere; editing attributes needs authentik.audit.read."));
      defs.add(new Def("deactivateUser", "Deactivate User", AdminAction.DEACTIVATE_USER, Kind.USERS, users, "block", false, List.of(
         new QFieldMetaData("revokeAppPasswords", QFieldType.BOOLEAN).withLabel("Also revoke their app passwords").withDefaultValue(false),
         typed, reason), "Deactivating ends their sessions immediately and deletes nothing. Type the username to confirm (when you select several people, type the username of the first one)."));
      defs.add(new Def("deleteUser", "Delete User", AdminAction.DELETE_USER, Kind.USERS, users, "delete_forever", false, List.of(typed, reason),
         "Deletes the account in Authentik permanently. To keep the account and its history, use Deactivate User instead."));
      defs.add(new Def("reactivateUser", "Reactivate User", AdminAction.REACTIVATE_USER, Kind.USERS, users, "check_circle", false, List.of(reason), null));
      defs.add(new Def("addToGroup", "Add To Group", AdminAction.ADD_MEMBER, Kind.USERS, users, "group_add", false, List.of(group,
         new QFieldMetaData("confirmText", QFieldType.STRING).withLabel("Confirm the number of people (needed only above 25)").withIsHidden(false), reason),
         "You can only add people to a group whose permissions you hold yourself."));
      defs.add(new Def("removeFromGroup", "Remove From Group", AdminAction.REMOVE_MEMBER, Kind.USERS, users, "group_remove", false, List.of(group,
         new QFieldMetaData("confirmText", QFieldType.STRING).withLabel("Confirm the number of people (needed only above 25)").withIsHidden(false), reason), null));
      defs.add(new Def("sendPasswordReset", "Send Password Reset Email", AdminAction.SEND_RECOVERY_EMAIL, Kind.USERS, users, "lock_reset", false, List.of(reason),
         "Authentik emails the person a link. You never see the link."));
      defs.add(new Def("resetMfa", "Reset MFA", AdminAction.RESET_MFA, Kind.USERS, users, "phonelink_erase", false, List.of(typed, reason),
         "Removes every MFA device; the person sets MFA up again at next sign-in."));
      defs.add(new Def("revokeAppPasswords", "Revoke App Passwords", AdminAction.REVOKE_APP_PASSWORDS, Kind.USERS, users, "key_off", false, List.of(typed, reason),
         "Revokes app passwords only; API tokens are never touched."));
      defs.add(new Def("revokeSessions", "Revoke Sessions", AdminAction.REVOKE_SESSIONS, Kind.USERS, users, "logout", false, List.of(reason), "Signs the person out everywhere."));

      defs.add(new Def("createGroup", "Create Group", AdminAction.CREATE_GROUP, Kind.CREATE, groups, "group_add", false, List.of(
         new QFieldMetaData("name", QFieldType.STRING).withLabel("Group Name").withIsRequired(true),
         new QFieldMetaData("parents", QFieldType.TEXT).withLabel("Parent groups (names, one per line)"),
         new QFieldMetaData("permissions", QFieldType.TEXT).withLabel("QQQ permissions (one per line)"),
         new QFieldMetaData("appAccess", QFieldType.TEXT).withLabel("App access (app keys, one per line)"),
         reason), "A group's QQQ permissions apply to everyone in it, and to groups below it."));
      defs.add(new Def("editGroup", "Edit Group", AdminAction.EDIT_GROUP, Kind.GROUPS, groups, "edit", true, List.of(
         new QFieldMetaData("name", QFieldType.STRING).withLabel("Group Name"),
         new QFieldMetaData("parents", QFieldType.TEXT).withLabel("Parent groups (names, one per line; none to clear)"),
         otherAttributes,
         hidden("expectedFingerprint"), reason), "Rename a group, change its parents or its other attributes."));
      defs.add(new Def("deleteGroup", "Delete Group", AdminAction.DELETE_GROUP, Kind.GROUPS, groups, "delete_forever", false, List.of(
         new QFieldMetaData("confirmText", QFieldType.STRING).withLabel("Type the group name to confirm").withIsRequired(true), reason),
         "Deletes the group in Authentik permanently, with its permissions, app access and policy. Remove its members and child groups first."));
      defs.add(new Def("editPermissions", "Edit Permissions And App Access", AdminAction.EDIT_PERMISSIONS, Kind.GROUPS, groups, "admin_panel_settings", true, List.of(
         new QFieldMetaData("permissions", QFieldType.TEXT).withLabel("QQQ permissions (one per line)"),
         new QFieldMetaData("appAccess", QFieldType.TEXT).withLabel("App access (app keys, one per line)"),
         hidden("expectedFingerprint"), reason),
         "You can only add permissions you hold yourself. Adding authentik.* needs a second person to approve."));
      String policyHelp = "Tick what members of this group, and of the groups below it, may do. The document is what is saved to Authentik. "
         + "You can only grant permissions you hold yourself.";
      List<QFieldMetaData> policyFields = List.of(hidden("groupPk"), hidden("expectedFingerprint"), reason);
      defs.add(new Def("editPolicy", "Edit Policy", AdminAction.SAVE_POLICY, Kind.GROUPS, groups, "policy", true, policyFields, policyHelp));
      defs.add(new Def("editPolicyRecord", "Edit Policy", AdminAction.SAVE_POLICY, Kind.POLICIES, AuthentikLocalTables.POLICY, "policy", true, policyFields, policyHelp));
      defs.add(new Def("addMembers", "Add Members", AdminAction.ADD_MEMBER, Kind.GROUP_USERNAMES, groups, "person_add", false, List.of(
         new QFieldMetaData("usernames", QFieldType.TEXT).withLabel("Usernames (one per line)").withIsRequired(true),
         new QFieldMetaData("confirmText", QFieldType.STRING).withLabel("Confirm the number of people (needed only above 25)").withIsHidden(false), reason), null));
      defs.add(new Def("removeMembers", "Remove Members", AdminAction.REMOVE_MEMBER, Kind.GROUP_USERNAMES, groups, "person_remove", false, List.of(
         new QFieldMetaData("usernames", QFieldType.TEXT).withLabel("Usernames (one per line)").withIsRequired(true),
         new QFieldMetaData("confirmText", QFieldType.STRING).withLabel("Confirm the number of people (needed only above 25)").withIsHidden(false), reason), null));

      defs.add(new Def("cancelInvitation", "Cancel Invitation", AdminAction.CANCEL_INVITATION, Kind.INVITATIONS, "invitation", "cancel", false, List.of(reason), null));
      defs.add(new Def("approve", "Approve And Apply", null, Kind.APPROVALS, AuthentikLocalTables.APPROVAL_REQUEST, "check", false, List.of(), "A second person applies the change. The change is checked again against live data."));
      defs.add(new Def("reject", "Reject", null, Kind.APPROVALS, AuthentikLocalTables.APPROVAL_REQUEST, "close", false, List.of(), null));

      defs.removeIf(def -> def.action() != null && !config.hasFeature(def.action().getFeature()));
      defs.removeIf(def -> (def.action() == AdminAction.DELETE_USER && !config.hasFeature(com.kingsrook.qbits.authentik.AuthentikFeature.USERS))
         || (def.action() == AdminAction.DELETE_GROUP && !config.hasFeature(com.kingsrook.qbits.authentik.AuthentikFeature.GROUPS)));
      if(!config.hasFeature(com.kingsrook.qbits.authentik.AuthentikFeature.GROUPS) || !config.getTwoPersonApproval())
      {
         defs.removeIf(def -> def.kind() == Kind.APPROVALS);
      }
      if(StringUtils.hasContent(config.getInvitationFlow()))
      {
         return (defs);
      }
      defs.removeIf(def -> def.action() == AdminAction.INVITE_USER || def.action() == AdminAction.CANCEL_INVITATION);
      return (defs);
   }



   /*******************************************************************************
    ** A hidden form field (carries a stale-check fingerprint).
    *******************************************************************************/
   private static QFieldMetaData hidden(String name)
   {
      return (new QFieldMetaData(name, QFieldType.STRING).withIsHidden(true));
   }



   /*******************************************************************************
    ** The process names for a config's definitions (for the app and tests).
    *******************************************************************************/
   public static String processName(AuthentikQBitConfig config, Def def)
   {
      return (config.applyPrefix(def.key()));
   }



   /*******************************************************************************
    ** All processes for a config.
    *******************************************************************************/
   public static List<QProcessMetaData> processes(AuthentikQBitConfig config)
   {
      List<QProcessMetaData> processes = new ArrayList<>();
      for(Def def : definitions(config))
      {
         processes.add(build(config, def));
      }
      return (processes);
   }



   /*******************************************************************************
    ** Build one process.
    *******************************************************************************/
   static QProcessMetaData build(AuthentikQBitConfig config, Def def)
   {
      String name  = processName(config, def);
      String table = config.applyTablePrefix(def.table());
      DEFS_BY_PROCESS.put(name, def);
      CONFIGS_BY_PROCESS.put(name, config);

      Map<String, Serializable> values = new HashMap<>();
      values.put(StreamedETLWithFrontendProcess.FIELD_SOURCE_TABLE, table);
      values.put(StreamedETLWithFrontendProcess.FIELD_DESTINATION_TABLE, table);
      values.put(StreamedETLWithFrontendProcess.FIELD_SUPPORTS_FULL_VALIDATION, true);
      values.put(StreamedETLWithFrontendProcess.FIELD_DO_FULL_VALIDATION, true);
      values.put(StreamedETLWithFrontendProcess.FIELD_PREVIEW_MESSAGE, "This is a preview of what will change. Nothing has been sent to Authentik yet.");

      Class<? extends AbstractExtractStep> extract = def.kind() == Kind.CREATE ? SingleRecordExtractStep.class : ExtractViaQueryStep.class;
      QProcessMetaData process = StreamedETLWithFrontendProcess.defineProcessMetaData(extract, ActionTransformStep.class, ActionLoadStep.class, values);
      process.setName(name);
      process.setLabel(def.label());
      process.setTableName(table);
      process.setIcon(new QIcon(def.icon()));
      process.setPermissionRules((def.action() == null ? IdentityPermission.APPROVE : def.action().getPermission()).rules());
      switch(def.kind())
      {
         case CREATE -> process.setMaxInputRecords(0);
         case USERS, GROUP_USERNAMES, GROUPS, INVITATIONS, APPROVALS, POLICIES ->
         {
            process.setMinInputRecords(1);
            process.setMaxInputRecords(def.action() == AdminAction.EDIT_USER || def.action() == AdminAction.EDIT_GROUP || def.action() == AdminAction.EDIT_PERMISSIONS
               || def.action() == AdminAction.SAVE_POLICY || def.action() == AdminAction.DELETE_USER || def.action() == AdminAction.DELETE_GROUP ? 1 : AuthentikAdmin.MAX_BULK);
         }
         default ->
         {
         }
      }

      if(!def.fields().isEmpty())
      {
         QFrontendStepMetaData details = new QFrontendStepMetaData().withName("details").withLabel(def.label()).withFormFields(def.fields());
         if(StringUtils.hasContent(def.help()))
         {
            details.withComponent(new QFrontendComponentMetaData().withType(QComponentType.HELP_TEXT).withValue("text", def.help()));
         }
         if(def.action() == AdminAction.SAVE_POLICY)
         {
            details.withComponent(new QFrontendComponentMetaData().withType(QComponentType.WIDGET).withValue("widgetName", config.applyPrefix(PolicyEditorWidget.NAME)));
         }
         details.withComponent(new QFrontendComponentMetaData().withType(QComponentType.EDIT_FORM));
         process.withStep(0, details);
         if(def.prefill())
         {
            process.withStep(0, new QBackendStepMetaData().withName("prepare").withCode(new QCodeReference(PrepareStep.class))
               .withInputData(new QFunctionInputMetaData().withRecordListMetaData(new QRecordListMetaData().withTableName(table))));
         }
      }
      return (process);
   }



   /*******************************************************************************
    ** The definition behind a process name.
    *******************************************************************************/
   static Def defFor(String processName)
   {
      Def def = DEFS_BY_PROCESS.get(processName);
      if(def == null)
      {
         throw (new IllegalStateException("Not an Authentik qbit process: " + processName));
      }
      return (def);
   }



   /*******************************************************************************
    ** The summary-line wording of an action: future (Review) and past (Result).
    *******************************************************************************/
   static String[] wording(AdminAction action)
   {
      if(action == null)
      {
         return (new String[] { "approval request will be decided", "approval requests will be decided", "approval request was decided", "approval requests were decided" });
      }
      return switch(action)
      {
         case CREATE_USER -> w("user will be created", "users will be created", "user was created", "users were created");
         case INVITE_USER -> w("invitation will be sent", "invitations will be sent", "invitation was sent", "invitations were sent");
         case EDIT_USER -> w("user will be updated", "users will be updated", "user was updated", "users were updated");
         case DEACTIVATE_USER -> w("user will be deactivated", "users will be deactivated", "user was deactivated", "users were deactivated");
         case REACTIVATE_USER -> w("user will be reactivated", "users will be reactivated", "user was reactivated", "users were reactivated");
         case CANCEL_INVITATION -> w("invitation will be cancelled", "invitations will be cancelled", "invitation was cancelled", "invitations were cancelled");
         case ADD_MEMBER -> w("membership will be added", "memberships will be added", "membership was added", "memberships were added");
         case REMOVE_MEMBER -> w("membership will be removed", "memberships will be removed", "membership was removed", "memberships were removed");
         case CREATE_GROUP -> w("group will be created", "groups will be created", "group was created", "groups were created");
         case EDIT_GROUP -> w("group will be updated", "groups will be updated", "group was updated", "groups were updated");
         case EDIT_PERMISSIONS -> w("group's permissions will be updated", "groups' permissions will be updated", "group's permissions were updated", "groups' permissions were updated");
         case DELETE_USER -> w("user will be deleted", "users will be deleted", "user was deleted", "users were deleted");
         case DELETE_GROUP -> w("group will be deleted", "groups will be deleted", "group was deleted", "groups were deleted");
         case SAVE_POLICY -> w("group's policy will be saved to Authentik", "groups' policies will be saved to Authentik", "group's policy was saved to Authentik", "groups' policies were saved to Authentik");
         case SEND_RECOVERY_EMAIL -> w("password reset email will be sent", "password reset emails will be sent", "password reset email was sent", "password reset emails were sent");
         case RESET_MFA -> w("user's MFA will be reset", "users' MFA will be reset", "user's MFA was reset", "users' MFA were reset");
         case REVOKE_APP_PASSWORDS -> w("user's app passwords will be revoked", "users' app passwords will be revoked", "user's app passwords were revoked", "users' app passwords were revoked");
         case REVOKE_SESSIONS -> w("user's sessions will be revoked", "users' sessions will be revoked", "user's sessions were revoked", "users' sessions were revoked");
      };
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String[] w(String a, String b, String c, String d)
   {
      return (new String[] { a, b, c, d });
   }



   /*******************************************************************************
    ** A summary line with future (Review) and past (Result) wording.
    *******************************************************************************/
   static ProcessSummaryLine line(Status status, String singularFuture, String pluralFuture, String singularPast, String pluralPast)
   {
      ProcessSummaryLine line = new ProcessSummaryLine(status, 0, null);
      line.setSingularFutureMessage(singularFuture);
      line.setPluralFutureMessage(pluralFuture);
      line.setSingularPastMessage(singularPast);
      line.setPluralPastMessage(pluralPast);
      return (line);
   }



   /*******************************************************************************
    ** Build the requests a record stands for, from the process's form values.
    *******************************************************************************/
   static List<AdminRequest> requests(Def def, RunBackendStepInput input, QRecord record, AuthentikAdmin admin) throws QException
   {
      String reason = input.getValueString("reason");
      List<AdminRequest> rs = new ArrayList<>();
      switch(def.kind())
      {
         case CREATE -> rs.add(withParams(AdminRequest.of(def.action(), "", reason), def, input));
         case USERS ->
         {
            String userPk = String.valueOf(record.getValue("pk"));
            if(def.action() == AdminAction.ADD_MEMBER || def.action() == AdminAction.REMOVE_MEMBER)
            {
               rs.add(withParams(AdminRequest.of(def.action(), input.getValueString("group") + ":" + userPk, reason), def, input));
            }
            else
            {
               rs.add(withParams(AdminRequest.of(def.action(), userPk, reason), def, input));
            }
         }
         case GROUP_USERNAMES ->
         {
            String groupPk = String.valueOf(record.getValue("pk"));
            for(String username : AuthentikSafety.parseList(input.getValueString("usernames")))
            {
               Integer userPk = admin.userPkByUsername(username);
               AdminRequest request = AdminRequest.of(def.action(), groupPk + ":" + (userPk == null ? "0" : userPk), reason);
               withParams(request, def, input);
               request.with("username", username);
               rs.add(request);
            }
         }
         case GROUPS, INVITATIONS -> rs.add(withParams(AdminRequest.of(def.action(), String.valueOf(record.getValue("pk") != null ? record.getValue("pk") : record.getValue("uuid")), reason), def, input));
         case POLICIES -> rs.add(withParams(AdminRequest.of(def.action(), record.getValueString("groupPk"), reason), def, input));
         default ->
         {
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** Copy the details-screen values onto a request.
    *******************************************************************************/
   private static AdminRequest withParams(AdminRequest request, Def def, RunBackendStepInput input)
   {
      //////////////////////////////////////////////////////////////////////
      // the policy editor widget writes the document as a process value //
      // (not a form field), as does an API client                       //
      //////////////////////////////////////////////////////////////////////
      if(def.action() == AdminAction.SAVE_POLICY && input.getValue(AuthentikAdmin.POLICY_DOCUMENT) != null)
      {
         request.with(AuthentikAdmin.POLICY_DOCUMENT, input.getValueString(AuthentikAdmin.POLICY_DOCUMENT));
      }
      for(QFieldMetaData field : def.fields())
      {
         if(field.getName().equals("reason"))
         {
            continue;
         }
         Serializable value = input.getValue(field.getName());
         if(value != null)
         {
            request.with(field.getName(), value);
         }
      }
      return (request);
   }



   /*******************************************************************************
    ** How many records the run covers: counted from the same filter the extract
    ** step uses (the preview step's count is not carried into later steps).
    *******************************************************************************/
   static Integer countTargets(RunBackendStepInput input, RunBackendStepOutput output) throws QException
   {
      if(defFor(input.getProcessName()).kind() == Kind.CREATE)
      {
         return (1);
      }
      ExtractViaQueryStep extract = new ExtractViaQueryStep();
      extract.preRun(input, output);
      return (extract.doCount(input));
   }



   /*******************************************************************************
    ** The admin for the current backend.
    *******************************************************************************/
   static AuthentikAdmin admin(RunBackendStepInput input) throws QException
   {
      AuthentikQBitConfig config = CONFIGS_BY_PROCESS.get(input.getProcessName());
      if(config == null)
      {
         throw (new QException("The Authentik qbit is not set up in this instance."));
      }
      return (AuthentikAdmin.forBackend(config.getApiBackendName()));
   }



   /*******************************************************************************
    ** Attributes are sensitive (DESIGN.md section 5.3): they are shown on the
    ** edit forms only with authentik.audit.read; left blank, they are unchanged.
    *******************************************************************************/
   static boolean canSeeAttributes()
   {
      return (QContext.getQSession() != null && QContext.getQSession().getPermissions() != null
         && QContext.getQSession().getPermissions().contains(IdentityPermission.AUDIT_READ.getSessionPermission()));
   }



   /*******************************************************************************
    ** The details screen is filled from the selected record (edit actions).
    *******************************************************************************/
   public static class PrepareStep implements BackendStep
   {
      /*******************************************************************************
       ** Fill the form fields and the stale-check fingerprint.
       *******************************************************************************/
      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         Def def = defFor(input.getProcessName());
         if(input.getRecords() == null || input.getRecords().isEmpty())
         {
            return;
         }
         QRecord record = input.getRecords().get(0);
         AuthentikAdmin admin = admin(input);
         String pk = def.kind() == Kind.POLICIES ? record.getValueString("groupPk") : String.valueOf(record.getValue("pk"));
         switch(def.action())
         {
            case SAVE_POLICY ->
            {
               JSONObject group = admin.getUtil().getApiJsonOrNull("/core/groups/" + AuthentikAdmin.safeKey(pk) + "/?include_users=true&include_parents=true&include_children=true");
               output.addValue(PolicyEditorWidget.GROUP_PK_PARAM, pk);
               if(group != null)
               {
                  output.addValue("expectedFingerprint", AuthentikSafety.groupFingerprint(group));
               }
            }
            case EDIT_USER ->
            {
               JSONObject user = admin.getUtil().getObject(AuthentikTables.get(AuthentikTables.USER), pk);
               if(user != null)
               {
                  output.addValue("username", user.optString("username"));
                  if(canSeeAttributes())
                  {
                     output.addValue(AuthentikAdmin.OTHER_ATTRIBUTES, AuthentikAdmin.otherAttributes(user.optJSONObject("attributes")).toString(2));
                  }
                  output.addValue("name", user.optString("name"));
                  output.addValue("email", user.optString("email"));
                  output.addValue("path", user.optString("path"));
                  output.addValue("expectedFingerprint", AuthentikSafety.userFingerprint(user));
               }
            }
            case EDIT_GROUP, EDIT_PERMISSIONS ->
            {
               JSONObject group = admin.getUtil().getApiJsonOrNull("/core/groups/" + pk + "/?include_users=true&include_parents=true&include_children=true");
               if(group != null)
               {
                  output.addValue("expectedFingerprint", AuthentikSafety.groupFingerprint(group));
                  if(def.action() == AdminAction.EDIT_GROUP)
                  {
                     if(canSeeAttributes())
                     {
                        output.addValue(AuthentikAdmin.OTHER_ATTRIBUTES, AuthentikAdmin.otherAttributes(group.optJSONObject("attributes")).toString(2));
                     }
                     output.addValue("name", group.optString("name"));
                     JSONArray parents = group.optJSONArray("parents_obj");
                     List<String> names = new ArrayList<>();
                     for(int i = 0; parents != null && i < parents.length(); i++)
                     {
                        names.add(parents.getJSONObject(i).optString("name"));
                     }
                     output.addValue("parents", String.join("\n", names));
                  }
                  else
                  {
                     output.addValue("permissions", String.join("\n", AuthentikJson.stringList(group.optJSONObject("attributes"), AuthentikJson.ATTR_PERMISSIONS) == null
                        ? List.of() : AuthentikJson.stringList(group.optJSONObject("attributes"), AuthentikJson.ATTR_PERMISSIONS)));
                     output.addValue("appAccess", String.join("\n", AuthentikJson.stringList(group.optJSONObject("attributes"), AuthentikJson.ATTR_APP_ACCESS) == null
                        ? List.of() : AuthentikJson.stringList(group.optJSONObject("attributes"), AuthentikJson.ATTR_APP_ACCESS)));
                  }
               }
            }
            default ->
            {
            }
         }
      }
   }



   /*******************************************************************************
    ** The extract step of actions that create something: one placeholder record
    ** (the form values carry the data).
    *******************************************************************************/
   public static class SingleRecordExtractStep extends AbstractExtractStep
   {
      /*******************************************************************************
       ** One record, so the transform and load run once.
       *******************************************************************************/
      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         getRecordPipe().addRecord(new QRecord().withValue("pk", "new"));
      }



      /*******************************************************************************
       ** One record.
       *******************************************************************************/
      @Override
      public Integer doCount(RunBackendStepInput input)
      {
         return (1);
      }
   }



   /*******************************************************************************
    ** Review (and the full validation): plan every target against live data.
    *******************************************************************************/
   public static class ActionTransformStep extends AbstractTransformStep implements ProcessSummaryProviderInterface
   {
      private final Map<String, ProcessSummaryLine> lines   = new LinkedHashMap<>();
      private final List<String>                    details = new ArrayList<>();
      private final Map<String, List<String>>       targetsByLine = new LinkedHashMap<>();
      private final List<String>                    notes   = new ArrayList<>();
      private AuthentikAdmin                        admin;
      private Integer                               totalTargets;



      /*******************************************************************************
       ** Remember how many records the run covers (for the more-than-25 rule).
       *******************************************************************************/
      @Override
      public void preRun(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         totalTargets = countTargets(input, output);
      }



      /*******************************************************************************
       ** Plan each record's requests.
       *******************************************************************************/
      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         Def def = defFor(input.getProcessName());
         if(admin == null)
         {
            admin = admin(input);
         }

         for(QRecord record : input.getRecords())
         {
            List<AdminRequest> requests = def.kind() == Kind.APPROVALS ? List.of() : requests(def, input, record, admin);
            if(def.kind() == Kind.APPROVALS)
            {
               add(Status.OK, "approval request will be decided", "approval requests will be decided", "approval request was decided", "approval requests were decided", "approve");
               output.getRecords().add(record);
               continue;
            }
            int total = requests.size();
            for(AdminRequest request : requests)
            {
               AdminPlan plan = admin.plan(request);
               String problem = bulkProblem(def, request, total, input);
               if(problem != null && plan.isRunnable())
               {
                  plan.refuse(problem);
               }
               report(def, plan);
               output.getRecords().add(record);
            }
         }
      }



      /*******************************************************************************
       ** More than 25 targets in one run need the count typed.
       *******************************************************************************/
      private String bulkProblem(Def def, AdminRequest request, int total, RunBackendStepInput input)
      {
         Integer count = totalTargets;
         int     n     = Math.max(total, count == null ? 0 : count);
         if(n > AuthentikAdmin.TYPED_ABOVE && (def.action() == AdminAction.ADD_MEMBER || def.action() == AdminAction.REMOVE_MEMBER)
            && !String.valueOf(n).equals(request.str("confirmText")))
         {
            return ("More than " + AuthentikAdmin.TYPED_ABOVE + " people: type " + n + " in the confirmation field.");
         }
         return (null);
      }



      /*******************************************************************************
       ** Add a plan to the summary.
       *******************************************************************************/
      private void report(Def def, AdminPlan plan)
      {
         String[] w = wording(def.action());
         switch(plan.getState())
         {
            case READY ->
            {
               add(Status.OK, w[0], w[1], w[2], w[3], "ready");
               name("ready", plan);
               plan.getNotes().forEach(note ->
               {
                  if(!notes.contains(note))
                  {
                     notes.add(note);
                  }
               });
            }
            case NEEDS_APPROVAL ->
            {
               add(Status.WARNING, "change needs a second person's approval and will be requested", "changes need a second person's approval and will be requested",
                  "change was sent for approval", "changes were sent for approval", "approval");
               name("approval", plan);
            }
            case NO_CHANGE -> add(Status.INFO, "target needs no change: " + plan.getMessage(), "targets need no change: " + plan.getMessage(),
               "target needed no change: " + plan.getMessage(), "targets needed no change: " + plan.getMessage(), "nochange:" + plan.getMessage());
            default -> {
               add(Status.ERROR, "target is refused: " + plan.getMessage(), "targets are refused: " + plan.getMessage(),
                  "target was refused: " + plan.getMessage(), "targets were refused: " + plan.getMessage(), "refused:" + plan.getMessage());
               name("refused:" + plan.getMessage(), plan);
            }
         }
      }



      /*******************************************************************************
       **
       *******************************************************************************/
      private void add(Status status, String sf, String pf, String sp, String pp, String key)
      {
         lines.computeIfAbsent(key, k -> line(status, sf, pf, sp, pp)).incrementCount();
      }



      /*******************************************************************************
       ** Remember which target a line is about (shown as bullets, first 10).
       *******************************************************************************/
      private void name(String key, AdminPlan plan)
      {
         List<String> names = targetsByLine.computeIfAbsent(key, k -> new ArrayList<>());
         if(names.size() < 10)
         {
            names.add(plan.getBefore() != null || plan.getAfter() != null ? plan.describe() : (plan.getTargetLabel() == null ? plan.getRequest().targetKey() : plan.getTargetLabel()));
         }
      }



      /*******************************************************************************
       ** Review lines: one per outcome, then the before and after of the first
       ** targets and any notes.
       *******************************************************************************/
      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         ArrayList<ProcessSummaryLineInterface> rs = new ArrayList<>();
         for(Map.Entry<String, ProcessSummaryLine> entry : lines.entrySet())
         {
            List<String> names = targetsByLine.get(entry.getKey());
            if(names != null && !names.isEmpty() && !isForResultScreen)
            {
               entry.getValue().setBulletsOfText(new ArrayList<>(names));
            }
            entry.getValue().addSelfToListIfAnyCount(rs);
         }
         for(String note : notes)
         {
            ProcessSummaryLine noteLine = new ProcessSummaryLine(Status.INFO, note);
            noteLine.setCount(null);
            rs.add(noteLine);
         }
         return (rs);
      }
   }



   /*******************************************************************************
    ** Result: execute each target (the rules are checked again against live
    ** data inside), with a line per outcome.
    *******************************************************************************/
   public static class ActionLoadStep extends AbstractLoadStep implements ProcessSummaryProviderInterface
   {
      private final Map<String, ProcessSummaryLine> lines = new LinkedHashMap<>();
      private AuthentikAdmin                        admin;
      private Integer                               totalTargets;



      /*******************************************************************************
       ** Remember how many records the run covers (for the more-than-25 rule).
       *******************************************************************************/
      @Override
      public void preRun(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         totalTargets = countTargets(input, output);
      }



      /*******************************************************************************
       ** Execute each record's requests.
       *******************************************************************************/
      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         Def def = defFor(input.getProcessName());
         if(admin == null)
         {
            admin = admin(input);
         }
         String[] w = wording(def.action());

         for(QRecord record : input.getRecords())
         {
            if(def.kind() == Kind.APPROVALS)
            {
               AuthentikAdmin.AdminResult result = "approve".equals(def.key()) ? admin.approve(record.getValue("id")) : admin.reject(record.getValue("id"));
               tally(result, w);
               output.getRecords().add(record);
               continue;
            }

            List<AdminRequest> requests = requests(def, input, record, admin);
            int total = requests.size();
            for(AdminRequest request : requests)
            {
               Integer count = totalTargets;
               int     n     = Math.max(total, count == null ? 0 : count);
               AuthentikAdmin.AdminResult result;
               if(n > AuthentikAdmin.TYPED_ABOVE && (def.action() == AdminAction.ADD_MEMBER || def.action() == AdminAction.REMOVE_MEMBER)
                  && !String.valueOf(n).equals(request.str("confirmText")))
               {
                  result = new AuthentikAdmin.AdminResult(false, false, false, "More than " + AuthentikAdmin.TYPED_ABOVE + " people: type " + n + " in the confirmation field.", null);
               }
               else
               {
                  result = admin.execute(request);
               }
               tally(result, w);
               output.getRecords().add(record);
               pace(admin);
            }
         }
      }



      /*******************************************************************************
       ** Pace bulk work (Authentik shares its database with the app).
       *******************************************************************************/
      private void pace(AuthentikAdmin admin)
      {
         Integer millis = admin.getUtil().getRuntime().getConfig().getBulkPacingMillis();
         if(millis != null && millis > 0)
         {
            com.kingsrook.qqq.backend.core.utils.SleepUtils.sleep(millis, java.util.concurrent.TimeUnit.MILLISECONDS);
         }
      }



      /*******************************************************************************
       **
       *******************************************************************************/
      private void tally(AuthentikAdmin.AdminResult result, String[] w)
      {
         if(result.ok() && result.pending())
         {
            lines.computeIfAbsent("pending", k -> line(Status.WARNING, "change needs approval", "changes need approval", "change was sent for approval", "changes were sent for approval")).incrementCount();
         }
         else if(result.ok() && result.noChange())
         {
            lines.computeIfAbsent("nochange", k -> line(Status.INFO, "target needed no change", "targets needed no change", "target needed no change", "targets needed no change")).incrementCount();
         }
         else if(result.ok())
         {
            lines.computeIfAbsent("ok", k -> line(Status.OK, w[0], w[1], w[2], w[3])).incrementCount();
         }
         else
         {
            lines.computeIfAbsent("error:" + result.message(), k -> line(Status.ERROR, "target was not changed: " + result.message(), "targets were not changed: " + result.message(),
               "target was not changed: " + result.message(), "targets were not changed: " + result.message())).incrementCount();
         }
      }



      /*******************************************************************************
       ** Result lines.
       *******************************************************************************/
      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         ArrayList<ProcessSummaryLineInterface> rs = new ArrayList<>();
         lines.values().forEach(line -> line.addSelfToListIfAnyCount(rs));
         return (rs);
      }
   }

}
