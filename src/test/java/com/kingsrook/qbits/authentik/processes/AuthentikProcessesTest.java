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
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.admin.AdminTestSupport;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qqq.backend.core.actions.processes.RunProcessAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLine;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessOutput;
import com.kingsrook.qqq.backend.core.model.actions.processes.Status;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.StreamedETLWithFrontendProcess;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** The record and table actions run as standard streamed-ETL processes through
 ** QQQ's own RunProcessAction: a details screen, a Review step (the dry run,
 ** with refused targets and why) and a Result step, and none is in the nav.
 *******************************************************************************/
class AuthentikProcessesTest
{
   private AdminTestSupport t;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeEach
   void setUp() throws QException
   {
      t = AdminTestSupport.create();
   }



   /*******************************************************************************
    ** What a run produced: the Review lines and the Result lines.
    *******************************************************************************/
   private record Outcome(List<ProcessSummaryLine> review, List<ProcessSummaryLine> result)
   {
      /*******************************************************************************
       ** All messages of a list, for readable assertions.
       *******************************************************************************/
      static List<String> messages(List<ProcessSummaryLine> lines)
      {
         return (lines.stream().map(l -> l.getCount() + " " + l.getMessage()).toList());
      }
   }



   /*******************************************************************************
    ** Run a process as the frontend would: start (collecting the first screen),
    ** submit the details with a full validation, review, execute.
    *******************************************************************************/
   @SuppressWarnings("unchecked")
   private Outcome run(String processName, String table, String key, List<? extends Serializable> keys, Map<String, Serializable> form, boolean execute) throws QException
   {
      RunProcessInput input = new RunProcessInput();
      input.setProcessName(processName);
      if(keys != null)
      {
         input.addValue("recordIds", keys.stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(",")));
      }
      RunProcessOutput output = new RunProcessAction().execute(input);
      input.setProcessUUID(output.getProcessUUID());
      form.forEach(input::addValue);
      input.setStartAfterStep(t.qInstance.getProcess(processName).getStepList().stream().filter(s -> s.getName().equals("details")).findFirst().isPresent() ? "details" : null);
      output = new RunProcessAction().execute(input);
      assertThat(output.getException()).isEmpty();

      /////////////////////////////////////////////////////////////////////////////
      // the process defaults to full validation, so the Review screen already  //
      // holds the dry-run lines for every target                               //
      /////////////////////////////////////////////////////////////////////////////
      List<ProcessSummaryLine> review = (List<ProcessSummaryLine>) output.getValues().get(StreamedETLWithFrontendProcess.FIELD_VALIDATION_SUMMARY);
      assertThat(output.getProcessState().getNextStepName()).contains("review");
      if(!execute)
      {
         return (new Outcome(review, List.of()));
      }

      input.setStartAfterStep("review");
      output = new RunProcessAction().execute(input);
      assertThat(output.getException()).isEmpty();
      return (new Outcome(review, (List<ProcessSummaryLine>) output.getValues().get(StreamedETLWithFrontendProcess.FIELD_PROCESS_SUMMARY)));
   }



   /*******************************************************************************
    ** Which processes exist depends on the features; they are table or record
    ** actions (bound to a table, hidden from the nav by not being in an app).
    *******************************************************************************/
   @Test
   void processesFollowFeaturesAndAreNeverInTheNav() throws QException
   {
      assertThat(t.qInstance.getProcesses().keySet()).contains("authentikCreateUser", "authentikInviteUser", "authentikEditUser", "authentikDeactivateUser",
         "authentikReactivateUser", "authentikAddToGroup", "authentikRemoveFromGroup", "authentikSendPasswordReset", "authentikResetMfa", "authentikRevokeAppPasswords",
         "authentikRevokeSessions", "authentikCreateGroup", "authentikEditGroup", "authentikEditPermissions", "authentikAddMembers", "authentikRemoveMembers",
         "authentikCancelInvitation", "authentikApprove", "authentikReject");

      for(QProcessMetaData process : t.qInstance.getProcesses().values())
      {
         assertThat(process.getTableName()).as(process.getName()).isNotBlank();
         assertThat(t.qInstance.getApp("authentikAdmin").getChildren()).extracting(c -> c.getName()).doesNotContain(process.getName());
      }
      assertThat(t.qInstance.getProcess("authentikCreateUser").getMaxInputRecords()).isEqualTo(0);
      assertThat(t.qInstance.getProcess("authentikEditUser").getMaxInputRecords()).isEqualTo(1);
      assertThat(t.qInstance.getProcess("authentikAddToGroup").getMinInputRecords()).isEqualTo(1);

      AdminTestSupport readOnly = AdminTestSupport.create(java.util.EnumSet.of(AuthentikFeature.READ, AuthentikFeature.MEMBERSHIP));
      assertThat(readOnly.qInstance.getProcesses().keySet()).contains("authentikAddToGroup", "authentikAddMembers").doesNotContain("authentikCreateUser", "authentikEditPermissions", "authentikApprove");
   }



   /*******************************************************************************
    ** Add To Group: the Review is a dry run (nothing sent), refused people are
    ** listed with the reason, the Result applies the rest.
    *******************************************************************************/
   @Test
   void addToGroupReviewThenResult() throws QException
   {
      Map<String, Serializable> form = Map.of("group", t.authentik.pk("kof-website-publishers"), "reason", "onboarding");

      Outcome review = run("authentikAddToGroup", t.config.applyTablePrefix(AuthentikTables.USER), "pk", List.of(3, 4, 7), form, false);
      assertThat(Outcome.messages(review.review())).anyMatch(m -> m.contains("membership will be added") || m.contains("memberships will be added"));
      assertThat(review.review()).anyMatch(l -> l.getStatus() == Status.ERROR && l.getMessage().toLowerCase().contains("protected"));
      assertThat(t.writes()).as("review is a dry run").isEmpty();

      Outcome result = run("authentikAddToGroup", t.config.applyTablePrefix(AuthentikTables.USER), "pk", List.of(3, 4, 7), form, true);
      assertThat(result.result()).anyMatch(l -> l.getStatus() == Status.OK && l.getCount() == 2);
      assertThat(result.result()).anyMatch(l -> l.getStatus() == Status.ERROR);
      assertThat(t.authentik.groupNamesOf(3)).contains("kof-website-publishers");
      assertThat(t.authentik.groupNamesOf(7)).contains("kof-website-publishers");
      assertThat(t.authentik.groupNamesOf(4)).doesNotContain("kof-website-publishers");
   }



   /*******************************************************************************
    ** Create User is a table action with no records: the form carries the data.
    *******************************************************************************/
   @Test
   void createUserIsATableAction() throws QException
   {
      Map<String, Serializable> form = Map.of("username", "newbie", "name", "New Bie", "email", "newbie@example.test", "reason", "new hire", "groups", "", "sendRecovery", true);
      Outcome outcome = run("authentikCreateUser", t.config.applyTablePrefix(AuthentikTables.USER), null, null, form, true);

      assertThat(Outcome.messages(outcome.review())).anyMatch(m -> m.contains("user will be created"));
      assertThat(Outcome.messages(outcome.result())).anyMatch(m -> m.contains("user was created"));
      assertThat(t.authentik.users.values()).anyMatch(u -> u.getString("username").equals("newbie"));
   }



   /*******************************************************************************
    ** Edit Permissions fills its form from the group (prepare step) and sends the
    ** stale-check fingerprint back with it.
    *******************************************************************************/
   @Test
   void editPermissionsPrefillsTheForm() throws QException
   {
      RunProcessInput input = new RunProcessInput();
      input.setProcessName("authentikEditPermissions");
      input.addValue("recordIds", t.authentik.pk("kof-website-analysts"));
      RunProcessOutput output = new RunProcessAction().execute(input);

      assertThat(output.getValues().get("permissions")).isEqualTo("kof22.analytics.hasAccess");
      assertThat(String.valueOf(output.getValues().get("expectedFingerprint"))).hasSize(16);
   }



   /*******************************************************************************
    ** A change that needs a second person shows as a warning in Review and is
    ** queued by the Result; Approve then applies it.
    *******************************************************************************/
   @Test
   void approvalFlowThroughProcesses() throws QException
   {
      Map<String, Serializable> form = Map.of("permissions", "cms.publish.hasAccess\nauthentik.users.read", "appAccess", "kof22-website-prod", "reason", "grant");
      String table = t.config.applyTablePrefix(AuthentikTables.GROUP);
      Outcome outcome = run("authentikEditPermissions", table, "pk", List.of(t.authentik.pk("kof-website-publishers")), form, true);

      assertThat(outcome.review()).anyMatch(l -> l.getStatus() == Status.WARNING && l.getMessage().contains("second person"));
      assertThat(outcome.result()).anyMatch(l -> l.getStatus() == Status.WARNING);
      assertThat(t.writes()).isEmpty();

      t.loginAs("second@example.test", com.kingsrook.qbits.authentik.security.IdentityPermission.values());
      String approvalTable = t.config.applyTablePrefix(AuthentikLocalTables.APPROVAL_REQUEST);
      Outcome approved = run("authentikApprove", approvalTable, "id", List.of(1), Map.of(), true);
      assertThat(approved.result()).anyMatch(l -> l.getStatus() == Status.OK);
      assertThat(t.authentik.groupByName("kof-website-publishers").getJSONObject("attributes").getJSONArray("qqq.io/permissions").toList()).contains("authentik.users.read");
   }



   /*******************************************************************************
    ** More than 25 people in one run needs the count typed.
    *******************************************************************************/
   @Test
   void bulkAboveTwentyFiveNeedsTypedCount() throws QException
   {
      for(int pk = 200; pk < 230; pk++)
      {
         t.authentik.user(pk, "bulk" + pk, "bulk" + pk + "@example.test", "internal", true);
      }
      List<Integer> keys = new java.util.ArrayList<>();
      for(int pk = 200; pk < 230; pk++)
      {
         keys.add(pk);
      }

      Map<String, Serializable> untyped = Map.of("group", t.authentik.pk("kof-website-publishers"), "reason", "bulk");
      Outcome review = run("authentikAddToGroup", t.config.applyTablePrefix(AuthentikTables.USER), "pk", keys, untyped, false);
      assertThat(review.review()).anyMatch(l -> l.getStatus() == Status.ERROR && l.getMessage().contains("type 30"));
      assertThat(t.writes()).isEmpty();

      Map<String, Serializable> typed = Map.of("group", t.authentik.pk("kof-website-publishers"), "reason", "bulk", "confirmText", "30");
      Outcome result = run("authentikAddToGroup", t.config.applyTablePrefix(AuthentikTables.USER), "pk", keys, typed, true);
      assertThat(result.result()).anyMatch(l -> l.getStatus() == Status.OK && l.getCount() == 30);
   }

}
