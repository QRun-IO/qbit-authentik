/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.admin;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Map;
import java.util.UUID;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.processes.AuthentikProcesses;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qbits.authentik.sync.AuthentikInvitationAssignments;
import com.kingsrook.qbits.authentik.sync.AuthentikWebhookInbox;
import com.kingsrook.qbits.authentik.sync.AuthentikWebhookEnvelope;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData;
import org.h2.jdbcx.JdbcDataSource;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Exercise the public admin action with real host SQL and fixture provider HTTP.
 ** QQQ's normal admin audit tables remain on the existing memory test backend.
 *******************************************************************************/
class InvitationCreationSqlTest
{
   private AdminTestSupport support;
   private JdbcDataSource source;
   private Map<String, JSONObject> flow;
   private QSession operator;

   /***************************************************************************
    ** Add isolated SQL intent storage to the established admin/guard fixture.
    ***************************************************************************/
   @BeforeEach
   void setup() throws Exception
   {
      support = AdminTestSupport.create();
      String owner = "invitation_" + UUID.randomUUID().toString().replace("-", "");
      source = new JdbcDataSource();
      source.setURL("jdbc:h2:mem:" + owner + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1");
      source.setUser("sa");
      source.setPassword("");
      support.qInstance.addBackend(new RDBMSBackendMetaData().withName(owner).withVendor(RDBMSBackendMetaData.VENDOR_H2)
         .withJdbcUrl(source.getURL()).withUsername("sa").withPassword(""));
      sql(Files.readString(Path.of("docs/schema-sync.sql")));
      support.config.withLocalBackendName(owner).withInvitationFlow("enroll").withFeatures(EnumSet.of(
         AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP,
         AuthentikFeature.MIRROR, AuthentikFeature.WEBHOOK));
      support.authentik.users.get(1).put("uuid", "81000000-0000-0000-0000-000000000001");
      flow = AuthentikInvitationFlowTest.configuration();
      var provider = FixtureActionUtil.handler;
      FixtureActionUtil.handler = request ->
      {
         var response = flow.get(request.getURI().getPath());
         return (response == null ? provider.apply(request) : FixtureActionUtil.response(200, response.toString()));
      };
      operator = QContext.getQSession();
   }

   /***************************************************************************
    ** Delete only this test's in-memory database and context.
    ***************************************************************************/
   @AfterEach
   void cleanup() throws Exception
   {
      QContext.clear();
      FixtureActionUtil.reset();
      if(source != null)
      {
         sql("DROP ALL OBJECTS");
      }
   }

   /***************************************************************************
    ** The selected publisher group is within the original operator's grants.
    ***************************************************************************/
   private AdminRequest invite()
   {
      return (AdminRequest.of(AdminAction.INVITE_USER, "", "Approved onboarding").with("email", "guest@example.test")
         .with("groupIds", support.authentik.pk("kof-website-publishers"))
         .with("operatorPk", 999).with("operatorUuid", UUID.randomUUID().toString()));
   }

   /***************************************************************************
    ** Intent exists before creation, provider identity is attached before mail,
    ** and the normal interactive actor is restored before either provider write.
    ***************************************************************************/
   @Test
   void persistsAndAttachesBeforeEmailThenCancels() throws Exception
   {
      var provider = FixtureActionUtil.handler;
      FixtureActionUtil.handler = request ->
      {
         if("POST".equals(request.getMethod()) && request.getURI().getPath().contains("/stages/invitation/"))
         {
            assertThat(QContext.getQSession()).isSameAs(operator);
            assertThat(scalar("SELECT COUNT(*) FROM authentik_invitation_assignment")).isEqualTo("1");
            if(request.getURI().getPath().endsWith("/send_email/"))
            {
               assertThat(scalar("SELECT invitation_id FROM authentik_invitation_assignment")).isNotBlank();
            }
         }
         return (provider.apply(request));
      };
      var result = support.admin().execute(invite());
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(QContext.getQSession()).isSameAs(operator);
      var payload = new JSONObject(scalar("SELECT payload_json FROM authentik_invitation_assignment"));
      assertThat(payload.getInt("operatorPk")).isEqualTo(1);
      assertThat(payload.getString("operatorUuid")).isEqualTo("81000000-0000-0000-0000-000000000001");
      assertThat(payload.getString("reason")).isEqualTo("Approved onboarding");
      assertThat(payload.getJSONObject("groups").keySet()).containsExactly(support.authentik.pk("kof-website-publishers"));
      String invitation = scalar("SELECT invitation_id FROM authentik_invitation_assignment");
      assertThat(support.authentik.invitations.get(invitation).getJSONObject("fixed_data").getString(AuthentikInvitationEvidence.REFERENCE))
         .isEqualTo(scalar("SELECT reference FROM authentik_invitation_assignment"));
      assertThat(support.admin().execute(AdminRequest.of(AdminAction.CANCEL_INVITATION, invitation, "Withdraw offer")).ok()).isTrue();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("CANCELLED");
      assertThat(support.authentik.invitations).isEmpty();
   }

   /***************************************************************************
    ** Consuming/deleting the provider invitation does not defeat cancellation of
    ** deferred intent, including after its enrollment window has expired.
    ***************************************************************************/
   @Test
   void cancelsConsumedAndExpiredIntent() throws Exception
   {
      assertThat(support.admin().execute(invite()).ok()).isTrue();
      String invitation = scalar("SELECT invitation_id FROM authentik_invitation_assignment");
      support.authentik.invitations.clear();
      sql("UPDATE authentik_invitation_assignment SET expires_at=CURRENT_TIMESTAMP - INTERVAL '1' HOUR");
      assertThat(support.admin().execute(AdminRequest.of(AdminAction.CANCEL_INVITATION, invitation, "Withdraw offer")).ok()).isTrue();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("CANCELLED");
   }

   /***************************************************************************
    ** A rendered review cannot authorize a changed flow at execution time.
    ***************************************************************************/
   @Test
   void rechecksFlowAfterPreview() throws Exception
   {
      var preview = support.admin().plan(invite());
      assertThat(preview.isRunnable()).isTrue();
      flow.get("/api/v3/policies/bindings/").getJSONArray("results").getJSONObject(0).put("enabled", false);
      assertThat(support.admin().execute(preview, null).ok()).isFalse();
      assertThat(support.changes()).isEmpty();
      assertThat(scalar("SELECT COUNT(*) FROM authentik_invitation_assignment")).isEqualTo("0");
   }

   /***************************************************************************
    ** No remote invitation is created if durable intent cannot be saved.
    ***************************************************************************/
   @Test
   void storageFailureStopsProviderWritesAndRestoresActor() throws Exception
   {
      sql("DROP TABLE authentik_invitation_assignment");
      var result = support.admin().execute(invite());
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("state could not be accessed");
      assertThat(support.changes()).isEmpty();
      assertThat(QContext.getQSession()).isSameAs(operator);
   }

   /***************************************************************************
    ** Audit remains the first required durable step, before local intent too.
    ***************************************************************************/
   @Test
   void missingAuditStopsIntentAndProviderWrites() throws Exception
   {
      support.qInstance.getTables().remove(support.config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION));
      assertThatThrownBy(() -> support.admin().execute(invite())).isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QException.class);
      assertThat(support.changes()).isEmpty();
      assertThat(scalar("SELECT COUNT(*) FROM authentik_invitation_assignment")).isEqualTo("0");
   }

   /***************************************************************************
    ** Losing the attachment after remote creation must still prevent email.
    ***************************************************************************/
   @Test
   void attachFailureStopsEmail() throws Exception
   {
      var provider = FixtureActionUtil.handler;
      FixtureActionUtil.handler = request ->
      {
         var response = provider.apply(request);
         if("POST".equals(request.getMethod()) && request.getURI().getPath().endsWith("/stages/invitation/invitations/"))
         {
            sql("DROP TABLE authentik_invitation_assignment");
         }
         return (response);
      };
      var result = support.admin().execute(invite());
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("Invitation created", "email was not sent");
      assertThat(support.changes()).containsExactly("POST /stages/invitation/invitations/");
      assertThat(QContext.getQSession()).isSameAs(operator);
   }

   /***************************************************************************
    ** A stale session permission cannot replace the original actor's live rights.
    ***************************************************************************/
   @Test
   void refusesRevokedLiveMembershipAuthority() throws Exception
   {
      support.authentik.groupByName("identity-admins").getJSONObject("attributes").put("qqq.io/permissions",
         new org.json.JSONArray().put("authentik.users.manage").put("authentik.users.read").put("authentik.audit.read"));
      var result = support.admin().execute(invite());
      assertThat(result.ok()).isFalse();
      assertThat(result.message()).contains("no longer have");
      assertThat(support.changes()).isEmpty();
   }

   /***************************************************************************
    ** The existing paged group/QQQ-role picker is only offered with its services.
    ***************************************************************************/
   @Test
   void pickerRequiresAssignmentInfrastructure()
   {
      assertThat(AuthentikProcesses.definitions(support.config).stream().filter(def -> def.key().equals("inviteUser"))
         .findFirst().orElseThrow().fields()).anyMatch(field -> field.getName().equals("groupIds"));
      support.config.withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.MEMBERSHIP));
      assertThat(AuthentikProcesses.definitions(support.config).stream().filter(def -> def.key().equals("inviteUser"))
         .findFirst().orElseThrow().fields()).noneMatch(field -> field.getName().equals("groupIds"));
   }

   /***************************************************************************
    ** Saved intent and paired enrollment ready for the real admin execution path.
    ***************************************************************************/
   private record Deferred(String reference, AuthentikWebhookInbox inbox, AuthentikWebhookInbox.Claim claim)
   {
   }

   /***************************************************************************
    ** Create through the public invite action, then supply separately verified
    ** enrollment facts. Provider event verification has its own SQL contracts.
    ***************************************************************************/
   private Deferred readyAssignment() throws Exception
   {
      assertThat(support.admin().execute(invite()).ok()).isTrue();
      support.authentik.users.get(3).put("uuid", "81000000-0000-0000-0000-000000000003");
      QContext.setQSession(new QSystemUserSession(support.qInstance));
      var store = new AuthentikInvitationAssignments(support.config);
      String reference = scalar("SELECT reference FROM authentik_invitation_assignment");
      var intent = store.find(reference);
      var consumption = new AuthentikInvitationEvidence.Consumption(UUID.randomUUID().toString(), intent.invitationId(), intent.createdAt());
      var enrollment = new AuthentikInvitationEvidence.Enrollment(UUID.randomUUID().toString(), reference, 3, intent.createdAt());
      assertThat(store.bind(reference, consumption, enrollment, support.authentik.users.get(3).getString("uuid"))).isTrue();
      var inbox = new AuthentikWebhookInbox(support.config, java.time.Duration.ofMinutes(5));
      inbox.accept(new AuthentikWebhookEnvelope(enrollment.eventId(), "user_write", intent.createdAt(), "sam", null, null, null, null));
      support.authentik.writes.clear();
      return (new Deferred(reference, inbox, inbox.claim(1).getFirst()));
   }

   /***************************************************************************
    ** Audited human delegation grants once; later manual removal stays removed
    ** even when the same event or another worker tries to execute again.
    ***************************************************************************/
   @Test
   void deferredAssignmentAuditsBeforeWriteAndDoesNotReplayRemoval() throws Exception
   {
      var work = readyAssignment();
      var internal = QContext.getQSession();
      var provider = FixtureActionUtil.handler;
      FixtureActionUtil.handler = request ->
      {
         if(request.getURI().getPath().endsWith("/add_user/"))
         {
            assertThat(QContext.getQSession()).isNotInstanceOf(QSystemUserSession.class);
            assertThat(QContext.getQSession().getUser().getIdReference()).isEqualTo("operator@example.test");
            assertThat(new JSONObject(scalar("SELECT payload_json FROM authentik_invitation_assignment"))
               .getJSONObject("groups").getJSONObject(support.authentik.pk("kof-website-publishers")).getString("state")).isEqualTo("IN_FLIGHT");
            try
            {
               var query = new com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput();
               query.setTableName(support.config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION));
               assertThat(new com.kingsrook.qqq.backend.core.actions.tables.QueryAction().execute(query).getRecords())
                  .anyMatch(row -> "ADD_MEMBER".equals(row.getValueString("actionName")) && "RUNNING".equals(row.getValueString("status"))
                     && "operator@example.test".equals(row.getValueString("operator")));
            }
            catch(Exception failure)
            {
               throw (new AssertionError("Audit must precede provider write", failure));
            }
         }
         return (provider.apply(request));
      };
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim())).isTrue();
      assertThat(QContext.getQSession()).isSameAs(internal);
      assertThat(support.authentik.groupNamesOf(3)).contains("kof-website-publishers");
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("COMPLETE");
      support.authentik.groupByName("kof-website-publishers").put("users", new org.json.JSONArray().put(1));
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim())).isTrue();
      assertThat(support.authentik.groupNamesOf(3)).doesNotContain("kof-website-publishers");
      assertThat(support.changes()).hasSize(1);
   }

   /***************************************************************************
    ** Saved identities and original authority cannot be replaced by newer
    ** accounts, stale session grants, or a changed enrollment policy.
    ***************************************************************************/
   @ParameterizedTest
   @ValueSource(strings = {"operator-replaced", "operator-inactive", "target-replaced", "target-inactive", "authority-revoked", "flow-disabled"})
   void deferredAssignmentRejectsIdentityAndAuthorityChanges(String change) throws Exception
   {
      var work = readyAssignment();
      switch(change)
      {
         case "operator-replaced" -> support.authentik.users.get(1).put("uuid", UUID.randomUUID().toString());
         case "operator-inactive" -> support.authentik.users.get(1).put("is_active", false);
         case "target-replaced" -> support.authentik.users.get(3).put("uuid", UUID.randomUUID().toString());
         case "target-inactive" -> support.authentik.users.get(3).put("is_active", false);
         case "authority-revoked" -> support.authentik.groupByName("identity-admins").put("attributes", new JSONObject());
         case "flow-disabled" -> flow.get("/api/v3/policies/bindings/").getJSONArray("results").getJSONObject(0).put("enabled", false);
         default -> throw (new AssertionError("Unknown test case"));
      }
      var internal = QContext.getQSession();
      assertThatThrownBy(() -> support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim()))
         .isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QException.class);
      assertThat(QContext.getQSession()).isSameAs(internal);
      assertThat(support.changes()).isEmpty();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("REVIEW");
   }

   /***************************************************************************
    ** Missing audit prevents provider calls after reservation, leaving a visible
    ** review outcome instead of silently replaying the action on another event.
    ***************************************************************************/
   @Test
   void deferredAssignmentRequiresAuditAndInternalCaller() throws Exception
   {
      var work = readyAssignment();
      QContext.setQSession(operator);
      assertThatThrownBy(() -> support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim()))
         .isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException.class);
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("READY");
      QContext.setQSession(new QSystemUserSession(support.qInstance));
      support.qInstance.getTables().remove(support.config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION));
      assertThatThrownBy(() -> support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim()))
         .isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QException.class);
      assertThat(support.changes()).isEmpty();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("REVIEW");
   }

   /***************************************************************************
    ** Cancellation, read-only mode and expired inbox ownership prevent new
    ** attempts. They cannot be bypassed by a previously READY snapshot.
    ***************************************************************************/
   @Test
   void deferredAssignmentHonorsReadOnlyCancellationAndOwnership() throws Exception
   {
      var work = readyAssignment();
      support.config.withReadOnly(true);
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim())).isFalse();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("READY");
      support.config.withReadOnly(false);
      sql("UPDATE authentik_webhook_inbox SET lease_until=TIMESTAMP '2000-01-01 00:00:00'");
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim())).isFalse();
      assertThat(new AuthentikInvitationAssignments(support.config).cancel(work.reference())).isTrue();
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim())).isTrue();
      assertThat(support.changes()).isEmpty();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("CANCELLED");
   }

   /***************************************************************************
    ** A provider side effect followed by a lost response is never automatically
    ** retried as another saved attempt. Human review must resolve the outcome.
    ***************************************************************************/
   @Test
   void deferredAssignmentDoesNotReplayAmbiguousProviderOutcome() throws Exception
   {
      var work = readyAssignment();
      var provider = FixtureActionUtil.handler;
      FixtureActionUtil.handler = request ->
      {
         var result = provider.apply(request);
         if(request.getURI().getPath().endsWith("/add_user/"))
         {
            throw (new IllegalStateException("Simulated lost provider response"));
         }
         return (result);
      };
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim())).isTrue();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("REVIEW");
      assertThat(support.changes()).hasSize(1);
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim())).isTrue();
      assertThat(support.changes()).hasSize(1);
   }

   /***************************************************************************
    ** Normal membership protections still apply to a previously authorized
    ** invitation when the selected group or target changes before enrollment.
    ***************************************************************************/
   @ParameterizedTest
   @ValueSource(strings = {"target-protected", "group-superuser", "group-escalated"})
   void deferredAssignmentRetainsNormalMembershipProtection(String change) throws Exception
   {
      var work = readyAssignment();
      switch(change)
      {
         case "target-protected" -> support.authentik.users.get(3).getJSONObject("attributes").put("qqq.io/protected", true);
         case "group-superuser" -> support.authentik.groupByName("kof-website-publishers").put("is_superuser", true);
         case "group-escalated" ->
         {
            // Remove the operator from the selected group before expanding it.
            support.authentik.groupByName("kof-website-publishers").put("users", new org.json.JSONArray())
               .getJSONObject("attributes").put("qqq.io/permissions", new org.json.JSONArray().put("kof22.analytics.hasAccess"));
         }
         default -> throw (new AssertionError("Unknown test case"));
      }
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim())).isTrue();
      assertThat(support.changes()).isEmpty();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("REVIEW");
   }

   /***************************************************************************
    ** Rights revoked after the delegated session is prepared must still fail
    ** the fresh execution check; the old permission set is not authority.
    ***************************************************************************/
   @Test
   void deferredAssignmentRechecksRightsAfterPreparingSession() throws Exception
   {
      var work = readyAssignment();
      var provider = FixtureActionUtil.handler;
      FixtureActionUtil.handler = request ->
      {
         var result = provider.apply(request);
         if(request.getURI().getPath().contains("/policies/expression/"))
         {
            support.authentik.groupByName("identity-admins").put("attributes", new JSONObject());
         }
         return (result);
      };
      assertThatThrownBy(() -> support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim()))
         .isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException.class);
      assertThat(support.changes()).isEmpty();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("REVIEW");
      assertThat(QContext.getQSession()).isInstanceOf(QSystemUserSession.class);
   }

   /***************************************************************************
    ** From the public invitation action through real SQL inbox, event verifier,
    ** protected flow and admin writer, paired events result in one membership.
    ** Only provider HTTP is replaced; no direct binding is used in this test.
    ***************************************************************************/
   @Test
   void invitationEventsExecuteSavedMembershipThroughAdmin() throws Exception
   {
      assertThat(support.admin().execute(invite()).ok()).isTrue();
      support.authentik.users.get(3).put("uuid", "81000000-0000-0000-0000-000000000003");
      QContext.setQSession(new QSystemUserSession(support.qInstance));
      var store = new AuthentikInvitationAssignments(support.config);
      String reference = scalar("SELECT reference FROM authentik_invitation_assignment");
      var intent = store.find(reference);
      var events = new java.util.LinkedHashMap<String, JSONObject>();
      for(String action : java.util.List.of("user_write", "invitation_used"))
      {
         var context = new JSONObject().put("http_request", new JSONObject().put("path", "/api/v3/flows/executor/enroll/"));
         if(action.equals("user_write"))
         {
            context.put("created", true).put(AuthentikInvitationEvidence.REFERENCE, reference);
         }
         else
         {
            context.put("invitation_uuid", intent.invitationId().replace("-", ""));
         }
         String eventId = UUID.randomUUID().toString();
         events.put(eventId, new JSONObject().put("pk", eventId).put("action", action).put("created", intent.createdAt().toString())
            .put("user", new JSONObject().put("pk", action.equals("user_write") ? 3 : 1)).put("context", context));
      }
      var provider = FixtureActionUtil.handler;
      FixtureActionUtil.handler = request ->
      {
         String path = request.getURI().getPath();
         String id = path.substring(path.lastIndexOf('/', path.length() - 2) + 1, path.length() - 1);
         return ("GET".equals(request.getMethod()) && events.containsKey(id)
            ? FixtureActionUtil.response(200, events.get(id).toString()) : provider.apply(request));
      };
      var inbox = new AuthentikWebhookInbox(support.config, java.time.Duration.ofMinutes(5));
      var eventWorker = new com.kingsrook.qbits.authentik.sync.AuthentikInvitationEvents(support.admin().getUtil(), store);
      var processor = new com.kingsrook.qbits.authentik.sync.AuthentikApplyChangeEvents(inbox, (event, claim) ->
         assertThat(eventWorker.apply(inbox, claim)).isTrue());
      support.authentik.writes.clear();
      for(var event : events.values())
      {
         inbox.accept(new AuthentikWebhookEnvelope(event.getString("pk"), event.getString("action"), java.time.Instant.EPOCH,
            "untrusted", null, null, null, null));
         assertThat(processor.runBatch().succeeded()).isEqualTo(1);
      }
      assertThat(store.find(reference).status()).isEqualTo("COMPLETE");
      assertThat(support.authentik.groupNamesOf(3)).contains("kof-website-publishers");
      assertThat(support.changes()).containsExactly("POST /core/groups/" + support.authentik.pk("kof-website-publishers") + "/add_user/");
      assertThat(QContext.getQSession()).isInstanceOf(QSystemUserSession.class);
   }

   /***************************************************************************
    ** Disabling writes must retain the inbox trigger. Re-enabling can complete
    ** the same saved work without another webhook and without a failure retry.
    ***************************************************************************/
   @ParameterizedTest
   @ValueSource(booleans = {true, false})
   void deferredAssignmentResumesAfterReadOnlyPause(boolean readOnly) throws Exception
   {
      var work = readyAssignment();
      var originalFeatures = EnumSet.copyOf(support.config.getFeatures());
      if(readOnly)
      {
         support.config.withReadOnly(true);
      }
      else
      {
         var pausedFeatures = EnumSet.copyOf(originalFeatures);
         pausedFeatures.remove(AuthentikFeature.MEMBERSHIP);
         support.config.withFeatures(pausedFeatures);
      }
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), work.claim())).isFalse();
      assertThat(work.inbox().defer(work.claim())).isTrue();
      assertThat(support.changes()).isEmpty();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("READY");
      assertThat(scalar("SELECT attempts FROM authentik_webhook_inbox")).isEqualTo("0");
      sql("UPDATE authentik_webhook_inbox SET next_attempt_at=TIMESTAMP '2000-01-01 00:00:00'");
      support.config.withReadOnly(false).withFeatures(originalFeatures);
      var resumed = work.inbox().claim(1).getFirst();
      assertThat(support.admin().applyInvitationAssignments(work.reference(), work.inbox(), resumed)).isTrue();
      assertThat(work.inbox().complete(resumed)).isTrue();
      assertThat(scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("COMPLETE");
      assertThat(support.changes()).hasSize(1);
   }

   /***************************************************************************
    ** Fixture-only SQL, restricted to this test's isolated database.
    ***************************************************************************/
   private void sql(String command)
   {
      try(var connection = source.getConnection(); var statement = connection.createStatement())
      {
         statement.execute(command);
      }
      catch(Exception failure)
      {
         throw (new AssertionError("Fixture SQL failed", failure));
      }
   }

   /***************************************************************************
    ** Read persisted state during intercepted HTTP without changing QContext.
    ***************************************************************************/
   private String scalar(String command)
   {
      try(var connection = source.getConnection(); var statement = connection.createStatement(); var result = statement.executeQuery(command))
      {
         assertThat(result.next()).isTrue();
         return (result.getString(1));
      }
      catch(Exception failure)
      {
         throw (new AssertionError("Fixture SQL read failed", failure));
      }
   }
}
