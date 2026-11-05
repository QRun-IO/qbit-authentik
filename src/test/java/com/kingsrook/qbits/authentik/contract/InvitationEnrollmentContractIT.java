/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.contract;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.UUID;
import java.util.List;
import java.util.EnumSet;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.AuthentikAdmin;
import com.kingsrook.qbits.authentik.admin.AdminAction;
import com.kingsrook.qbits.authentik.admin.AdminRequest;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QUser;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import org.json.JSONObject;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Native enrollment ordering, protected correlation and public invitation to
 ** durable SQL inbox to audited membership using the non-superuser QBit bearer.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
class InvitationEnrollmentContractIT
{
   /***************************************************************************
    ** A consumed invitation is deleted before the write stage. Fixed data
    ** survives into the server-created user_write event with its actual pk.
    ***************************************************************************/
   @ParameterizedTest
   @ValueSource(booleans = { true, false })
   void consumedInvitationCorrelatesWithNativeUserCreationEvent(boolean withSavedReference) throws Exception
   {
      var stack = AuthentikTestStack.get();
      var admin = stack.admin();
      String owner = "qbit-invite-" + UUID.randomUUID().toString().substring(0, 8);
      String reference = UUID.randomUUID().toString();
      var earliest = java.time.Instant.now().minusSeconds(5);
      var cleanup = new ArrayList<String>();
      NativeAssignment assignment = null;
      var temporaryPermissions = withSavedReference ? stack.grantTemporaryPermissions(List.of(
         "authentik_stages_invitation.view_invitation", "authentik_stages_invitation.add_invitation",
         "authentik_core.change_group", "authentik_core.add_user_to_group")) : List.<String>of();
      try
      {
         String flow = create(admin, "/flows/instances/", new JSONObject().put("name", owner).put("slug", owner)
            .put("title", "Invitation contract").put("designation", "enrollment").put("authentication", "none"), cleanup);
         String inviteStage = create(admin, "/stages/invitation/stages/", new JSONObject().put("name", owner + "-invite")
            .put("continue_flow_without_invitation", false), cleanup);
         String writeStage = create(admin, "/stages/user_write/", new JSONObject().put("name", owner + "-write")
            .put("user_creation_mode", "always_create").put("user_type", "external").put("user_path_template", "users/invitation-contract"), cleanup);
         String prompt = create(admin, "/stages/prompt/prompts/", new JSONObject().put("name", owner + "-reference")
            .put("field_key", "qqq_invitation_reference").put("label", "Untrusted reference").put("type", "text").put("required", true), cleanup);
         String usernamePrompt = create(admin, "/stages/prompt/prompts/", new JSONObject().put("name", owner + "-username")
            .put("field_key", "username").put("label", "Username").put("type", "username").put("required", true), cleanup);
         String promptStage = create(admin, "/stages/prompt/stages/", new JSONObject().put("name", owner + "-prompt")
            .put("fields", new org.json.JSONArray().put(prompt).put(usernamePrompt)), cleanup);
         String policy = create(admin, "/policies/expression/", new JSONObject().put("name", owner + "-correlation")
            .put("expression", com.kingsrook.qbits.authentik.admin.AuthentikInvitationFlow.expression()), cleanup);
         create(admin, "/flows/bindings/", new JSONObject().put("target", flow).put("stage", inviteStage).put("order", 10), cleanup);
         create(admin, "/flows/bindings/", new JSONObject().put("target", flow).put("stage", promptStage).put("order", 15), cleanup);
         String writeBinding = create(admin, "/flows/bindings/", new JSONObject().put("target", flow).put("stage", writeStage).put("order", 20)
            .put("evaluate_on_plan", false).put("re_evaluate_policies", true).put("policy_engine_mode", "all"), cleanup);
         String protectionBinding = create(admin, "/policies/bindings/", new JSONObject().put("target", writeBinding).put("policy", policy).put("order", 0)
            .put("enabled", true).put("negate", false).put("failure_result", false), cleanup);
         String invitation;
         if(withSavedReference)
         {
            assignment = new NativeAssignment(stack, owner, cleanup);
            invitation = assignment.invite(owner);
            reference = assignment.sql.scalar("SELECT reference FROM authentik_invitation_assignment");
            cleanup.add("/stages/invitation/invitations/" + invitation + "/");
         }
         else
         {
            invitation = create(admin, "/stages/invitation/invitations/", new JSONObject().put("name", owner)
               .put("flow", flow).put("single_use", true).put("fixed_data", new JSONObject()
                  .put("username", owner).put("email", owner + "@example.test").put("name", "Invitation Contract")), cleanup);
         }

         var cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
         try(var browser = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).cookieHandler(cookies)
            .connectTimeout(Duration.ofSeconds(10)).build())
         {
            var entry = browser.send(HttpRequest.newBuilder(URI.create(stack.baseUrl() + "/if/flow/" + owner + "/?itoken=" + invitation))
               .timeout(Duration.ofSeconds(30)).GET().build(), HttpResponse.BodyHandlers.discarding());
            assertThat(entry.statusCode()).isEqualTo(200);
            URI executor = URI.create(stack.baseUrl() + "/api/v3/flows/executor/" + owner + "/?query=itoken%3D" + invitation);
            URI next = executor;
            HttpResponse<String> response = null;
            boolean consumedBeforeCreation = false;
            boolean forgedReferenceSubmitted = false;
            for(int transition = 0; transition < 8; transition++)
            {
               var request = HttpRequest.newBuilder(next).timeout(Duration.ofSeconds(30)).GET().build();
               response = browser.send(request, HttpResponse.BodyHandlers.ofString());
               if(response.statusCode() == 200 && "ak-stage-prompt".equals(new JSONObject(response.body()).optString("component")))
               {
                  assertThat(forgedReferenceSubmitted).isFalse();
                  String forged = new JSONObject().put("component", "ak-stage-prompt")
                     .put("username", owner)
                     .put("qqq_invitation_reference", UUID.randomUUID().toString()).toString();
                  response = browser.send(HttpRequest.newBuilder(next).timeout(Duration.ofSeconds(30))
                     .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(forged)).build(), HttpResponse.BodyHandlers.ofString());
                  forgedReferenceSubmitted = true;
               }
               if(response.statusCode() != 302)
               {
                  break;
               }
               if(admin.get("/stages/invitation/invitations/" + invitation + "/").status() == 404)
               {
                  if(!forgedReferenceSubmitted)
                  {
                     assertThat(admin.get("/core/users/?username=" + owner).results().length()).isZero();
                     consumedBeforeCreation = true;
                  }
               }
               next = next.resolve(response.headers().firstValue("Location").orElseThrow());
               assertThat(next.getScheme()).isEqualTo(executor.getScheme());
               assertThat(next.getAuthority()).isEqualTo(executor.getAuthority());
               assertThat(next.getPath()).isEqualTo(executor.getPath());
            }
            assertThat(consumedBeforeCreation).isTrue();
            assertThat(forgedReferenceSubmitted).isTrue();
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(new JSONObject(response.body()).optString("component")).isNotEqualTo("ak-stage-access-denied");
         }

         var users = admin.get("/core/users/?username=" + owner).results();
         assertThat(users.length()).isEqualTo(1);
         int userPk = users.getJSONObject(0).getInt("pk");
         cleanup.add("/core/users/" + userPk + "/");
         assertThat(admin.get("/stages/invitation/invitations/" + invitation + "/").status()).isEqualTo(404);
         var writes = admin.get("/events/events/?action=user_write&username=" + owner).results();
         assertThat(writes.length()).isEqualTo(1);
         var write = writes.getJSONObject(0);
         assertThat(write.getJSONObject("user").getInt("pk")).isEqualTo(userPk);
         assertThat(write.getJSONObject("context").getBoolean("created")).isTrue();
         if(withSavedReference)
         {
            assertThat(write.getJSONObject("context").getString("qqq_invitation_reference")).isEqualTo(reference);
         }
         else
         {
            assertThat(write.getJSONObject("context").has("qqq_invitation_reference")).isFalse();
         }
         var consumed = admin.get("/events/events/?action=invitation_used&page_size=100").results();
         JSONObject used = null;
         for(int i = 0; i < consumed.length(); i++)
         {
            var event = consumed.getJSONObject(i);
            if(invitation.replace("-", "").equals(event.getJSONObject("context").optString("invitation_uuid")))
            {
               used = event;
            }
         }
         assertThat(used).isNotNull();
         assertThat(used.getJSONObject("user").optInt("pk", -1)).isNotEqualTo(userPk);
         var config = assignment == null ? new com.kingsrook.qbits.authentik.AuthentikQBitConfig().withBaseUrl(stack.baseUrl())
            .withApiToken(stack.serviceAccountToken()).withAppKey("kof22-admin").withListCacheTtlSeconds(0) : assignment.config;
         var instance = assignment == null ? com.kingsrook.qbits.authentik.AuthentikTestSupport.produce(config) : assignment.instance;
         com.kingsrook.qqq.backend.core.context.QContext.init(instance,
            new com.kingsrook.qqq.backend.core.model.session.QSystemUserSession(instance));
         var evidence = new com.kingsrook.qbits.authentik.admin.AuthentikInvitationEvidence(
            com.kingsrook.qbits.authentik.client.AuthentikActionUtil.forBackend(config.getApiBackendName()));
         var latest = java.time.Instant.now().plusSeconds(5);
         var consumption = evidence.consumed(used.getString("pk"), invitation, owner, earliest, latest);
         assertThat(com.kingsrook.qbits.authentik.client.AuthentikActionUtil.forBackend(config.getApiBackendName())
            .invitationFlowSlug(flow)).isEqualTo(owner);
         assertThat(new com.kingsrook.qbits.authentik.admin.AuthentikInvitationFlow(
            com.kingsrook.qbits.authentik.client.AuthentikActionUtil.forBackend(config.getApiBackendName())).verify(owner)).isEqualTo(flow);
         assertThat(consumption.invitationId()).isEqualTo(invitation);
         String verifiedReference = reference;
         if(withSavedReference)
         {
            var enrollment = evidence.enrolled(write.getString("pk"), reference, owner, earliest, latest);
            assertThat(enrollment.userPk()).isEqualTo(userPk);
            assertThat(enrollment.createdAt()).isAfterOrEqualTo(consumption.createdAt());
            assignment.deliver(write, used, userPk);
            assertThat(admin.patch("/policies/bindings/" + protectionBinding + "/", new JSONObject().put("enabled", false)
               .put("target", writeBinding).put("policy", policy).put("order", 0)).status()).isEqualTo(200);
            assertThatThrownBy(() -> evidence.enrolled(write.getString("pk"), verifiedReference, owner, earliest, latest))
               .isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QException.class);
         }
         else
         {
            assertThatThrownBy(() -> evidence.enrolled(write.getString("pk"), verifiedReference, owner, earliest, latest))
               .isInstanceOf(com.kingsrook.qqq.backend.core.exceptions.QException.class);
         }
      }
      finally
      {
         com.kingsrook.qqq.backend.core.context.QContext.clear();
         try
         {
            if(assignment != null)
            {
               assignment.sql.close();
            }
            for(String path : cleanup.reversed())
            {
               admin.delete(path);
            }
         }
         finally
         {
            stack.removeTemporaryPermissions(temporaryPermissions);
         }
      }
   }

   /***************************************************************************
    ** Track exact test-owned resources and never echo potentially sensitive
    ** enrollment response bodies in an assertion failure.
    ***************************************************************************/
   private static String create(TestApi admin, String path, JSONObject body, ArrayList<String> cleanup)
   {
      var response = admin.post(path, body);
      assertThat(response.status()).as("create %s", path).isEqualTo(201);
      String pk = response.json().get("pk").toString();
      cleanup.add(path + (path.equals("/flows/instances/") ? body.getString("slug") : pk) + "/");
      return (pk);
   }

   /***************************************************************************
    ** Native provider plus real SQL administrative audit and invitation storage.
    ***************************************************************************/
   private static final class NativeAssignment
   {
      private final AuthentikTestStack stack;
      private final AuthentikQBitConfig config;
      private final QInstance instance;
      private final SessionSqlHost sql;
      private final String group;

      /***********************************************************************
       ** Create only owner-prefixed provider objects and a private host database.
       ***********************************************************************/
      private NativeAssignment(AuthentikTestStack stack, String owner, ArrayList<String> cleanup) throws Exception
      {
         this.stack = stack;
         var admin = stack.admin();
         String admins = create(admin, "/core/groups/", new JSONObject().put("name", owner + "-admins").put("attributes",
            new JSONObject().put("qqq.io/permissions", new org.json.JSONArray().put("authentik.*"))), cleanup);
         group = create(admin, "/core/groups/", new JSONObject().put("name", owner + "-readers").put("attributes",
            new JSONObject().put("qqq.io/permissions", new org.json.JSONArray().put("authentik.users.read"))), cleanup);
         String actor = create(admin, "/core/users/", new JSONObject().put("username", owner + "-operator").put("name", "Invitation operator")
            .put("email", owner + "-operator@example.test").put("type", "internal").put("path", "users/invitation-contract"), cleanup);
         assertThat(admin.post("/core/groups/" + admins + "/add_user/", new JSONObject().put("pk", Integer.parseInt(actor))).status()).isEqualTo(204);
         config = new AuthentikQBitConfig().withBaseUrl(stack.baseUrl()).withApiToken(stack.serviceAccountToken()).withAppKey("kof22-admin")
            .withListCacheTtlSeconds(0).withGroupCacheTtlSeconds(0).withInvitationFlow(owner).withLocalBackendName("memory")
            .withRecoveryEmailStage("kof22-recovery-email")
            .withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP));
         instance = new QInstance();
         instance.withInstanceDefaultAuthentication(new com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData()
            .withName("mock").withType(com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType.MOCK));
         instance.addBackend(new com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData().withName("memory")
            .withBackendType(com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule.class));
         new com.kingsrook.qbits.authentik.AuthentikQBitProducer().withQBitConfig(config).produce(instance);
         sql = new SessionSqlHost(instance, config, true);
         config.withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP,
            AuthentikFeature.MIRROR, AuthentikFeature.WEBHOOK));
         QSession session = new QSession();
         session.setUser(new QUser().withIdReference(owner + "-operator@example.test").withFullName("Invitation operator"));
         var permissions = new java.util.HashSet<String>();
         for(var permission : com.kingsrook.qbits.authentik.security.IdentityPermission.values())
         {
            permissions.add(permission.getSessionPermission());
         }
         session.setPermissions(permissions);
         QContext.init(instance, session);
      }

      /***********************************************************************
       ** Send through the public QBit action and verify actual email delivery.
       ***********************************************************************/
      private String invite(String owner) throws Exception
      {
         var result = AuthentikAdmin.forBackend(config.getApiBackendName()).execute(AdminRequest.of(AdminAction.INVITE_USER, "", "Native onboarding contract")
            .with("email", owner + "@example.test").with("name", "Invitation Contract").with("groupIds", group));
         assertThat(result.ok()).as(result.message()).isTrue();
         AuthentikTestStack.waitFor(Duration.ofSeconds(60), "the invitation email", () ->
         {
            try(var client = HttpClient.newHttpClient())
            {
               var response = client.send(HttpRequest.newBuilder(URI.create(stack.mailpitRoot() + "/api/v1/messages")).GET().build(), HttpResponse.BodyHandlers.ofString());
               for(Object raw : new JSONObject(response.body()).getJSONArray("messages"))
               {
                  for(Object recipient : ((JSONObject) raw).getJSONArray("To"))
                  {
                     if((owner + "@example.test").equalsIgnoreCase(((JSONObject) recipient).optString("Address")))
                     {
                        return (true);
                     }
                  }
               }
               return (false);
            }
            catch(Exception failure)
            {
               return (false);
            }
         });
         return (sql.scalar("SELECT invitation_id FROM authentik_invitation_assignment"));
      }

      /***********************************************************************
       ** Deliver enrollment first, then consumption. Native facts must produce
       ** a single audited membership through the production host processor.
       ***********************************************************************/
      private void deliver(JSONObject enrollment, JSONObject consumption, int userPk) throws Exception
      {
         QContext.init(instance, new QSystemUserSession(instance));
         var inbox = new com.kingsrook.qbits.authentik.sync.AuthentikWebhookInbox(config, Duration.ofMinutes(15));
         var processor = com.kingsrook.qbits.authentik.sync.AuthentikApplyChangeEvents.forHost(config, (snapshot, transaction) -> { });
         for(var event : List.of(enrollment, consumption))
         {
            inbox.accept(new com.kingsrook.qbits.authentik.sync.AuthentikWebhookEnvelope(event.getString("pk"), event.getString("action"),
               java.time.Instant.parse(event.getString("created")), null, null, null, null, null));
            var result = processor.runBatch();
            assertThat(result.succeeded()).isEqualTo(1);
            assertThat(result.retriedOrFailed()).isZero();
         }
         assertThat(sql.scalar("SELECT status FROM authentik_invitation_assignment")).isEqualTo("COMPLETE");
         assertThat(stack.admin().get("/core/groups/" + group + "/").json().getJSONArray("users").toList()).contains(userPk);
         assertThat(sql.scalar("SELECT COUNT(*) FROM authentik_admin_action WHERE action_name='ADD_MEMBER' AND status='SUCCEEDED'")).isEqualTo("1");
      }
   }
}
