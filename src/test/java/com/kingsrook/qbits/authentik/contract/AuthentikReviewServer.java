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


package com.kingsrook.qbits.authentik.contract;


import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikQBitProducer;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.instances.AbstractQQQApplication;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QUser;
import com.kingsrook.qqq.backend.core.modules.authentication.implementations.FullyAnonymousAuthenticationModule;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.middleware.javalin.QApplicationJavalinServer;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Loopback-only manual review host backed by a disposable real Authentik stack.
 ** Local automatic operator login is not an OAuth sign-in test. Audit and policy
 ** records use a private disposable SQL database; closing the JVM discards it.
 *******************************************************************************/
public class AuthentikReviewServer extends AbstractQQQApplication
{
   private static AuthentikTestStack stack;
   private static final String WEBHOOK_SECRET = java.util.UUID.randomUUID().toString() + java.util.UUID.randomUUID();
   private final String schedulerName = "qbit-review-" + java.util.UUID.randomUUID();
   private QInstance reviewInstance;
   private AuthentikQBitConfig reviewConfig;



   /*******************************************************************************
    ** Automatic local operator session. Never use this module outside this host.
    *******************************************************************************/
   public static class ReviewAuthentication extends FullyAnonymousAuthenticationModule
   {
      /*******************************************************************************
       ** Give the local reviewer the same identity that has live group grants.
       *******************************************************************************/
      @Override
      public QSession createSession(QInstance instance, Map<String, String> context)
      {
         QSession session = super.createSession(instance, context);
         // Fixed synthetic identities only. This deliberately unauthenticated
         // loopback test host is not an OAuth/authentication acceptance fixture.
         String selector = context == null ? null : context.getOrDefault("sessionUUID", context.get("sessionId"));
         boolean second = "qbit-authentik-review-second".equals(selector);
         session.setUser(new QUser().withIdReference(second ? "review.second@example.test" : "review.operator@example.test")
            .withFullName(second ? "Local Review Second Operator" : "Local Review Operator"));
         session.setPermissions(Arrays.stream(IdentityPermission.values()).map(IdentityPermission::getSessionPermission).collect(Collectors.toSet()));
         return (session);
      }
   }



   /*******************************************************************************
    ** Build the real qbit with disposable local persistence and write features.
    *******************************************************************************/
   @Override
   public QInstance defineQInstance() throws QException
   {
      QInstance instance = new QInstance();
      instance.withInstanceDefaultAuthentication(new QAuthenticationMetaData().withName("local-review")
         .withType(QAuthenticationType.FULLY_ANONYMOUS).withModuleCodeReference(new QCodeReference(ReviewAuthentication.class)));
      instance.addBackend(new QBackendMetaData().withName("review").withBackendType(MemoryBackendModule.class));
      ReviewSqlDatabase database = new ReviewSqlDatabase(instance);
      instance.addScheduler(new com.kingsrook.qqq.backend.core.model.metadata.scheduleing.quartz.QuartzSchedulerMetaData().withName(schedulerName));
      instance.addTable(new com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData()
         .withName("review_document").withLabel("Review Documents").withBackendName("review").withPrimaryKeyField("id")
         .withField(new com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData("id", com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType.INTEGER))
         .withField(new com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData("title", com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType.STRING))
         .withPermissionRules(new com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules()
            .withLevel(com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel.READ_INSERT_EDIT_DELETE_PERMISSIONS)));
      AuthentikQBitConfig config = new AuthentikQBitConfig()
         .withBaseUrl(stack.baseUrl()).withApiToken(stack.serviceAccountToken()).withAppKey("kof22-admin")
         .withLocalBackendName(ReviewSqlDatabase.BACKEND).withRecoveryEmailStage("kof22-recovery-email")
         .withSchedulerName(schedulerName).withWebhookSecret(WEBHOOK_SECRET)
         .withInvitationFlow("kof22-enrollment").withListCacheTtlSeconds(0).withGroupCacheTtlSeconds(0)
         .withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS,
            AuthentikFeature.MEMBERSHIP, AuthentikFeature.CREDENTIALS, AuthentikFeature.SESSIONS,
            AuthentikFeature.POLICIES, AuthentikFeature.DELETE, AuthentikFeature.MIRROR, AuthentikFeature.WEBHOOK));
      new AuthentikQBitProducer().withQBitConfig(config).produce(instance);
      try
      {
         database.initialize(instance);
      }
      catch(Exception failure)
      {
         throw (new QException("Could not initialize the private review database.", failure));
      }
      reviewInstance = instance;
      reviewConfig = config;
      instance.setHomeAppName("authentikAdmin");
      return (instance);
   }



   /*******************************************************************************
    ** Seed synthetic people and least-privilege service-account write grants.
    *******************************************************************************/
   private static void seed()
   {
      stack.grantTemporaryPermissions(List.of("authentik_core.add_user", "authentik_core.change_user", "authentik_core.reset_user_password", "authentik_core.delete_user", "authentik_core.delete_group",
      "authentik_core.add_group", "authentik_core.change_group", "authentik_core.add_user_to_group", "authentik_core.remove_user_from_group",
      "authentik_core.view_token", "authentik_core.delete_token", "authentik_core.delete_authenticatedsession",
      "authentik_stages_invitation.view_invitation", "authentik_stages_invitation.add_invitation", "authentik_stages_invitation.delete_invitation",
      "authentik_flows.view_flow",
      "authentik_stages_authenticator_totp.view_totpdevice", "authentik_stages_authenticator_totp.delete_totpdevice",
      "authentik_stages_authenticator_static.view_staticdevice", "authentik_stages_authenticator_static.delete_staticdevice",
      "authentik_stages_authenticator_webauthn.view_webauthndevice", "authentik_stages_authenticator_webauthn.delete_webauthndevice",
      "authentik_stages_authenticator_email.view_emaildevice", "authentik_stages_authenticator_email.delete_emaildevice",
      "authentik_stages_authenticator_sms.view_smsdevice", "authentik_stages_authenticator_sms.delete_smsdevice",
      "authentik_stages_authenticator_duo.view_duodevice", "authentik_stages_authenticator_duo.delete_duodevice"));
      TestApi admin = stack.admin();
      seedEnrollment(admin);
      requireCreated(admin.post("/core/groups/", new JSONObject().put("name", "Review Administrators")
         .put("attributes", new JSONObject().put("qqq.io/permissions", new JSONArray(List.of("authentik.*", "review_document.*"))))));
      requireCreated(admin.post("/core/groups/", new JSONObject().put("name", "Review Readers")
         .put("attributes", new JSONObject().put("qqq.io/permissions", new JSONArray(List.of("authentik.users.read"))))));
      for(String role : List.of("Viewer", "Editor"))
      {
         requireCreated(admin.post("/core/groups/", new JSONObject().put("name", "Review " + role)
            .put("attributes", new JSONObject().put("qqq.io/application-role", true).put("qqq.io/permissions",
               new JSONArray(role.equals("Viewer") ? List.of("review_document.read") : List.of("review_document.read", "review_document.edit"))))));
      }
      for(String name : List.of("operator", "second", "sam", "alex"))
      {
         requireCreated(admin.post("/core/users/", new JSONObject().put("username", "review." + name)
            .put("name", "Review " + name).put("email", "review." + name + "@example.test")
            .put("type", "internal").put("path", "users")));
         String group = List.of("operator", "second").contains(name) ? "Review Administrators" : "Review Readers";
         if(admin.post("/core/groups/" + admin.groupPk(group) + "/add_user/",
            new JSONObject().put("pk", admin.userPk("review." + name))).status() != 204)
         {
            throw (new IllegalStateException("Could not seed review membership"));
         }
      }
      String brand = admin.get("/core/brands/").results().getJSONObject(0).getString("brand_uuid");
      String flow = admin.first("/flows/instances/?slug=kof22-recovery").getString("pk");
      if(admin.patch("/core/brands/" + brand + "/", new JSONObject().put("flow_recovery", flow)).status() != 200)
      {
         throw (new IllegalStateException("Could not configure review recovery flow"));
      }
   }



   /*******************************************************************************
    ** Fail startup without disclosing response bodies when setup is incomplete.
    *******************************************************************************/
   private static void requireCreated(TestApi.Response response)
   {
      if(response.status() != 201)
      {
         throw (new IllegalStateException("Review seed failed: HTTP " + response.status()));
      }
   }



   /*******************************************************************************
    ** Start a fresh review stack and serve the embedded Next UI on loopback.
    *******************************************************************************/
   public static void main(String[] args) throws Exception
   {
      int port = args.length == 0 ? 18300 : Integer.parseInt(args[0]);
      System.setProperty("authentik.localReview", "true");
      System.setProperty("authentik.reviewWebhookSecret", WEBHOOK_SECRET);
      stack = AuthentikTestStack.get();
      seed();
      var application = new AuthentikReviewServer();
      new QApplicationJavalinServer(application).withPort(port).withServeFrontendNext(true)
         .withJavalinConfigCustomizer(config -> config.jetty.host = "127.0.0.1").start();
      application.startSynchronization();
      seedNotifications(stack.admin(), port);
      System.out.println("REVIEW UI http://localhost:" + port + "/app/authentikAdmin");
      System.out.println("REVIEW AUTHENTIK " + stack.baseUrl());
      System.out.println("REVIEW MAIL " + stack.mailpitRoot());
   }

   /***************************************************************************
    ** Protected invitation enrollment with the username prompt needed by the
    ** public invite action. Password setup remains available through recovery.
    ***************************************************************************/
   private static void seedEnrollment(TestApi admin)
   {
      String flow = create(admin, "/flows/instances/", new JSONObject().put("name", "Review enrollment").put("slug", "kof22-enrollment")
         .put("title", "Local review enrollment").put("designation", "enrollment").put("authentication", "none"));
      String invitation = create(admin, "/stages/invitation/stages/", new JSONObject().put("name", "review-invitation").put("continue_flow_without_invitation", false));
      String username = create(admin, "/stages/prompt/prompts/", new JSONObject().put("name", "review-username").put("field_key", "username")
         .put("label", "Username").put("type", "username").put("required", true));
      String prompt = create(admin, "/stages/prompt/stages/", new JSONObject().put("name", "review-signup").put("fields", new JSONArray().put(username)));
      String write = create(admin, "/stages/user_write/", new JSONObject().put("name", "review-create-account").put("user_creation_mode", "always_create")
         .put("user_type", "external").put("user_path_template", "users/review"));
      create(admin, "/flows/bindings/", new JSONObject().put("target", flow).put("stage", invitation).put("order", 10));
      create(admin, "/flows/bindings/", new JSONObject().put("target", flow).put("stage", prompt).put("order", 15));
      String binding = create(admin, "/flows/bindings/", new JSONObject().put("target", flow).put("stage", write).put("order", 20)
         .put("evaluate_on_plan", false).put("re_evaluate_policies", true).put("policy_engine_mode", "all"));
      try
      {
         String policy = create(admin, "/policies/expression/", new JSONObject().put("name", "review-invitation-correlation")
            .put("expression", com.kingsrook.qbits.authentik.admin.AuthentikInvitationFlow.expression()).put("execution_logging", false));
         create(admin, "/policies/bindings/", new JSONObject().put("target", binding).put("policy", policy).put("order", 0)
            .put("enabled", true).put("negate", false).put("failure_result", false));
      }
      catch(java.io.IOException failure)
      {
         throw (new IllegalStateException("Cannot load protected enrollment policy.", failure));
      }
   }

   /***************************************************************************
    ** Use the normal QQQ Quartz jobs, with one initial baseline before review.
    ***************************************************************************/
   private void startSynchronization() throws Exception
   {
      var previous = com.kingsrook.qqq.backend.core.context.QContext.capture();
      try
      {
         com.kingsrook.qqq.backend.core.context.QContext.init(reviewInstance, new com.kingsrook.qqq.backend.core.model.session.QSystemUserSession(reviewInstance));
         boolean refreshed = new com.kingsrook.qbits.authentik.sync.AuthentikMirrorWorker(reviewConfig,
            com.kingsrook.qbits.authentik.client.AuthentikActionUtil.forBackend(reviewConfig.getApiBackendName()))
            .fullRefresh((snapshot, transaction) -> { }, null, null);
         if(!refreshed)
         {
            throw (new IllegalStateException("Initial review synchronization did not complete."));
         }
         if(reviewInstance.getSchedulableType("PROCESS") == null)
         {
            reviewInstance.addSchedulableType(new com.kingsrook.qqq.backend.core.scheduler.schedulable.SchedulableType().withName("PROCESS")
               .withRunner(new QCodeReference(com.kingsrook.qqq.backend.core.scheduler.schedulable.runner.SchedulableProcessRunner.class)));
         }
         var properties = new java.util.Properties();
         properties.setProperty("org.quartz.scheduler.instanceName", schedulerName);
         properties.setProperty("org.quartz.threadPool.threadCount", "2");
         properties.setProperty("org.quartz.jobStore.class", "org.quartz.simpl.RAMJobStore");
         var scheduler = com.kingsrook.qqq.backend.core.scheduler.quartz.QuartzScheduler.initInstance(reviewInstance, schedulerName, properties,
            () -> new com.kingsrook.qqq.backend.core.model.session.QSystemUserSession(reviewInstance));
         scheduler.start();
         for(var process : com.kingsrook.qbits.authentik.sync.AuthentikSyncProcesses.processes(reviewInstance, reviewConfig))
         {
            scheduler.setupSchedulable(new com.kingsrook.qqq.backend.core.scheduler.schedulable.identity.BasicSchedulableIdentity("process:" + process.getName(), null),
               reviewInstance.getSchedulableType("PROCESS"), Map.of("processName", process.getName()), process.getSchedule(), true);
         }
      }
      finally
      {
         com.kingsrook.qqq.backend.core.context.QContext.init(previous);
      }
   }

   /***************************************************************************
    ** Docker Desktop's native gateway reaches this Windows loopback host.
    ** Destination group also covers anonymous invitation consumption.
    ***************************************************************************/
   private static void seedNotifications(TestApi admin, int port)
   {
      String body = create(admin, "/propertymappings/notification/", new JSONObject().put("name", "review-sync-body").put("expression", """
         event = notification.event
         return {"eventPk": str(event.pk), "action": event.action, "created": event.created.isoformat(),
                 "username": (event.user or {}).get("username"), "model": (event.context or {}).get("model"), "app": event.app}
         """));
      String headers = create(admin, "/propertymappings/notification/", new JSONObject().put("name", "review-sync-headers").put("expression", """
         from os import environ
         return {"X-QQQ-Webhook-Secret": environ["QBIT_REVIEW_WEBHOOK_SECRET"]}
         """));
      String transport = create(admin, "/events/transports/", new JSONObject().put("name", "review-sync").put("mode", "webhook").put("send_once", true)
         .put("webhook_url", "http://host.docker.internal:" + port + "/qqq/hooks/authentik/webhook")
         .put("webhook_mapping_body", body).put("webhook_mapping_headers", headers));
      String rule = create(admin, "/events/rules/", new JSONObject().put("name", "review-identity-sync").put("transports", new JSONArray().put(transport))
         .put("destination_group", admin.groupPk("Review Administrators")).put("destination_event_user", false));
      int order = 0;
      for(String action : List.of("model_created", "model_updated", "model_deleted", "login", "login_failed", "password_set", "invitation_used", "user_write"))
      {
         for(String model : action.startsWith("model_") ? List.of("authentik_core.user", "authentik_core.group") : List.of(""))
         {
            String policy = create(admin, "/policies/event_matcher/", new JSONObject().put("name", "review-sync-" + order).put("action", action)
               .put("model", model.isEmpty() ? JSONObject.NULL : model));
            create(admin, "/policies/bindings/", new JSONObject().put("target", rule).put("policy", policy).put("order", order++)
               .put("enabled", true).put("negate", false).put("failure_result", false));
         }
      }
   }

   /***************************************************************************
    ** Keep configuration failures useful without echoing provider request data.
    ***************************************************************************/
   private static String create(TestApi admin, String path, JSONObject body)
   {
      var response = admin.post(path, body);
      if(response.status() != 201)
      {
         throw (new IllegalStateException("Review setup failed for " + path + ": HTTP " + response.status()));
      }
      return (response.json().get("pk").toString());
   }

}
