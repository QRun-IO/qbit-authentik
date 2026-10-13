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


import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikQBitProducer;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import com.kingsrook.qbits.authentik.admin.AdminAction;
import com.kingsrook.qbits.authentik.admin.AdminRequest;
import com.kingsrook.qbits.authentik.admin.AuthentikAdmin;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QUser;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** The qbit's WRITE path against a real Authentik 2026.8.3 (DESIGN.md section
 ** 10 contract tests a, f and the phase 2/3 actions), as the service account
 ** holding the phase 2/3 role permissions (granted additively here and removed
 ** again): create user + groups + the recovery email arriving in Mailpit,
 ** membership, permission attributes (merged into the current attributes),
 ** deactivation, app-password revocation that spares API tokens, the guard
 ** refusing superuser groups and protected accounts before Authentik is
 ** called, and the audit event naming the human operator.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Order(70)
class QbitWriteContractIT
{
   private static final String OPERATOR_EMAIL = "wr.operator@example.test";

   /** The operator's own policy: they may grant read and edit on wr_page. */
   private static final String WR_POLICY = "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\",\"edit\"],\"Resource\":[\"wr_page\"]}]}";

   /** The phase 2/3 permissions of DESIGN.md section 5.1 (plus view_flow to resolve the invitation flow by slug). */
   private static final List<String> ROLE_PERMISSIONS = List.of(
      "authentik_core.add_user", "authentik_core.change_user", "authentik_core.reset_user_password",
      "authentik_core.add_group", "authentik_core.change_group", "authentik_core.add_user_to_group", "authentik_core.remove_user_from_group",
      "authentik_core.view_token", "authentik_core.delete_token", "authentik_core.delete_authenticatedsession",
      "authentik_stages_invitation.view_invitation", "authentik_stages_invitation.add_invitation", "authentik_stages_invitation.delete_invitation",
      "authentik_flows.view_flow",
      "authentik_stages_authenticator_totp.view_totpdevice", "authentik_stages_authenticator_totp.delete_totpdevice",
      "authentik_stages_authenticator_static.view_staticdevice", "authentik_stages_authenticator_static.delete_staticdevice",
      "authentik_stages_authenticator_webauthn.view_webauthndevice", "authentik_stages_authenticator_webauthn.delete_webauthndevice",
      "authentik_stages_authenticator_email.view_emaildevice", "authentik_stages_authenticator_email.delete_emaildevice",
      "authentik_stages_authenticator_sms.view_smsdevice", "authentik_stages_authenticator_sms.delete_smsdevice",
      "authentik_stages_authenticator_duo.view_duodevice", "authentik_stages_authenticator_duo.delete_duodevice");

   private static AuthentikTestStack stack;
   private static TestApi            admin;
   private static String             roleUuid;

   private QInstance           qInstance;
   private AuthentikQBitConfig config;



   /*******************************************************************************
    ** Grant the role permissions, and create an operator who is an identity
    ** administrator through a group (so the live subset rule has something to
    ** resolve), plus the enrollment flow.
    *******************************************************************************/
   @BeforeAll
   static void beforeAll()
   {
      stack = AuthentikTestStack.get();
      admin = stack.admin();
      roleUuid = admin.first("/rbac/roles/?name=" + AuthentikTestStack.SERVICE_ACCOUNT).getString("pk");
      admin.post("/rbac/permissions/assigned_by_roles/" + roleUuid + "/assign/", new JSONObject().put("permissions", new JSONArray(ROLE_PERMISSIONS)));

      admin.post("/core/groups/", new JSONObject().put("name", "wr-admins").put("attributes",
         new JSONObject().put("qqq.io/permissions", new JSONArray(List.of("authentik.*"))).put("qqq.io/app-access", new JSONArray(List.of(AuthentikTestStack.APP_SLUG)))
            .put("qqq.io/policy", WR_POLICY)));
      admin.post("/core/groups/", new JSONObject().put("name", "wr-readers").put("attributes",
         new JSONObject().put("qqq.io/permissions", new JSONArray(List.of("authentik.users.read")))));
      admin.post("/core/users/", new JSONObject().put("username", "wr.operator").put("name", "WR Operator").put("email", OPERATOR_EMAIL).put("type", "internal").put("path", "users"));
      admin.post("/core/groups/" + admin.groupPk("wr-admins") + "/add_user/", new JSONObject().put("pk", admin.userPk("wr.operator")));
      admin.post("/core/users/", new JSONObject().put("username", "wr.target").put("name", "WR Target").put("email", "wr.target@example.test").put("type", "internal").put("path", "users"));
      admin.post("/flows/instances/", new JSONObject().put("name", "wr enrollment").put("slug", "wr-enrollment").put("title", "Enroll").put("designation", "enrollment"));

      ///////////////////////////////////////////////////////////////////////////////
      // recovery_email needs the brand to have a recovery flow ("No recovery flow  //
      // set." otherwise): an owner prerequisite, documented in the checklist       //
      ///////////////////////////////////////////////////////////////////////////////
      String brand = admin.get("/core/brands/").results().getJSONObject(0).getString("brand_uuid");
      String flow  = admin.first("/flows/instances/?slug=kof22-recovery").getString("pk");
      admin.patch("/core/brands/" + brand + "/", new JSONObject().put("flow_recovery", flow));
   }



   /*******************************************************************************
    ** Remove the test-only grants again.
    *******************************************************************************/
   @AfterAll
   static void afterAll()
   {
      if(admin != null && roleUuid != null)
      {
         admin.patch("/rbac/permissions/assigned_by_roles/" + roleUuid + "/unassign/", new JSONObject().put("permissions", new JSONArray(ROLE_PERMISSIONS)));
      }
   }



   /*******************************************************************************
    ** A fresh qbit instance (all write features, audit on the memory backend)
    ** and the operator's session.
    *******************************************************************************/
   @BeforeEach
   void beforeEach() throws QException
   {
      MemoryRecordStore.getInstance().reset();
      config = new AuthentikQBitConfig()
         .withBaseUrl(stack.baseUrl())
         .withApiToken(stack.serviceAccountToken())
         .withAppKey("kof22-admin")
         .withListCacheTtlSeconds(0)
         .withGroupCacheTtlSeconds(0)
         .withBulkPacingMillis(0)
         .withLocalBackendName("memory")
         .withRecoveryEmailStage("kof22-recovery-email")
         .withInvitationFlow("wr-enrollment")
         .withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP,
            AuthentikFeature.CREDENTIALS, AuthentikFeature.SESSIONS, AuthentikFeature.POLICIES));

      qInstance = new QInstance();
      qInstance.withInstanceDefaultAuthentication(new QAuthenticationMetaData().withName("mock").withType(QAuthenticationType.MOCK));
      qInstance.addBackend(new QBackendMetaData().withName("memory").withBackendType(MemoryBackendModule.class));
      qInstance.addTable(new com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData().withName("wr_page").withBackendName("memory").withPrimaryKeyField("id")
         .withField(new com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData("id", com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType.INTEGER))
         .withPermissionRules(new com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules()
            .withLevel(com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel.READ_INSERT_EDIT_DELETE_PERMISSIONS)));
      new AuthentikQBitProducer().withQBitConfig(config).produce(qInstance);

      Set<String> permissions = new HashSet<>();
      for(IdentityPermission permission : IdentityPermission.values())
      {
         permissions.add(permission.getSessionPermission());
      }
      QSession session = new QSession();
      session.setUser(new QUser().withIdReference(OPERATOR_EMAIL).withFullName("WR Operator"));
      session.setPermissions(permissions);
      QContext.init(qInstance, session);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @AfterEach
   void afterEach()
   {
      QContext.clear();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AuthentikAdmin.AdminResult run(AdminRequest request) throws QException
   {
      return (new AuthentikAdmin(AuthentikActionUtil.forBackend(config.getApiBackendName())).execute(request));
   }



   /*******************************************************************************
    ** (a) Create user -> add to group -> recovery email arrives in Mailpit; no
    ** password is set; the operator's identity is on the user and in Authentik's
    ** event log.
    *******************************************************************************/
   @Test
   void createUserSendsRecoveryEmailAndAuditsInAuthentik() throws Exception
   {
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.CREATE_USER, "", "contract test").with("username", "wr.created").with("name", "WR Created")
         .with("email", "wr.created@example.test").with("groups", "wr-readers"));

      assertThat(result.ok()).as(result.message()).isTrue();
      JSONObject user = admin.first("/core/users/?username=wr.created&include_groups=true");
      assertThat(user.getString("email")).isEqualTo("wr.created@example.test");
      assertThat(user.getString("path")).isEqualTo("users");
      assertThat(user.getJSONObject("attributes").getString("qqq.io/created-by")).isEqualTo(OPERATOR_EMAIL);
      assertThat(user.getJSONArray("groups_obj").getJSONObject(0).getString("name")).isEqualTo("wr-readers");

      AuthentikTestStack.waitFor(Duration.ofSeconds(60), "the recovery email in Mailpit", () -> mailpitHas("wr.created@example.test"));

      AuthentikTestStack.waitFor(Duration.ofSeconds(30), "the audit event naming the operator", () ->
      {
         for(Object event : admin.get("/events/events/?search=" + TestApi.encode(OPERATOR_EMAIL) + "&ordering=-created").results())
         {
            JSONObject context = ((JSONObject) event).optJSONObject("context");
            if(((JSONObject) event).getString("action").startsWith("custom_") && context != null && "CREATE_USER".equals(context.optString("action")))
            {
               return (OPERATOR_EMAIL.equals(context.optString("operator")) && "contract test".equals(context.optString("reason")));
            }
         }
         return (false);
      });
   }



   /*******************************************************************************
    ** Memberships both ways, with the subset rule using the operator's live
    ** groups (wr-admins holds authentik.*, so adding to wr-readers is allowed).
    *******************************************************************************/
   @Test
   void addAndRemoveMember() throws Exception
   {
      int    target = admin.userPk("wr.target");
      String group  = admin.groupPk("wr-readers");

      assertThat(run(AdminRequest.of(AdminAction.ADD_MEMBER, group + ":" + target, "contract test")).ok()).isTrue();
      assertThat(memberNames("wr-readers")).contains("wr.target");

      assertThat(run(AdminRequest.of(AdminAction.REMOVE_MEMBER, group + ":" + target, "contract test")).ok()).isTrue();
      assertThat(memberNames("wr-readers")).doesNotContain("wr.target");
   }



   /*******************************************************************************
    ** The guard refuses a superuser group and a protected account BEFORE
    ** Authentik is called (Authentik itself would refuse the first, and allow the
    ** second: contract test (b) and the lockout findings).
    *******************************************************************************/
   @Test
   void guardRefusesBeforeAuthentikIsCalled() throws Exception
   {
      int    target    = admin.userPk("wr.target");
      String superuser = admin.groupPk(AuthentikTestStack.SUPERUSER_GROUP);

      AuthentikAdmin.AdminResult toSuperuser = run(AdminRequest.of(AdminAction.ADD_MEMBER, superuser + ":" + target, "contract test"));
      assertThat(toSuperuser.ok()).isFalse();
      assertThat(toSuperuser.message()).containsIgnoringCase("superuser");

      AuthentikAdmin.AdminResult breakGlass = run(AdminRequest.of(AdminAction.DEACTIVATE_USER, String.valueOf(admin.userPk(AuthentikTestStack.BREAK_GLASS)), "contract test")
         .with("confirmText", AuthentikTestStack.BREAK_GLASS));
      assertThat(breakGlass.ok()).isFalse();
      assertThat(breakGlass.message()).containsIgnoringCase("protected");
      assertThat(admin.get("/core/users/" + admin.userPk(AuthentikTestStack.BREAK_GLASS) + "/").json().getBoolean("is_active")).isTrue();
   }



   /*******************************************************************************
    ** Editing permissions merges only the two qqq.io keys into the group's
    ** CURRENT attributes, so something set in the Authentik UI survives.
    *******************************************************************************/
   @Test
   void editPermissionsKeepsOtherAttributes() throws Exception
   {
      admin.post("/core/groups/", new JSONObject().put("name", "wr-merge").put("attributes", new JSONObject().put("owner-note", "set in the Authentik UI")));
      String pk = admin.groupPk("wr-merge");

      config.withTwoPersonApproval(false);
      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.EDIT_PERMISSIONS, pk, "contract test")
         .with("permissions", "authentik.users.read").with("appAccess", AuthentikTestStack.APP_SLUG));

      assertThat(result.ok()).as(result.message()).isTrue();
      JSONObject attributes = admin.get("/core/groups/" + pk + "/").json().getJSONObject("attributes");
      assertThat(attributes.getString("owner-note")).isEqualTo("set in the Authentik UI");
      assertThat(attributes.getJSONArray("qqq.io/permissions").toList()).containsExactly("authentik.users.read");
      assertThat(attributes.getJSONArray("qqq.io/app-access").toList()).containsExactly(AuthentikTestStack.APP_SLUG);
   }



   /*******************************************************************************
    ** Save a policy on a real Authentik: the canonical compact string lands in
    ** the group's attributes next to the others, the qbit reads it back, and a
    ** grant the operator does not hold is refused.
    *******************************************************************************/
   @Test
   void savePolicy() throws Exception
   {
      admin.post("/core/groups/", new JSONObject().put("name", "wr-policy").put("attributes", new JSONObject().put("owner-note", "set in the Authentik UI")));
      String pk = admin.groupPk("wr-policy");
      String document = "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\",\"delete\"],\"Resource\":[\"wr_page\"]}]}";

      AuthentikAdmin.AdminResult escalation = run(AdminRequest.of(AdminAction.SAVE_POLICY, pk, "contract test").with(AuthentikAdmin.POLICY_DOCUMENT, document));
      assertThat(escalation.ok()).isFalse();
      assertThat(escalation.message()).contains("wr_page.delete");

      String allowed = document.replace(",\"delete\"", "");
      AuthentikAdmin.AdminResult saved = run(AdminRequest.of(AdminAction.SAVE_POLICY, pk, "contract test").with(AuthentikAdmin.POLICY_DOCUMENT, allowed));
      assertThat(saved.ok()).as(saved.message()).isTrue();

      JSONObject attributes = admin.get("/core/groups/" + pk + "/").json().getJSONObject("attributes");
      assertThat(attributes.getString("owner-note")).isEqualTo("set in the Authentik UI");
      assertThat(attributes.getString("qqq.io/policy")).isEqualTo("{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"wr_page\"]}]}");
      assertThat(AuthentikActionUtil.forBackend(config.getApiBackendName()).groupGraph().byPk(pk).policyPermissions()).containsExactly("wr_page.read");

      AuthentikAdmin.AdminResult cleared = run(AdminRequest.of(AdminAction.SAVE_POLICY, pk, "contract test").with(AuthentikAdmin.POLICY_DOCUMENT, ""));
      assertThat(cleared.ok()).as(cleared.message()).isTrue();
      assertThat(admin.get("/core/groups/" + pk + "/").json().getJSONObject("attributes").has("qqq.io/policy")).isFalse();
   }



   /*******************************************************************************
    ** Group create and edit (parents), and the superuser parent refused by the
    ** guard.
    *******************************************************************************/
   @Test
   void createAndEditGroup() throws Exception
   {
      AuthentikAdmin.AdminResult created = run(AdminRequest.of(AdminAction.CREATE_GROUP, "", "contract test").with("name", "wr-child").with("parents", "wr-readers"));
      assertThat(created.ok()).as(created.message()).isTrue();
      JSONObject group = admin.get("/core/groups/" + admin.groupPk("wr-child") + "/").json();
      assertThat(group.getJSONArray("parents").getString(0)).isEqualTo(admin.groupPk("wr-readers"));
      assertThat(group.getBoolean("is_superuser")).isFalse();

      AuthentikAdmin.AdminResult renamed = run(AdminRequest.of(AdminAction.EDIT_GROUP, admin.groupPk("wr-child"), "contract test").with("name", "wr-child-renamed"));
      assertThat(renamed.ok()).as(renamed.message()).isTrue();
      assertThat(admin.groupPk("wr-child-renamed")).isEqualTo(admin.groupPk("wr-child-renamed"));

      AuthentikAdmin.AdminResult superuserParent = run(AdminRequest.of(AdminAction.EDIT_GROUP, admin.groupPk("wr-child-renamed"), "contract test").with("parents", AuthentikTestStack.SUPERUSER_GROUP));
      assertThat(superuserParent.ok()).isFalse();
      assertThat(superuserParent.message()).containsIgnoringCase("superuser");
   }



   /*******************************************************************************
    ** (f) Deactivate: the user is inactive; app passwords go when asked, API
    ** tokens never do. Reactivate restores.
    *******************************************************************************/
   @Test
   void deactivateRevokesOnlyAppPasswords() throws Exception
   {
      admin.post("/core/users/", new JSONObject().put("username", "wr.deact").put("name", "WR Deact").put("email", "wr.deact@example.test").put("type", "internal").put("path", "users"));
      int pk = admin.userPk("wr.deact");
      admin.post("/core/tokens/", new JSONObject().put("identifier", "wr-deact-app").put("intent", "app_password").put("user", pk).put("expiring", false));
      admin.post("/core/tokens/", new JSONObject().put("identifier", "wr-deact-api").put("intent", "api").put("user", pk).put("expiring", false));

      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.DEACTIVATE_USER, String.valueOf(pk), "contract test").with("confirmText", "wr.deact").with("revokeAppPasswords", true));
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(admin.get("/core/users/" + pk + "/").json().getBoolean("is_active")).isFalse();
      assertThat(admin.get("/core/tokens/?identifier=wr-deact-app").results().length()).isZero();
      assertThat(admin.get("/core/tokens/?identifier=wr-deact-api").results().length()).isEqualTo(1);

      assertThat(run(AdminRequest.of(AdminAction.REACTIVATE_USER, String.valueOf(pk), "contract test")).ok()).isTrue();
      assertThat(admin.get("/core/users/" + pk + "/").json().getBoolean("is_active")).isTrue();
   }



   /*******************************************************************************
    ** Edit user and the password-reset email (Authentik's own email; the link is
    ** never shown to the operator).
    *******************************************************************************/
   @Test
   void editUserAndPasswordReset() throws Exception
   {
      int pk = admin.userPk("wr.target");
      AuthentikAdmin.AdminResult edit = run(AdminRequest.of(AdminAction.EDIT_USER, String.valueOf(pk), "contract test").with("name", "WR Target Renamed")
         .with("email", "wr.target@example.test").with("path", "users"));
      assertThat(edit.ok()).as(edit.message()).isTrue();
      assertThat(admin.get("/core/users/" + pk + "/").json().getString("name")).isEqualTo("WR Target Renamed");

      AuthentikAdmin.AdminResult reset = run(AdminRequest.of(AdminAction.SEND_RECOVERY_EMAIL, String.valueOf(pk), "contract test"));
      assertThat(reset.ok()).as(reset.message()).isTrue();
      assertThat(reset.message()).doesNotContain("http");
      AuthentikTestStack.waitFor(Duration.ofSeconds(60), "the reset email in Mailpit", () -> mailpitHas("wr.target@example.test"));
   }



   /*******************************************************************************
    ** Invitations: create (with its email through the enrollment flow's slug
    ** resolved by the qbit) and cancel.
    *******************************************************************************/
   @Test
   void inviteAndCancel() throws Exception
   {
      AuthentikAdmin.AdminResult invite = run(AdminRequest.of(AdminAction.INVITE_USER, "", "contract test").with("email", "wr.invited@example.test"));
      assertThat(invite.ok()).as(invite.message()).isTrue();

      JSONArray invitations = admin.get("/stages/invitation/invitations/").results();
      String    pk          = null;
      for(int i = 0; i < invitations.length(); i++)
      {
         if("wr.invited@example.test".equals(invitations.getJSONObject(i).getJSONObject("fixed_data").optString("email")))
         {
            pk = invitations.getJSONObject(i).getString("pk");
         }
      }
      assertThat(pk).isNotNull();

      assertThat(run(AdminRequest.of(AdminAction.CANCEL_INVITATION, pk, "contract test")).ok()).isTrue();
      assertThat(admin.get("/stages/invitation/invitations/" + pk + "/").status()).isEqualTo(404);
   }



   /*******************************************************************************
    ** Reset MFA: the device list is a bare array (not a paged object) whose type
    ** strings map to the delete endpoints; both device kinds are removed and a
    ** second reset finds nothing to do. (Devices are created in the server
    ** container because the admin API cannot create them for another user.)
    *******************************************************************************/
   @Test
   void resetMfaRemovesEveryDevice() throws Exception
   {
      admin.post("/core/users/", new JSONObject().put("username", "wr.mfa").put("name", "WR MFA").put("email", "wr.mfa@example.test").put("type", "internal").put("path", "users"));
      int pk = admin.userPk("wr.mfa");
      stack.execInServer("ak", "shell", "-c",
         "from authentik.core.models import User; from authentik.stages.authenticator_totp.models import TOTPDevice; "
            + "from authentik.stages.authenticator_static.models import StaticDevice; u = User.objects.get(username='wr.mfa'); "
            + "TOTPDevice.objects.create(user=u, name='wr-totp', confirmed=True); StaticDevice.objects.create(user=u, name='wr-static', confirmed=True)");
      JSONArray before = new JSONArray(admin.get("/authenticators/admin/all/?user=" + pk).body());
      assertThat(before.length()).isEqualTo(2);
      for(int i = 0; i < before.length(); i++)
      {
         assertThat(AuthentikAdmin.devicePath(before.getJSONObject(i))).as(before.getJSONObject(i).toString()).startsWith("/authenticators/admin/");
      }

      AuthentikAdmin.AdminResult untyped = run(AdminRequest.of(AdminAction.RESET_MFA, String.valueOf(pk), "contract test"));
      assertThat(untyped.ok()).isFalse();

      AuthentikAdmin.AdminResult result = run(AdminRequest.of(AdminAction.RESET_MFA, String.valueOf(pk), "contract test").with("confirmText", "wr.mfa"));
      assertThat(result.ok()).as(result.message()).isTrue();
      assertThat(new JSONArray(admin.get("/authenticators/admin/all/?user=" + pk).body()).length()).isZero();
      assertThat(run(AdminRequest.of(AdminAction.RESET_MFA, String.valueOf(pk), "contract test").with("confirmText", "wr.mfa")).noChange()).isTrue();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<String> memberNames(String groupName)
   {
      JSONArray users = admin.get("/core/groups/" + admin.groupPk(groupName) + "/?include_users=true").json().getJSONArray("users_obj");
      java.util.ArrayList<String> rs = new java.util.ArrayList<>();
      for(int i = 0; i < users.length(); i++)
      {
         rs.add(users.getJSONObject(i).getString("username"));
      }
      return (rs);
   }



   /*******************************************************************************
    ** Whether Mailpit holds a message addressed to this address.
    *******************************************************************************/
   private boolean mailpitHas(String address)
   {
      try
      {
         HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(stack.mailpitRoot() + "/api/v1/messages")).GET().build(),
            HttpResponse.BodyHandlers.ofString());
         JSONArray messages = new JSONObject(response.body()).optJSONArray("messages");
         for(int i = 0; messages != null && i < messages.length(); i++)
         {
            JSONArray to = messages.getJSONObject(i).optJSONArray("To");
            for(int j = 0; to != null && j < to.length(); j++)
            {
               if(address.equalsIgnoreCase(to.getJSONObject(j).optString("Address")))
               {
                  return (true);
               }
            }
         }
         return (false);
      }
      catch(Exception e)
      {
         return (false);
      }
   }

}
