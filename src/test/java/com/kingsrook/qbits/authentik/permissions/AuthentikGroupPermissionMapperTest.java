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

package com.kingsrook.qbits.authentik.permissions;


import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.client.FixtureRouter;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Tests for AuthentikGroupPermissionMapper over the recorded group graph.
 *******************************************************************************/
class AuthentikGroupPermissionMapperTest
{
   private QInstance           qInstance;
   private AuthentikQBitConfig config;



   /*******************************************************************************
    **
    *******************************************************************************/
   @BeforeEach
   void beforeEach() throws QException
   {
      FixtureActionUtil.reset();
      config = AuthentikTestSupport.unitConfig().withGroupCacheTtlSeconds(0).withBootstrapOperatorSubjects("opaque-sub-123, 42");
      qInstance = AuthentikTestSupport.produce(config);
      AuthentikTestSupport.useActionUtil(qInstance, config, FixtureActionUtil.class);
      QContext.init(qInstance, new QSession());
      new FixtureRouter().install();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @AfterEach
   void afterEach()
   {
      QContext.clear();
      FixtureActionUtil.reset();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static Map<String, Object> context(String email, Object groups)
   {
      Map<String, Object> context = new HashMap<>();
      context.put(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY, new JSONObject().put("email", email).put("groups", groups));
      return (context);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static Map<String, Object> subjectContext(String sub, String email, boolean verified)
   {
      Map<String, Object> context = new HashMap<>();
      context.put(AuthentikGroupPermissionMapper.CLAIMS_CONTEXT_KEY,
         new JSONObject().put("sub", sub).put("email", email).put("email_verified", verified).put("groups", new JSONArray()));
      return (context);
   }



   /*******************************************************************************
    ** Serve /core/users/?email= with these users (everything else as before).
    *******************************************************************************/
   private static void usersWithEmail(JSONObject... users)
   {
      java.util.function.Function<org.apache.http.client.methods.HttpRequestBase, com.kingsrook.qqq.backend.module.api.actions.QHttpResponse> previous = FixtureActionUtil.handler;
      FixtureActionUtil.handler = request ->
      {
         if(request.getURI().getPath().endsWith("/core/users/") && String.valueOf(request.getURI().getRawQuery()).contains("email="))
         {
            return (FixtureActionUtil.response(200, new JSONObject().put("pagination", new JSONObject().put("count", users.length).put("current", 1).put("total_pages", 1))
               .put("results", new JSONArray(users)).toString()));
         }
         return (previous.apply(request));
      };
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static JSONObject user(int pk, String email)
   {
      return (new JSONObject().put("pk", pk).put("uuid", "uuid-" + pk).put("email", email).put("is_active", true).put("username", "u" + pk));
   }



   /*******************************************************************************
    ** Direct API groups grant their own and inherited permissions to both
    ** people and service accounts, preserving the host's session permissions.
    *******************************************************************************/
   @ParameterizedTest
   @ValueSource(strings = { "internal", "service_account" })
   void automatedSessionsResolveGroups(String type)
   {
      JSONObject user = user(99, " Person@Example.Test ").put("type", type)
         .put("groups_obj", new JSONArray().put(new JSONObject().put("name", "child")));
      usersWithEmail(user, user(100, "other@example.test"));
      FixtureActionUtil.groupGraphBody = new JSONObject()
         .put("pagination", new JSONObject().put("count", 2).put("current", 1).put("total_pages", 1))
         .put("results", new JSONArray()
            .put(new JSONObject().put("pk", "parent-pk").put("name", "parent").put("attributes",
               new JSONObject().put("qqq.io/permissions", new JSONArray().put("authentik.users.read"))))
            .put(new JSONObject().put("pk", "child-pk").put("name", "child").put("parents", new JSONArray().put("parent-pk")).put("attributes",
               new JSONObject().put("qqq.io/permissions", new JSONArray().put("authentik.groups.manage"))))).toString();
      config.withStaticGroupPermissions(Map.of("child", List.of("config.fallback")));
      QSession session = new QSession();
      session.setPermissions(Set.of("already.there"));
      new AuthentikGroupPermissionMapper().withGroupPermissions("child", List.of("mapper.fallback"))
         .customizeAutomatedSessionForUser(qInstance, session, " person@example.test ");
      assertThat(session.getPermissions()).containsExactlyInAnyOrder("already.there", "config.fallback", "mapper.fallback",
         IdentityPermission.USERS_READ.getSessionPermission(), IdentityPermission.GROUPS_MANAGE.getSessionPermission());
      assertThat(FixtureActionUtil.REQUESTS).anySatisfy(request -> assertThat(request.getURI().getRawQuery())
         .contains("email=person%40example.test", "include_groups=true", "include_roles=false"));
   }



   /*******************************************************************************
    ** Unknown, blank, ambiguous and inactive identities never acquire groups,
    ** host permissions or bootstrap permissions from an email alone.
    *******************************************************************************/
   @ParameterizedTest
   @NullAndEmptySource
   @ValueSource(strings = { "unknown", "duplicate", "inactive", "missing-active", "bounded" })
   void automatedSessionsRejectUnprovenUsers(String scenario)
   {
      JSONObject candidate = user(42, "owner@example.test").put("groups_obj",
         new JSONArray().put(new JSONObject().put("name", "phase1-child-of-identity-admins")));
      if("duplicate".equals(scenario))
      {
         usersWithEmail(candidate, user(99, " OWNER@example.test ").put("is_active", false));
      }
      else if("inactive".equals(scenario))
      {
         usersWithEmail(candidate.put("is_active", false));
      }
      else if("missing-active".equals(scenario))
      {
         candidate.remove("is_active");
         usersWithEmail(candidate);
      }
      else if("bounded".equals(scenario))
      {
         JSONObject[] candidates = new JSONObject[10];
         java.util.Arrays.fill(candidates, user(99, "other@example.test"));
         candidates[0] = candidate;
         usersWithEmail(candidates);
      }
      else
      {
         usersWithEmail();
      }
      config.withStaticGroupPermissions(Map.of("phase1-child-of-identity-admins", List.of("config.fallback")))
         .withHostPermissionSource((email, groups) -> Set.of("host.permission"));
      QSession session = new QSession();
      session.setPermissions(Set.of("already.there"));
      new AuthentikGroupPermissionMapper().withGroupPermissions("phase1-child-of-identity-admins", List.of("mapper.fallback"))
         .customizeAutomatedSessionForUser(qInstance, session, scenario == null || scenario.isEmpty() ? scenario : "owner@example.test");
      assertThat(session.getPermissions()).containsExactly("already.there");
   }



   /*******************************************************************************
    ** Failed API lookups and absent runtimes keep only existing permissions.
    *******************************************************************************/
   @Test
   void automatedSessionLookupFailure()
   {
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(403, "{\"detail\":\"Forbidden\"}");
      QSession session = new QSession();
      session.setPermissions(Set.of("already.there"));
      new AuthentikGroupPermissionMapper().customizeAutomatedSessionForUser(qInstance, session, "owner@example.test");
      assertThat(session.getPermissions()).containsExactly("already.there");
      AuthentikGroupPermissionMapper noRuntime = new AuthentikGroupPermissionMapper()
      {
         /*******************************************************************************
          ** Deliberately missing backend.
          *******************************************************************************/
         @Override
         protected String getApiBackendName()
         {
            return ("missingAutomatedBackend");
         }
      };
      noRuntime.customizeAutomatedSessionForUser(qInstance, session, "owner@example.test");
      assertThat(session.getPermissions()).containsExactly("already.there");
   }



   /*******************************************************************************
    ** A readable user's direct group names retain static fallbacks when the
    ** group graph fails; group UUIDs can also be resolved when objects are absent.
    *******************************************************************************/
   @Test
   void automatedGroupFallbacks()
   {
      JSONObject child = new JSONObject(FixtureActionUtil.groupGraphBody).getJSONArray("results").toList().stream()
         .map(value -> new JSONObject((Map<?, ?>) value)).filter(group -> "phase1-child-of-identity-admins".equals(group.optString("name")))
         .findFirst().orElseThrow();
      usersWithEmail(user(99, "person@example.test").put("groups", new JSONArray().put(child.getString("pk"))));
      QSession session = new QSession();
      new AuthentikGroupPermissionMapper().customizeAutomatedSessionForUser(qInstance, session, "person@example.test");
      assertThat(session.getPermissions()).contains(IdentityPermission.USERS_READ.getSessionPermission());

      usersWithEmail(user(99, "person@example.test").put("groups_obj", new JSONArray().put(child)));
      FixtureActionUtil.groupGraphBody = "not json";
      config.withStaticGroupPermissions(Map.of(child.getString("name"), List.of("config.fallback")));
      session = new QSession();
      new AuthentikGroupPermissionMapper().withGroupPermissions(child.getString("name"), List.of("mapper.fallback"))
         .customizeAutomatedSessionForUser(qInstance, session, "person@example.test");
      assertThat(session.getPermissions()).containsExactlyInAnyOrder("config.fallback", "mapper.fallback");
   }



   /*******************************************************************************
    ** The cut-over floor is identical to sign-in and bootstrap recognizes both
    ** API immutable ids without inventing an email_verified claim.
    *******************************************************************************/
   @ParameterizedTest
   @ValueSource(strings = { "42", "uuid-42", "not-this-user" })
   void automatedCutoverFloor(String bootstrapSubject)
   {
      config.withBootstrapOperatorSubjects(bootstrapSubject)
         .withStaticGroupPermissions(Map.of("phase1-child-of-identity-admins", List.of("config.fallback")))
         .withHostPermissionSource((email, groups) ->
         {
            assertThat(email).isEqualTo("owner@example.test");
            assertThat(groups).containsExactly("phase1-child-of-identity-admins");
            return (Set.of("host.permission"));
         });
      AuthentikRuntime.forBackend(config.getApiBackendName()).markMapperInvoked();
      AuthentikRuntime.forBackend(config.getApiBackendName()).setMapperState(
         new AccessComparison.State(AccessComparison.Status.BLOCKED, "Test guard", Instant.now()));
      usersWithEmail(user(42, "owner@example.test").put("groups_obj",
         new JSONArray().put(new JSONObject().put("name", "phase1-child-of-identity-admins"))));
      QSession session = new QSession();
      new AuthentikGroupPermissionMapper().withGroupPermissions("phase1-child-of-identity-admins", List.of("mapper.fallback"))
         .customizeAutomatedSessionForUser(qInstance, session, "owner@example.test");
      if("not-this-user".equals(bootstrapSubject))
      {
         assertThat(session.getPermissions()).containsExactlyInAnyOrder("config.fallback", "mapper.fallback", "host.permission");
      }
      else
      {
         assertThat(session.getPermissions()).contains("config.fallback", "mapper.fallback", "host.permission");
         for(IdentityPermission permission : IdentityPermission.values())
         {
            assertThat(session.getPermissions()).contains(permission.getSessionPermission());
         }
      }
   }



   /*******************************************************************************
    ** Bootstrap operators are keyed on immutable ids, never on an email: a
    ** spoofed email (duplicate, or a different user) is denied, an unverified
    ** email is denied, a matching sub or a verified unique user is granted.
    *******************************************************************************/
   @Test
   void bootstrapIsNotEmailBased()
   {
      AuthentikGroupPermissionMapper mapper = new AuthentikGroupPermissionMapper();
      String                         grant  = IdentityPermission.MEMBERSHIPS_MANAGE.getSessionPermission();

      // the attacker set their email to the owner's: two users share it, sub differs
      usersWithEmail(user(42, "owner@example.test"), user(99, "owner@example.test"));
      QSession duplicate = new QSession();
      mapper.customizeSession(qInstance, duplicate, subjectContext("attacker-sub", "owner@example.test", true));
      assertThat(duplicate.getPermissions()).doesNotContain(grant);

      // only the attacker has that email, but their pk is not a configured subject
      usersWithEmail(user(99, "owner@example.test"));
      QSession other = new QSession();
      mapper.customizeSession(qInstance, other, subjectContext("attacker-sub", "owner@example.test", true));
      assertThat(other.getPermissions()).doesNotContain(grant);

      // the right user, but the token's email is not verified
      usersWithEmail(user(42, "owner@example.test"));
      QSession unverified = new QSession();
      mapper.customizeSession(qInstance, unverified, subjectContext("some-sub", "owner@example.test", false));
      assertThat(unverified.getPermissions()).doesNotContain(grant);

      // an email-looking sub never counts, even if it equals a configured value
      QSession emailSub = new QSession();
      mapper.customizeSession(qInstance, emailSub, subjectContext("owner@example.test", "x@example.test", false));
      assertThat(emailSub.getPermissions()).doesNotContain(grant);

      // verified email, exactly one active user, pk is a configured subject
      QSession good = new QSession();
      mapper.customizeSession(qInstance, good, subjectContext("some-sub", "owner@example.test", true));
      assertThat(good.getPermissions()).contains(grant);

      // the Authentik lookup failing denies
      FixtureActionUtil.handler = request -> FixtureActionUtil.response(500, "boom");
      QSession down = new QSession();
      mapper.customizeSession(qInstance, down, subjectContext("some-sub", "owner@example.test", true));
      assertThat(down.getPermissions()).doesNotContain(grant);
   }



   /*******************************************************************************
    ** Inherited authentik.* through a child group; existing permissions kept.
    *******************************************************************************/
   @Test
   void policyClaimIsAdded()
   {
      String policy = "{\"PolicySpec\":\"qqq-iam\",\"PolicyVersion\":\"1.0.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"read\"],\"Resource\":[\"cms_page\"]}]}";
      Map<String, Object> ctx = context("someone@example.test", new JSONArray());
      ctx.put("idToken", new JSONObject().put("qqq_policy", policy));
      QSession session = new QSession();
      new AuthentikGroupPermissionMapper().customizeSession(qInstance, session, ctx);
      assertThat(session.getPermissions()).contains("cms_page.read");

      ctx.put("idToken", new JSONObject().put("qqq_policy", policy.replace("Allow", "Deny")));
      QSession denied = new QSession();
      new AuthentikGroupPermissionMapper().customizeSession(qInstance, denied, ctx);
      assertThat(denied.getPermissions()).doesNotContain("cms_page.read");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void groupsBecomePermissions()
   {
      QSession session = new QSession();
      session.setPermissions(Set.of("already.there"));
      new AuthentikGroupPermissionMapper().customizeSession(qInstance, session, context("phase1@example.test", new JSONArray().put("phase1-child-of-identity-admins").put("no-such-group")));
      for(IdentityPermission permission : IdentityPermission.values())
      {
         assertThat(session.getPermissions()).contains(permission.getSessionPermission());
      }
      assertThat(session.getPermissions()).contains("already.there");
   }



   /*******************************************************************************
    ** Static fallbacks, bootstrap operators (case-insensitive), single-string
    ** groups claim; no claims means no change.
    *******************************************************************************/
   @Test
   void fallbacksAndBootstrap()
   {
      AuthentikGroupPermissionMapper mapper = new AuthentikGroupPermissionMapper().withGroupPermissions("kof22-admins", List.of("adminEsb.hasAccess"));

      QSession admin = new QSession();
      mapper.customizeSession(qInstance, admin, context("someone@example.test", "kof22-admins"));
      assertThat(admin.getPermissions()).contains("adminEsb.hasAccess").doesNotContain(IdentityPermission.USERS_READ.getSessionPermission());

      QSession boot = new QSession();
      mapper.customizeSession(qInstance, boot, subjectContext("opaque-sub-123", "boot@example.test", false));
      assertThat(boot.getPermissions()).contains(IdentityPermission.MEMBERSHIPS_MANAGE.getSessionPermission());

      QSession none = new QSession();
      mapper.customizeSession(qInstance, none, Map.of());
      mapper.customizeSession(qInstance, none, null);
      assertThat(none.getPermissions()).isNullOrEmpty();
   }



   /*******************************************************************************
    ** Authentik unreachable: only the static fallbacks, never everything.
    *******************************************************************************/
   @Test
   void authentikDownGrantsOnlyFallbacks()
   {
      FixtureActionUtil.groupGraphBody = "not json";
      AuthentikGroupPermissionMapper mapper = new AuthentikGroupPermissionMapper().withGroupPermissions("phase1-child-of-identity-admins", List.of("cms.publish"));
      QSession                       session = new QSession();
      mapper.customizeSession(qInstance, session, context("phase1@example.test", new JSONArray().put("phase1-child-of-identity-admins")));
      assertThat(session.getPermissions()).containsExactly("cms.publish");

      AuthentikGroupPermissionMapper wrongBackend = new AuthentikGroupPermissionMapper()
      {
         @Override
         protected String getApiBackendName()
         {
            return ("nope");
         }
      };
      assertThat(wrongBackend.resolve(qInstance, List.of("phase1-child-of-identity-admins"), "s", "x@example.test", false)).isEmpty();
   }

}
