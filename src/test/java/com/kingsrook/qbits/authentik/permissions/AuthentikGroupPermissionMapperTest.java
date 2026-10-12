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


import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
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
      config = AuthentikTestSupport.unitConfig().withGroupCacheTtlSeconds(0).withBootstrapOperators("Boot@Example.Test");
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
    ** Inherited authentik.* through a child group; existing permissions kept.
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
      mapper.customizeSession(qInstance, boot, context("boot@example.test", new JSONArray()));
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
      assertThat(wrongBackend.resolve(qInstance, List.of("phase1-child-of-identity-admins"), "x@example.test")).isEmpty();
   }

}
