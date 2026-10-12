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


import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikQBitProducer;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QUser;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore;


/*******************************************************************************
 ** A QInstance with the qbit (all write features, audit on a memory backend),
 ** two host tables whose permissions operators can grant, and a FakeAuthentik
 ** pre-loaded with a small realistic directory:
 **
 ** <pre>
 **   identity-admins        authentik.*               app kof22-website-prod
 **   kof-website-publishers cms.publish.hasAccess     app kof22-website-prod
 **   kof-website-analysts   kof22.analytics.hasAccess
 **   authentik Admins       (superuser group)
 **
 **   operator (1)  identity-admins, kof-website-publishers   operator@example.test
 **   second (2)    identity-admins
 **   sam (3)       -
 **   breakglass (4) authentik Admins   (superuser, protected)
 **   qqq-kof22-admin-idadmin (5)  the qbit's service account
 **   svc-publisher (6) service account
 **   dormant (7)   inactive
 ** </pre>
 *******************************************************************************/
public final class AdminTestSupport
{
   public static final String LOCAL = "memory";

   public QInstance           qInstance;
   public AuthentikQBitConfig config;
   public FakeAuthentik       authentik;



   /*******************************************************************************
    ** Build everything and log in as the operator with every authentik.* permission.
    *******************************************************************************/
   public static AdminTestSupport create() throws QException
   {
      return (create(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP,
         AuthentikFeature.CREDENTIALS, AuthentikFeature.SESSIONS)));
   }



   /*******************************************************************************
    ** Build with chosen features.
    *******************************************************************************/
   public static AdminTestSupport create(Set<AuthentikFeature> features) throws QException
   {
      AdminTestSupport support = new AdminTestSupport();
      MemoryRecordStore.getInstance().reset();

      support.authentik = new FakeAuthentik();
      support.authentik
         .group("identity-admins", false, List.of("authentik.*"), List.of("kof22-website-prod"))
         .group("kof-website-publishers", false, List.of("cms.publish.hasAccess"), List.of("kof22-website-prod"))
         .group("kof-website-analysts", false, List.of("kof22.analytics.hasAccess"), List.of())
         .group("authentik Admins", true, List.of(), List.of())
         .user(1, "operator", AuthentikTestSupport.OPERATOR, "internal", true, "identity-admins", "kof-website-publishers")
         .user(2, "second", "second@example.test", "internal", true, "identity-admins")
         .user(3, "sam", "sam@example.test", "internal", true)
         .user(4, "breakglass", "breakglass@example.test", "internal", true, "authentik Admins")
         .user(5, "qqq-kof22-admin-idadmin", "", "service_account", true)
         .user(6, "svc-publisher", "", "service_account", true)
         .user(7, "dormant", "dormant@example.test", "internal", false)
         .install();

      support.config = AuthentikTestSupport.unitConfig()
         .withFeatures(features)
         .withLocalBackendName(LOCAL)
         .withRecoveryEmailStage("kof22-recovery-email")
         .withInvitationFlow("kof22-enrollment")
         .withBulkPacingMillis(0);

      QInstance instance = new QInstance();
      instance.withInstanceDefaultAuthentication(new QAuthenticationMetaData().withName("mock").withType(QAuthenticationType.MOCK));
      instance.addBackend(new QBackendMetaData().withName(LOCAL).withBackendType(MemoryBackendModule.class));
      for(String[] table : new String[][] { { "post", "cms.publish" }, { "analytics", "kof22.analytics" } })
      {
         instance.addTable(new QTableMetaData().withName(table[0]).withBackendName(LOCAL).withPrimaryKeyField("id")
            .withField(new QFieldMetaData("id", QFieldType.INTEGER))
            .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION).withPermissionBaseName(table[1])));
      }
      new AuthentikQBitProducer().withQBitConfig(support.config).produce(instance);
      AuthentikTestSupport.useActionUtil(instance, support.config, FixtureActionUtil.class);
      support.qInstance = instance;

      support.loginAs(AuthentikTestSupport.OPERATOR, IdentityPermission.values());
      return (support);
   }



   /*******************************************************************************
    ** Log in as a user with the given authentik.* permissions.
    *******************************************************************************/
   public QSession loginAs(String email, IdentityPermission... permissions)
   {
      Set<String> names = new HashSet<>();
      for(IdentityPermission permission : permissions)
      {
         names.add(permission.getSessionPermission());
      }
      QSession session = new QSession();
      session.setUser(new QUser().withIdReference(email).withFullName(email));
      session.setPermissions(names);
      QContext.init(qInstance, session);
      return (session);
   }



   /*******************************************************************************
    ** An admin service for the qbit's backend.
    *******************************************************************************/
   public AuthentikAdmin admin() throws QException
   {
      return (new AuthentikAdmin(AuthentikActionUtil.forBackend(config.getApiBackendName())));
   }



   /*******************************************************************************
    ** The writes sent to Authentik so far, as "METHOD path".
    *******************************************************************************/
   public List<String> writes()
   {
      return (authentik.writes);
   }



   /*******************************************************************************
    ** The writes other than the audit event.
    *******************************************************************************/
   public List<String> changes()
   {
      return (authentik.writes.stream().filter(w -> !w.contains("/events/events/")).toList());
   }

}
