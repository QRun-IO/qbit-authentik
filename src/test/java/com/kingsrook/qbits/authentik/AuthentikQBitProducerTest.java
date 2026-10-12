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

package com.kingsrook.qbits.authentik;


import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.module.api.model.AuthorizationType;
import com.kingsrook.qqq.backend.module.api.model.metadata.APIBackendMetaData;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Tests for AuthentikQBitProducer.
 *******************************************************************************/
class AuthentikQBitProducerTest
{

   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void producesBackendTablesAndApp() throws QException
   {
      AuthentikQBitConfig config    = AuthentikTestSupport.unitConfig();
      QInstance           qInstance = AuthentikTestSupport.produce(config);

      APIBackendMetaData backend = (APIBackendMetaData) qInstance.getBackend("authentikApi");
      assertThat(backend.getBaseUrl()).isEqualTo("https://authentik.example.test/api/v3");
      assertThat(backend.getAuthorizationType()).isEqualTo(AuthorizationType.CUSTOM);
      assertThat(backend.getApiKey()).isNull();
      assertThat(backend.getActionUtil().getName()).isEqualTo(AuthentikActionUtil.class.getName());

      QTableMetaData users = qInstance.getTable("authentik_user");
      assertThat(users.getBackendName()).isEqualTo("authentikApi");
      assertThat(users.getPrimaryKeyField()).isEqualTo("pk");
      assertThat(users.getPermissionRules().getPermissionBaseName()).isEqualTo("authentik.users.read");
      assertThat(users.isCapabilityEnabled(qInstance.getBackend("authentikApi"), Capability.TABLE_QUERY)).isTrue();
      assertThat(users.isCapabilityEnabled(qInstance.getBackend("authentikApi"), Capability.TABLE_INSERT)).isFalse();
      assertThat(users.isCapabilityEnabled(qInstance.getBackend("authentikApi"), Capability.TABLE_DELETE)).isFalse();
      assertThat(users.getField("uuid").getIsHidden()).isTrue();
      assertThat(qInstance.getTable("authentik_group")).isNotNull();

      QAppMetaData app = qInstance.getApp("authentikAdmin");
      assertThat(app.getLabel()).isEqualTo("Identity");
      assertThat(app.getChildren()).extracting(c -> c.getName()).containsExactly("authentik_user", "authentik_group", "authentik_group_member", "authentik_session", "authentik_event");
      assertThat(app.getWidgets()).containsExactly("authentikDriftReport");
      assertThat(qInstance.getTable("authentik_session").getPermissionRules().getPermissionBaseName()).isEqualTo("authentik.audit.read");
      assertThat(qInstance.getWidget("authentikDriftReport").getPermissionRules().getPermissionBaseName()).isEqualTo("authentik.admin");

      assertThat(PermissionsHelper.getAllAvailablePermissionNames(qInstance)).contains(IdentityPermission.USERS_READ.getSessionPermission());
      assertThat(qInstance.getQBits()).containsKey("com.kingsrook.qbits:authentik");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void namespaceBecomesPrefix() throws QException
   {
      AuthentikQBitConfig config    = AuthentikTestSupport.unitConfig().withTableNamePrefix(null);
      QInstance           qInstance = new QInstance();
      new AuthentikQBitProducer().withQBitConfig(config).withNamespace("idp").produce(qInstance);
      assertThat(qInstance.getTable("idp_user")).isNotNull();
      assertThat(qInstance.getBackend("idpApi")).isNotNull();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void invalidConfigFailsWithAllErrors()
   {
      assertThatThrownBy(() -> new AuthentikQBitProducer().produce(new QInstance())).hasMessageContaining("no config");
      assertThatThrownBy(() -> new AuthentikQBitProducer().withQBitConfig(new AuthentikQBitConfig()).produce(new QInstance()))
         .hasMessageContaining("baseUrl").hasMessageContaining("apiToken").hasMessageContaining("appKey");
      assertThat(new AuthentikQBitProducer().isEnabled()).isFalse();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void identityAndVersion()
   {
      AuthentikQBitProducer producer = new AuthentikQBitProducer();
      producer.setQBitConfig(AuthentikTestSupport.unitConfig());
      assertThat(producer.getQBitMetaData().getArtifactId()).isEqualTo("authentik");
      assertThat(AuthentikQBitProducer.getVersion()).isNotBlank();
      assertThat(IdentityPermission.fromName("authentik.audit.read")).contains(IdentityPermission.AUDIT_READ);
      assertThat(IdentityPermission.fromName("authentik.audit.read.hasAccess")).contains(IdentityPermission.AUDIT_READ);
      assertThat(IdentityPermission.fromName("nope")).isEmpty();
      assertThat(IdentityPermission.fromName(null)).isEmpty();
   }

}
