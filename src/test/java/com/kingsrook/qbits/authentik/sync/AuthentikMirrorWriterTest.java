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

package com.kingsrook.qbits.authentik.sync;

import java.time.Instant;
import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.audits.AuditsMetaDataProvider;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Standard QQQ actions retain mirror identities and RECORD audit. This memory
 ** test verifies action semantics; SQL rollback is a separate integration gate.
 *******************************************************************************/
class AuthentikMirrorWriterTest
{
   private AuthentikQBitConfig config;
   private QInstance instance;
   private AuthentikMirrorWriter writer;

   /*******************************************************************************
    ** Production mirror metadata and standard audit metadata on one backend.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws Exception
   {
      MemoryRecordStore.getInstance().reset();
      config = AuthentikTestSupport.unitConfig();
      instance = AuthentikTestSupport.produce(config);
      config.withLocalBackendName("mirrorTest");
      instance.addBackend(new QBackendMetaData().withName("mirrorTest").withBackendType(MemoryBackendModule.class));
      for(var table : AuthentikSyncTables.all(config))
      {
         instance.addTable(table);
      }
      new AuditsMetaDataProvider().withDefineRecordScreens(false).defineAll(instance, "mirrorTest", table -> {});
      QContext.init(instance, new QSystemUserSession(instance));
      writer = new AuthentikMirrorWriter(config);
   }

   /*******************************************************************************
    ** Release only the test JVM's memory context.
    *******************************************************************************/
   @AfterEach
   void tearDown()
   {
      QContext.clear();
      MemoryRecordStore.getInstance().reset();
   }

   /*******************************************************************************
    ** One complete synthetic directory, with a controllable username.
    *******************************************************************************/
   private AuthentikMirrorSnapshot snapshot(String username)
   {
      Instant refreshed = Instant.parse("2026-11-04T12:00:00Z");
      return (new AuthentikMirrorSnapshot(
         List.of(new QRecord().withValue("pk", 1).withValue("username", username).withValue("refreshedAt", refreshed)),
         List.of(new QRecord().withValue("pk", "g1").withValue("name", "Viewer").withValue("refreshedAt", refreshed)),
         List.of(new QRecord().withValue("userPk", 1).withValue("groupPk", "g1").withValue("groupName", "Viewer").withValue("refreshedAt", refreshed)), refreshed));
   }

   /*******************************************************************************
    ** Observe stored rows using QQQ, including its standard audit table.
    *******************************************************************************/
   private List<QRecord> rows(String table) throws Exception
   {
      return (new QueryAction().execute(new QueryInput().withTableName(table)).getRecords());
   }

   /*******************************************************************************
    ** Replaying identical data is a no-op; rename keeps IDs and generates an
    ** edit audit; a full empty directory removes and audits obsolete rows.
    *******************************************************************************/
   @Test
   void insertsUpdatesAndDeletesThroughAuditedActions() throws Exception
   {
      var transaction = new QBackendTransaction();
      writer.fullRefresh(snapshot("sam"), transaction);
      assertThat(rows("audit")).hasSize(3);
      var originalId = rows("authentik_user_mirror").get(0).getValue("id");
      writer.fullRefresh(snapshot("sam"), transaction);
      assertThat(rows("audit")).hasSize(3);
      writer.fullRefresh(snapshot("renamed"), transaction);
      assertThat(rows("authentik_user_mirror").get(0).getValue("id")).isEqualTo(originalId);
      assertThat(rows("authentik_user_mirror").get(0).getValue("username")).isEqualTo("renamed");
      assertThat(rows("audit")).hasSize(5);
      writer.fullRefresh(new AuthentikMirrorSnapshot(List.of(), List.of(), List.of(), Instant.now()), transaction);
      assertThat(rows("authentik_user_mirror")).isEmpty();
      assertThat(rows("authentik_group_mirror")).isEmpty();
      assertThat(rows("authentik_membership_mirror")).isEmpty();
      assertThat(rows("audit")).hasSize(8);
   }

   /*******************************************************************************
    ** Interactive operators cannot bypass the guarded directory workflow by
    ** calling the internal mirror writer directly.
    *******************************************************************************/
   @Test
   void requiresInternalSessionAndExplicitTransaction()
   {
      assertThatThrownBy(() -> writer.fullRefresh(snapshot("sam"), null)).isInstanceOf(NullPointerException.class);
      AuthentikTestSupport.loginWith(instance, IdentityPermission.ADMIN, IdentityPermission.USERS_READ);
      assertThatThrownBy(() -> writer.fullRefresh(snapshot("sam"), new QBackendTransaction())).isInstanceOf(QPermissionDeniedException.class);
   }
}
