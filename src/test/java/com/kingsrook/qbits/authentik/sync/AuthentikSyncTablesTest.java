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

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Locale;
import java.util.UUID;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Execute the additive DDL and verify metadata and database constraints agree.
 ** H2's PostgreSQL mode is a fast schema check, not the PostgreSQL release gate.
 *******************************************************************************/
class AuthentikSyncTablesTest
{
   /*******************************************************************************
    ** Every field maps to an actual SQL column, and generic writes stay off.
    *******************************************************************************/
   @Test
   void migrationMatchesReadOnlyMetadata() throws Exception
   {
      var config = AuthentikTestSupport.unitConfig().withLocalBackendName("syncLocal");
      try(var connection = DriverManager.getConnection("jdbc:h2:mem:sync_" + UUID.randomUUID() + ";MODE=PostgreSQL"))
      {
         try(var statement = connection.createStatement())
         {
            statement.execute(Files.readString(Path.of("docs/schema-sync.sql")));
         }
         var backend = new QBackendMetaData().withName("syncLocal").withBackendType(MemoryBackendModule.class);
         for(var table : AuthentikSyncTables.all(config))
         {
            var columns = new HashSet<String>();
            try(var result = connection.getMetaData().getColumns(null, null, table.getName().toUpperCase(Locale.ROOT), null))
            {
               while(result.next())
               {
                  columns.add(result.getString("COLUMN_NAME").toLowerCase(Locale.ROOT));
               }
            }
            assertThat(columns).containsExactlyInAnyOrderElementsOf(table.getFields().values().stream().map(f -> f.getBackendName()).toList());
            for(Capability capability : new Capability[] { Capability.TABLE_INSERT, Capability.TABLE_UPDATE, Capability.TABLE_DELETE, Capability.TABLE_EXPORT })
            {
               assertThat(table.isCapabilityEnabled(backend, capability)).isFalse();
            }
            assertThat(table.getFields().values()).allMatch(f -> Boolean.FALSE.equals(f.getIsEditable()));
         }
         try(var statement = connection.createStatement())
         {
            String event = "INSERT INTO authentik_webhook_inbox(event_pk,payload_json,status,received_at) VALUES ('event-1','{}','PENDING',CURRENT_TIMESTAMP)";
            statement.executeUpdate(event);
            assertThatThrownBy(() -> statement.executeUpdate(event)).isInstanceOf(SQLException.class);
            statement.executeUpdate("INSERT INTO authentik_membership_mirror(user_pk,group_pk,refreshed_at) VALUES (1,'g1',CURRENT_TIMESTAMP)");
            assertThatThrownBy(() -> statement.executeUpdate("INSERT INTO authentik_membership_mirror(user_pk,group_pk,refreshed_at) VALUES (1,'g1',CURRENT_TIMESTAMP)"))
               .isInstanceOf(SQLException.class);
            statement.executeUpdate("INSERT INTO authentik_user_mirror(pk,username,refreshed_at) VALUES (1,'one',CURRENT_TIMESTAMP),(2,'two',CURRENT_TIMESTAMP)");
            statement.executeUpdate("UPDATE authentik_user_mirror SET email='one@example.test' WHERE pk=1");
            assertThatThrownBy(() -> statement.executeUpdate("UPDATE authentik_user_mirror SET email='one@example.test' WHERE pk=2"))
               .isInstanceOf(SQLException.class);
         }
      }
   }
}
