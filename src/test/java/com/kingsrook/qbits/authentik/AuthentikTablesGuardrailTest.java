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


import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import com.kingsrook.qbits.authentik.admin.AdminTestSupport;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.metadata.AuthentikHelp;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.help.QHelpContent;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Guardrail (owner requirement 2026-10-14: "all tables should be populated and
 ** the qbit should be fully using them"). For every authentik_* table:
 ** - it is used at runtime: an API-backed table through its backend (every row
 **   is read live from Authentik by AuthentikActionUtil, so it has no rows of
 **   its own); a local table by runtime code that reads or writes it, not only
 **   its metadata or the home screen;
 ** - it has nothing to seed (setup comes from config; every table is live data
 **   or a log), and says why in STARTS_EMPTY;
 ** - it has bundle help that says what it is for and how its rows get created
 **   (shown on the table screen and when it is empty).
 ** A new table fails this test until it is wired, explained and documented.
 *******************************************************************************/
class AuthentikTablesGuardrailTest
{
   private static final Path MAIN = Path.of("src", "main", "java", "com", "kingsrook", "qbits", "authentik");

   /*******************************************************************************
    ** The API-backed tables: rows are read live from Authentik, never stored.
    *******************************************************************************/
   static final List<String> API_TABLES = List.of("authentik_user", "authentik_group", "authentik_group_member", "authentik_session", "authentik_event",
      "authentik_application", "authentik_policy_binding", "authentik_blueprint", "authentik_role", "authentik_token", "authentik_invitation");

   /*******************************************************************************
    ** The qbit's own tables, with the constant runtime code uses to reach them.
    *******************************************************************************/
   static final Map<String, String> LOCAL_TABLES = Map.of(
      "authentik_admin_action", "AuthentikLocalTables.ADMIN_ACTION",
      "authentik_approval_request", "AuthentikLocalTables.APPROVAL_REQUEST",
      "authentik_policy", "AuthentikLocalTables.POLICY",
      "authentik_token_scope", "AuthentikLocalTables.TOKEN_SCOPE");

   /*******************************************************************************
    ** Why no table is seeded.
    *******************************************************************************/
   static final Map<String, String> STARTS_EMPTY = Map.ofEntries(
      Map.entry("authentik_user", "live Authentik data, no rows of its own; setup is the qbit config"),
      Map.entry("authentik_group", "live Authentik data, no rows of its own"),
      Map.entry("authentik_group_member", "virtual: computed live from group member lists"),
      Map.entry("authentik_session", "live Authentik data: signed-in sessions"),
      Map.entry("authentik_event", "live Authentik data: its event log"),
      Map.entry("authentik_application", "live Authentik data, defined by blueprints in Authentik"),
      Map.entry("authentik_policy_binding", "live Authentik data, defined on applications in Authentik"),
      Map.entry("authentik_blueprint", "live Authentik data: blueprint status"),
      Map.entry("authentik_role", "live Authentik data: RBAC roles"),
      Map.entry("authentik_token", "live Authentik data: token metadata, never the key"),
      Map.entry("authentik_invitation", "live Authentik data: pending invitations"),
      Map.entry("authentik_admin_action", "log: one row per action a person runs"),
      Map.entry("authentik_approval_request", "log: a second-person approval is requested"),
      Map.entry("authentik_policy", "history: written when a person saves a group policy"),
      Map.entry("authentik_token_scope", "history: written when a scoped token is created"));



   /*******************************************************************************
    ** Every produced table is accounted for here, and the other way round.
    *******************************************************************************/
   @Test
   void everyTableIsKnown() throws Exception
   {
      QInstance    instance = support().qInstance;
      List<String> produced = instance.getTables().values().stream().map(QTableMetaData::getName).filter(n -> n.startsWith("authentik_")).sorted().toList();
      assertThat(produced).containsExactlyInAnyOrderElementsOf(STARTS_EMPTY.keySet());
      assertThat(STARTS_EMPTY.keySet()).containsAll(API_TABLES).containsAll(LOCAL_TABLES.keySet());
      assertThat(STARTS_EMPTY).hasSize(API_TABLES.size() + LOCAL_TABLES.size());
   }



   /*******************************************************************************
    ** Every table is used at runtime: an API table through its backend, a local
    ** table by non-metadata code.
    *******************************************************************************/
   @Test
   void everyTableIsUsedAtRuntime() throws Exception
   {
      AdminTestSupport support = support();
      for(String table : API_TABLES)
      {
         QTableMetaData metaData = support.qInstance.getTable(table);
         assertThat(metaData).as(table).isNotNull();
         assertThat(metaData.getBackendName()).as(table + " is served by the Authentik API backend").isEqualTo(support.config.getApiBackendName());
         assertThat(AuthentikTables.get(specName(table))).as(table + " has an API spec").isNotNull();
      }

      List<String> runtimeSource;
      try(Stream<Path> files = Files.walk(MAIN))
      {
         runtimeSource = files.filter(p -> p.toString().endsWith(".java"))
            .filter(p -> !p.startsWith(MAIN.resolve("metadata")) && !p.startsWith(MAIN.resolve("app")))
            .filter(p -> !p.endsWith("AuthentikLocalTables.java"))
            .map(AuthentikTablesGuardrailTest::read).toList();
      }
      for(Map.Entry<String, String> local : LOCAL_TABLES.entrySet())
      {
         assertThat(runtimeSource.stream().anyMatch(source -> source.contains(local.getValue())))
            .as(local.getKey() + " (" + local.getValue() + ") must be read or written by runtime code, not only declared").isTrue();
         assertThat(support.qInstance.getTable(local.getKey()).getBackendName()).isEqualTo(AdminTestSupport.LOCAL);
      }
   }



   /*******************************************************************************
    ** Every table and the app have bundle help that says how rows get created,
    ** and what an empty list means; the API-backed ones say rows are live.
    *******************************************************************************/
   @Test
   void everyTableHasEmptyStateHelp() throws Exception
   {
      QInstance instance = support().qInstance;
      assertThat(AuthentikHelp.entries()).allSatisfy((key, entry) -> assertThat(entry.path("summary").asText().length()).as(key).isLessThanOrEqualTo(120));
      for(String table : STARTS_EMPTY.keySet())
      {
         List<QHelpContent> help = instance.getTable(table).getHelpContent() == null ? null : instance.getTable(table).getHelpContent().get(AuthentikHelp.SLOT);
         assertThat(help).as(table + " table help").isNotEmpty();
         String text = help.get(0).getContent();
         assertThat(text).as(table + " help says how rows get created").contains("How rows get created");
         assertThat(text).as(table + " help says what empty means").containsAnyOf("An empty list means", "An empty table means");
         if(API_TABLES.contains(table))
         {
            assertThat(text).as(table + " help says rows are live").containsAnyOf("live", "Live");
         }
      }
      assertThat(instance.getApp("authentikAdmin").getHelpContent()).containsKey(AuthentikHelp.SLOT);

   }



   /*******************************************************************************
    ** A host with its own table prefix gets the same help on the renamed tables,
    ** and a host's own help is never replaced.
    *******************************************************************************/
   @Test
   void helpFollowsTheHostPrefixAndKeepsHostHelp() throws Exception
   {
      AuthentikQBitConfig config = AuthentikTestSupport.unitConfig().withTableNamePrefix("idp");
      QInstance           idp    = AuthentikTestSupport.produce(config);
      assertThat(idp.getTable("idp_user").getHelpContent().get(AuthentikHelp.SLOT).get(0).getContent()).contains("How rows get created");
      assertThat(idp.getApp("idpAdmin").getHelpContent()).containsKey(AuthentikHelp.SLOT);

      QInstance hosted = AuthentikTestSupport.produce(AuthentikTestSupport.unitConfig());
      hosted.getTable("authentik_user").getHelpContent().put(AuthentikHelp.SLOT, List.of(new QHelpContent().withContentAsMarkdown("host text")));
      AuthentikHelp.apply(hosted, AuthentikTestSupport.unitConfig());
      assertThat(hosted.getTable("authentik_user").getHelpContent().get(AuthentikHelp.SLOT)).hasSize(1);
      assertThat(hosted.getTable("authentik_user").getHelpContent().get(AuthentikHelp.SLOT).get(0).getContent()).isEqualTo("host text");
   }



   /*******************************************************************************
    ** Every feature on, local tables on a memory backend, an invitation flow set.
    *******************************************************************************/
   private static AdminTestSupport support() throws Exception
   {
      return (AdminTestSupport.create(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.TOKENS, AuthentikFeature.POLICIES, AuthentikFeature.USERS,
         AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP, AuthentikFeature.CREDENTIALS, AuthentikFeature.SESSIONS)));
   }



   /*******************************************************************************
    ** "authentik_group_member" -> "groupMember" (the spec's own name).
    *******************************************************************************/
   private static String specName(String table)
   {
      String name = table.substring("authentik_".length());
      for(String spec : AuthentikTables.all().keySet())
      {
         if(AuthentikQBitConfig.toSnakeCase(spec).equals(name))
         {
            return (spec);
         }
      }
      return (name);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String read(Path path)
   {
      try
      {
         return (Files.readString(path, StandardCharsets.UTF_8));
      }
      catch(Exception e)
      {
         throw (new IllegalStateException(e));
      }
   }

}
