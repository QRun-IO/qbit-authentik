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

package com.kingsrook.qbits.authentik.app;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qbits.authentik.admin.AdminTestSupport;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.RawHTML;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** The Identity app: nav with only the main tables, child lists on the parents,
 ** the local tables, the single home, and the guarantee that nothing but the
 ** admin service changes Authentik.
 *******************************************************************************/
class AuthentikAppTest
{
   /*******************************************************************************
    ** The nav lists only the main tables; memberships, sessions, tokens, events,
    ** bindings, roles and blueprints are reached from their parents.
    *******************************************************************************/
   @Test
   void navHasOnlyMainTablesAndParentsHaveChildLists() throws QException
   {
      AdminTestSupport t = AdminTestSupport.create();
      QAppMetaData     app = t.qInstance.getApp("authentikAdmin");

      assertThat(app.getChildren()).extracting(c -> c.getName())
         .containsExactly("authentik_user", "authentik_invitation", "authentik_group", "authentik_application", "authentik_approval_request", "authentik_admin_action");
      assertThat(app.getSections()).extracting(s -> s.getLabel()).containsExactly("People", "Access", "Activity");
      assertThat(app.getWidgets()).containsExactly("authentikHome", "authentikAccessTokens", "authentikDriftReport");

      for(String subTable : List.of("authentik_group_member", "authentik_session", "authentik_token", "authentik_event", "authentik_policy_binding", "authentik_role", "authentik_blueprint"))
      {
         assertThat(t.qInstance.getTable(subTable)).as(subTable).isNotNull();
         assertThat(app.getChildren()).extracting(c -> c.getName()).doesNotContain(subTable);
      }

      QTableMetaData user = t.qInstance.getTable("authentik_user");
      assertThat(user.getSections()).extracting(s -> s.getName()).contains("identity", "access", "memberships", "sessions", "tokens", "events");
      assertThat(t.qInstance.getTable("authentik_group").getSections()).extracting(s -> s.getName()).contains("details", "permissions", "members");
      assertThat(t.qInstance.getJoin("authentik_user_sessions").getRightTable()).isEqualTo("authentik_session");
      assertThat(t.qInstance.getWidget("authentik_user_memberships")).isNotNull();
   }



   /*******************************************************************************
    ** The local tables are standard visible tables on the host's backend, written
    ** only by the qbit; with no local backend there are none (read-only app).
    *******************************************************************************/
   @Test
   void localTables() throws QException
   {
      AdminTestSupport t = AdminTestSupport.create();
      for(String name : List.of("authentik_admin_action", "authentik_approval_request"))
      {
         QTableMetaData table = t.qInstance.getTable(name);
         assertThat(table.getBackendName()).isEqualTo(AdminTestSupport.LOCAL);
         assertThat(table.isCapabilityEnabled(t.qInstance.getBackend(AdminTestSupport.LOCAL), Capability.TABLE_INSERT)).isFalse();
         assertThat(table.isCapabilityEnabled(t.qInstance.getBackend(AdminTestSupport.LOCAL), Capability.TABLE_UPDATE)).isFalse();
         assertThat(table.isCapabilityEnabled(t.qInstance.getBackend(AdminTestSupport.LOCAL), Capability.TABLE_DELETE)).isFalse();
         assertThat(table.isCapabilityEnabled(t.qInstance.getBackend(AdminTestSupport.LOCAL), Capability.TABLE_QUERY)).isTrue();
      }
      assertThat(t.qInstance.getTable("authentik_admin_action").getPermissionRules().getPermissionBaseName()).isEqualTo("authentik.audit.read");
      assertThat(t.qInstance.getTable("authentik_approval_request").getPermissionRules().getPermissionBaseName()).isEqualTo("authentik.approve");
      assertThat(t.qInstance.getPossibleValueSource(AuthentikLocalTables.PVS_ACTION_STATUS)).isNotNull();

      QInstance readOnly = AuthentikTestSupport.produce(AuthentikTestSupport.unitConfig());
      assertThat(readOnly.getTable("authentik_admin_action")).isNull();
      assertThat(readOnly.getProcesses()).isEmpty();
      assertThat(readOnly.getApp("authentikAdmin").getChildren()).extracting(c -> c.getName()).containsExactly("authentik_user", "authentik_group", "authentik_application");
   }



   /*******************************************************************************
    ** Read-only tables carry no key field for tokens and no insert capability.
    *******************************************************************************/
   @Test
   void tokenTableNeverHasAKey() throws QException
   {
      AdminTestSupport t = AdminTestSupport.create();
      QTableMetaData   token = t.qInstance.getTable("authentik_token");
      assertThat(token.getFields().keySet()).doesNotContain("key", "token", "secret");
      assertThat(token.getPermissionRules().getPermissionBaseName()).isEqualTo("authentik.audit.read");
   }



   /*******************************************************************************
    ** The home renders every card, escapes values, and shows honest states.
    *******************************************************************************/
   @Test
   void homeRenders() throws Exception
   {
      AdminTestSupport t = AdminTestSupport.create();
      t.config.withBootstrapOperatorSubjects("<b>boot</b>");
      com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaDataInterface widget = t.qInstance.getWidget("authentikHome");
      assertThat(widget.getPermissionRules().getPermissionBaseName()).isEqualTo("authentik.users.read");

      RenderWidgetInput input = new RenderWidgetInput();
      input.setWidgetMetaData(widget);
      RenderWidgetOutput output = ((AbstractWidgetRenderer) new AuthentikHomeWidget.Renderer()).render(input);
      String html = ((RawHTML) output.getWidgetData()).getHtml();

      assertThat(html).contains("Needs attention", "People", "Groups and permissions", "Recent changes", "Health", "System Health");
      assertThat(html).contains("Active</dt><dd style=\"margin:0;\">4<");
      assertThat(html).contains("Inactive</dt><dd style=\"margin:0;\">1<");
      assertThat(html).contains("Service accounts</dt><dd style=\"margin:0;\">2<");
      assertThat(html).contains("bootstrapOperatorSubjects is still set");
      assertThat(html).contains("No changes have been made from here yet.");
      assertThat(html).contains("href=\"/app/authentik_user\"").contains("href=\"/app/authentik_group\"");
      assertThat(html).doesNotContain("<b>boot</b>");
      assertThat(html).doesNotContain(AuthentikTestSupport.TEST_TOKEN);

      t.loginAs(AuthentikTestSupport.OPERATOR, IdentityPermission.USERS_READ);
      String withoutAudit = ((RawHTML) new AuthentikHomeWidget.Renderer().render(input).getWidgetData()).getHtml();
      assertThat(withoutAudit).contains("needs the authentik.audit.read permission");
   }



   /*******************************************************************************
    ** Home reads the persisted central component and links directly to its record.
    *******************************************************************************/
   @Test
   void centralHealthRollup() throws Exception
   {
      AdminTestSupport t = AdminTestSupport.create();
      new com.kingsrook.qqq.backend.core.health.HealthMetaDataProvider().defineAll(t.qInstance, AdminTestSupport.LOCAL, table -> { });
      com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore.getInstance().insert(
         new com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput().withTableName("health_component")
            .withRecord(new com.kingsrook.qqq.backend.core.model.data.QRecord().withValue("id", 7).withValue("name", "authentik").withValue("status", "DEGRADED")), true);
      AuthentikTestSupport.loginWithPermissions(t.qInstance, java.util.Set.of("health.read"));
      AuthentikHomeData data = AuthentikHomeData.load(t.config);
      assertThat(data.getHealthStatus()).isEqualTo("DEGRADED");
      assertThat(AuthentikHomeView.render(data)).contains("Authentik: DEGRADED", "href=\"/app/health_component/7\"")
         .doesNotContain("Policies at sign-in", "Version</dt>");
      AuthentikTestSupport.loginWithPermissions(t.qInstance, java.util.Set.of());
      assertThat(AuthentikHomeData.load(t.config).getHealthStatus()).isEqualTo("UNKNOWN");
   }



   /*******************************************************************************
    ** Nothing but AuthentikAdmin may send a change to Authentik: the util's
    ** write method is only called from there (the guard's authorization is the
    ** required argument; this keeps the call sites to one class).
    *******************************************************************************/
   @Test
   void onlyTheAdminServiceWrites() throws IOException
   {
      Path root = Path.of("src/main/java/com/kingsrook/qbits/authentik");
      try(Stream<Path> files = Files.walk(root))
      {
         List<Path> callers = files.filter(p -> p.toString().endsWith(".java")).filter(p ->
         {
            try
            {
               return (Files.readString(p).contains("util.write(") || Files.readString(p).contains(".write(auth") || Files.readString(p).contains("util.writeAs("));
            }
            catch(IOException e)
            {
               throw (new IllegalStateException(e));
            }
         }).toList();
         assertThat(callers).extracting(p -> p.getFileName().toString()).containsExactlyInAnyOrder("AuthentikAdmin.java", "AuthentikTokens.java");
      }
   }

}
