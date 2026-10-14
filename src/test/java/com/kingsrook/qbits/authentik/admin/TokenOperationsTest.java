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


import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.app.AuthentikTokenWidget;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.client.AuthentikTokenActivity;
import com.kingsrook.qbits.authentik.client.FixtureActionUtil;
import com.kingsrook.qbits.authentik.metadata.AuthentikTokenReminderProcessProducer;
import com.kingsrook.qbits.authentik.processes.AuthentikTokenReminders;
import com.kingsrook.qbits.authentik.security.AuthentikTokenScopes;
import com.kingsrook.qqq.backend.core.actions.processes.RunProcessAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunProcessInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.TableData;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.scheduleing.simple.SimpleSchedulerMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Event aggregation, scheduling, delivery dedupe and standard admin widgets.
 *******************************************************************************/
class TokenOperationsTest
{
   private AdminTestSupport t;
   private AuthentikActionUtil util;
   private final List<AuthentikTokenAlerts.Notice> notices = new ArrayList<>();
   private final Instant now = Instant.now();

   /*******************************************************************************
    ** Capture delivery without a dependency on Alerts or a real mail service.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws QException
   {
      t = AdminTestSupport.create();
      util = AuthentikActionUtil.forBackend(t.config.getApiBackendName());
      util.getRuntime().withTokenAlerts(notice -> { notices.add(notice); return (true); });
   }



   /*******************************************************************************
    ** Seed an expiring token for the chosen owner.
    *******************************************************************************/
   private JSONObject token(String id, int owner, int days)
   {
      return (t.authentik.seedToken(id, owner, "app_password", now.plus(days, ChronoUnit.DAYS).toString()));
   }



   /*******************************************************************************
    ** A login event using the pinned context.method_args.identifier contract.
    *******************************************************************************/
   private JSONObject event(String id, Instant at)
   {
      return (new JSONObject().put("action", "login").put("created", at.toString())
         .put("context", new JSONObject().put("method", "token").put("method_args", new JSONObject().put("identifier", id))));
   }



   /*******************************************************************************
    ** Create non-secret bookkeeping with a known age for widget assertions.
    *******************************************************************************/
   private void created(String id, int days) throws QException
   {
      TokenScopeStore store = new TokenScopeStore(t.config);
      store.create(id, t.authentik.users.get(3), AdminRequest.of(AdminAction.CREATE_TOKEN, "", "test"), "sam@example.test");
      QRecord row = store.find(id).withValue("createdAt", now.minus(days, ChronoUnit.DAYS));
      new UpdateAction().execute(new UpdateInput().withTableName("authentik_token_scope").withRecords(List.of(row)));
   }



   /*******************************************************************************
    ** Page, stop at 90 days, exclude non-token events, and reuse the 5-minute map.
    *******************************************************************************/
   @Test
   void eventPagingWindowAndCache() throws QException
   {
      for(int i = 0; i < 101; i++)
      {
         t.authentik.loginEvents.add(event("token-" + i, now.minus(i, ChronoUnit.HOURS)));
      }
      t.authentik.loginEvents.add(event("token-0", now.minus(20, ChronoUnit.DAYS)));
      t.authentik.loginEvents.add(event("password", now).put("context", new JSONObject().put("method", "password")));
      t.authentik.loginEvents.add(event("wrong-action", now).put("action", "logout"));
      t.authentik.loginEvents.add(event("old", now.minus(91, ChronoUnit.DAYS)));
      Map<String, Instant> used = AuthentikTokenActivity.lastUsed(util);
      assertThat(used).hasSize(101).containsEntry("token-0", now).doesNotContainKeys("password", "wrong-action", "old");
      long requests = FixtureActionUtil.REQUESTS.stream().filter(r -> r.getURI().getPath().endsWith("/events/events/")).count();
      assertThat(requests).isEqualTo(2);
      t.authentik.loginEvents.add(event("later", now));
      assertThat(AuthentikTokenActivity.lastUsed(util)).isEqualTo(used);
      assertThat(FixtureActionUtil.REQUESTS.stream().filter(r -> r.getURI().getPath().endsWith("/events/events/")).count()).isEqualTo(requests);
      assertThat(util.getRuntime().getTokenActivityCache().getTimeout()).isEqualTo(java.time.Duration.ofMinutes(5));
   }



   /*******************************************************************************
    ** API activity is explicitly not tracked, and local creation/scope is shown.
    *******************************************************************************/
   @Test
   void computedFields() throws QException
   {
      token("personal", 3, 5);
      created("personal", 31);
      t.authentik.loginEvents.add(event("personal", now));
      QRecord record = util.toRecord(AuthentikTables.get(AuthentikTables.TOKEN), util.getApiJson("/core/tokens/personal/"), true);
      assertThat(record.getValueInstant("lastUsed")).isEqualTo(now);
      assertThat(record.getValueInstant("createdAt")).isEqualTo(now.minus(31, ChronoUnit.DAYS));
      assertThat(record.getValueString("scopeSummary")).isEqualTo("Owner permissions");
      JSONObject api = token("api", 3, 5).put("intent", "api");
      QRecord untracked = util.toRecord(AuthentikTables.get(AuthentikTables.TOKEN), api, true);
      assertThat(untracked.getValue("lastUsed")).isNull();
      assertThat(untracked.getValueString("lastUsedNote")).isEqualTo("not tracked");
   }



   /*******************************************************************************
    ** Each window sends once to the owner's email; a minimal external row does
    ** not invent restrictions or a creation date. Extending resets the windows.
    *******************************************************************************/
   @Test
   void remindersDedupeAcrossBothWindows() throws QException
   {
      token("external", 3, 5);
      token("tomorrow", 3, 1);
      token("api", 3, 1).put("intent", "api");
      token("expired", 3, -1);
      token("later", 3, 20);
      token("no-email", 6, 2);
      AuthentikTokenReminders.run(util, now);
      AuthentikTokenReminders.run(util, now);
      assertThat(notices).hasSize(2).allMatch(n -> "sam@example.test".equals(n.recipient()));
      assertThat(notices.getFirst().message()).contains("Your access token Test access (external)", "Preferences > Access tokens.");
      TokenScopeStore store = new TokenScopeStore(t.config);
      QRecord row = store.find("external");
      assertThat(row.getValue("createdAt")).isNull();
      assertThat(row.getValue("readOnly")).isNull();
      assertThat(row.getValue("lastReminder7d")).isNotNull();
      assertThat(row.getValue("lastReminder1d")).isNull();
      AuthentikTokenReminders.run(util, now.plus(4, ChronoUnit.DAYS));
      assertThat(notices).hasSize(3);
      assertThat(store.find("external").getValue("lastReminder1d")).isNotNull();
      store.resetReminders("external");
      assertThat(store.find("external").getValue("lastReminder7d")).isNull();
      AuthentikTokenScopes.apply(QContext.getQSession(), new JSONObject().put("qqq_token", "external"));
      assertThat(QContext.getQSession().getPermissions()).isNotEmpty();
   }



   /*******************************************************************************
    ** Delivery absence leaves dedupe unset so installing Alerts permits retry.
    *******************************************************************************/
   @Test
   void unavailableDeliveryAndUnauthorizedRun() throws QException
   {
      token("external", 3, 5);
      util.getRuntime().withTokenAlerts(new AuthentikTokenAlerts()::send);
      AuthentikTokenReminders.run(util, now);
      assertThat(new TokenScopeStore(t.config).find("external")).isNull();
      assertThat(new AuthentikTokenAlerts().send(new AuthentikTokenAlerts.Notice("authentik_token_guard_bypass", "high", null, "safe"))).isFalse();
      t.loginAs("sam@example.test");
      assertThatThrownBy(() -> AuthentikTokenReminders.run(util, now)).hasMessageContaining("tokens.manage");
      assertThatThrownBy(() -> AuthentikTokenWidget.data(util, now)).hasMessageContaining("tokens.manage");
   }



   /*******************************************************************************
    ** The hidden daily process runs with core's system scheduler session.
    *******************************************************************************/
   @Test
   void scheduledProcessAndBulkRevokeMetadata() throws QException
   {
      t.qInstance.addScheduler(new SimpleSchedulerMetaData().withName("test"));
      AuthentikTokenReminderProcessProducer producer = new AuthentikTokenReminderProcessProducer();
      producer.setQBitConfig(t.config);
      var process = producer.produce(t.qInstance);
      assertThat(process.getSchedule().getRepeatSeconds()).isEqualTo(86400);
      assertThat(process.getSchedule().getSchedulerName()).isEqualTo("test");
      assertThat(process.getIsHidden()).isTrue();
      token("external", 3, 5);
      QContext.init(t.qInstance, new QSystemUserSession());
      new RunProcessAction().execute(new RunProcessInput().withProcessName("authentikTokenReminders"));
      assertThat(notices).hasSize(1);
      var revoke = t.qInstance.getProcess("authentikRevokeToken");
      assertThat(revoke.getTableName()).isEqualTo("authentik_token");
      assertThat(revoke.getMinInputRecords()).isEqualTo(1);
      assertThat(revoke.getMaxInputRecords()).isEqualTo(AuthentikAdmin.MAX_BULK);
      assertThat(Boolean.TRUE.equals(revoke.getIsHidden())).isFalse();
   }



   /*******************************************************************************
    ** Widget counts, known/unknown ages, links, deactivated owners and inactivity.
    *******************************************************************************/
   @Test
   void adminWidgetUsesStandardTableAndSafeFilters() throws QException
   {
      token("new", 3, 5); created("new", 10);
      token("middle", 3, 5); created("middle", 45);
      token("unused", 3, 5); created("unused", 100);
      token("ancient", 3, 5); created("ancient", 400);
      token("unknown", 7, 5);
      token("api", 3, 5).put("intent", "api"); created("api", 100);
      t.authentik.loginEvents.add(event("middle", now));
      TableData data = AuthentikTokenWidget.data(util, now);
      assertThat(data.getRows()).contains(Map.of("category", "Age: unknown", "count", 1, "tokens", data.getRows().stream()
         .filter(row -> "Age: unknown".equals(row.get("category"))).findFirst().orElseThrow().get("tokens")));
      assertThat(data.getRows()).filteredOn(row -> "Unused for 60 days".equals(row.get("category"))).hasSize(2);
      assertThat(data.getRows()).filteredOn(row -> "Owner deactivated".equals(row.get("category"))).hasSize(1);
      assertThat(data.getRows().toString()).contains("?filter=", "identifier", "username").doesNotContain("lastUsed%22");
      QWidgetMetaData widget = (QWidgetMetaData) t.qInstance.getWidget("authentikAccessTokens");
      assertThat(widget.getType()).isEqualTo("TABLE");
      assertThat(new AuthentikTokenWidget().render(new RenderWidgetInput().withWidgetMetaData(widget))).isNotNull();
      t.config.withTokenUnusedDays(120);
      assertThat(AuthentikTokenWidget.data(util, now).getRows()).noneMatch(row -> "Unused for 120 days".equals(row.get("category")));
   }



   /*******************************************************************************
    ** A post-write owner move is a high-severity incident without a token key.
    *******************************************************************************/
   @Test
   void protectedOwnerRaceRaisesAlert() throws QException
   {
      t.authentik.users.get(6).getJSONObject("attributes").put("goauthentik.io/user/token-maximum-lifetime", "days=365");
      token("service", 6, 5);
      t.authentik.moveTokenAfterUpdate = true;
      var result = t.admin().execute(AdminRequest.of(AdminAction.EXTEND_TOKEN, "service", "test").with("expiresInDays", 20));
      assertThat(result.ok()).isFalse();
      assertThat(notices).hasSize(1);
      assertThat(notices.getFirst().key()).isEqualTo("authentik_token_guard_bypass");
      assertThat(notices.getFirst().severity()).isEqualTo("high");
      assertThat(notices.toString()).doesNotContain(t.authentik.tokenKeys.get("service"));
   }
   /*******************************************************************************
    ** External extension opens a new reminder window without rewriting scope.
    *******************************************************************************/
   @Test
   void externalExtensionStartsNewReminderWindow() throws QException
   {
      JSONObject token = token("external", 3, 5);
      AuthentikTokenReminders.run(util, now);
      token.put("expires", now.plus(20, ChronoUnit.DAYS).toString());
      util.getRuntime().invalidateCache();
      AuthentikTokenReminders.run(util, now.plus(15, ChronoUnit.DAYS));
      assertThat(notices).hasSize(2);
   }

}
