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


import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.ChildRecordListRenderer;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.joins.JoinOn;
import com.kingsrook.qqq.backend.core.model.metadata.joins.JoinType;
import com.kingsrook.qqq.backend.core.model.metadata.joins.QJoinMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QFieldSection;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Tier;


/*******************************************************************************
 ** Sub-tables appear on their parents' record screens as child lists, not in
 ** the nav (owner standard): a user shows its memberships, sessions, tokens and
 ** events; a group shows its members; an application shows its policy bindings;
 ** an approval request needs none. The joins are metadata only (the lists
 ** query the child table filtered by the parent's key), so they work on the
 ** API backend.
 *******************************************************************************/
public final class AuthentikRelations
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikRelations()
   {
   }



   /*******************************************************************************
    ** Add the joins, child-list widgets and record sections for the tables the
    ** config produced. Safe to call once per instance.
    *******************************************************************************/
   public static void apply(QInstance qInstance, AuthentikQBitConfig config)
   {
      String user       = config.applyTablePrefix(AuthentikTables.USER);
      String group      = config.applyTablePrefix(AuthentikTables.GROUP);
      String membership = config.applyTablePrefix(AuthentikTables.GROUP_MEMBER);
      String session    = config.applyTablePrefix(AuthentikTables.SESSION);
      String token      = config.applyTablePrefix(AuthentikTables.TOKEN);
      String event      = config.applyTablePrefix(AuthentikTables.EVENT);
      String application = config.applyTablePrefix(AuthentikTables.APPLICATION);
      String binding    = config.applyTablePrefix(AuthentikTables.POLICY_BINDING);

      List<QFieldSection> userSections = new ArrayList<>();
      userSections.add(new QFieldSection("identity", "Identity", new QIcon("badge"), Tier.T1,
         List.of("username", "name", "email", "isActive", "type", "isProtected", "isSuperuser", "path", "lastLogin", "dateJoined", "lastUpdated", "pk")));
      userSections.add(new QFieldSection("access", "Access", new QIcon("admin_panel_settings"), Tier.T2,
         List.of("groupNames", "roleNames", "effectivePermissions")));
      relate(qInstance, userSections, "memberships", "Memberships", "group_add", user, membership, "pk", "userPk");
      relate(qInstance, userSections, "sessions", "Sessions", "devices", user, session, "username", "username");
      relate(qInstance, userSections, "tokens", "Tokens and app passwords", "key", user, token, "username", "username");
      relate(qInstance, userSections, "events", "History", "history", user, event, "username", "username");
      userSections.add(new QFieldSection("attributes", "Attributes", new QIcon("data_object"), Tier.T3, List.of("qqqAttributes", "passwordChangeDate", "attributes")));
      applySections(qInstance, user, userSections);

      List<QFieldSection> groupSections = new ArrayList<>();
      groupSections.add(new QFieldSection("details", "Details", new QIcon("groups"), Tier.T1,
         List.of("name", "isSuperuser", "isSuperuserInherited", "parentNames", "childNames", "memberCount", "roleNames", "pk")));
      groupSections.add(new QFieldSection("permissions", "Permissions and app access", new QIcon("admin_panel_settings"), Tier.T2,
         List.of("permissions", "effectivePermissions", "appAccess")));
      relate(qInstance, groupSections, "members", "Members", "group", group, membership, "pk", "groupPk");
      groupSections.add(new QFieldSection("attributes", "Attributes", new QIcon("data_object"), Tier.T3, List.of("attributes")));
      applySections(qInstance, group, groupSections);

      List<QFieldSection> appSections = new ArrayList<>();
      appSections.add(new QFieldSection("details", "Details", new QIcon("apps"), Tier.T1,
         List.of("name", "slug", "group", "providerName", "policyEngineMode", "launchUrl", "publisher", "hiddenFromLibrary")));
      relate(qInstance, appSections, "bindings", "Who can open it (policy bindings)", "rule", application, binding, "bindingTarget", "target");
      applySections(qInstance, application, appSections);
   }



   /*******************************************************************************
    ** One join plus its child-list widget and the section that shows it.
    *******************************************************************************/
   private static void relate(QInstance qInstance, List<QFieldSection> sections, String key, String label, String icon,
      String parentTable, String childTable, String parentField, String childField)
   {
      if(qInstance.getTable(parentTable) == null || qInstance.getTable(childTable) == null)
      {
         return;
      }

      String       joinName = parentTable + "_" + key;
      QJoinMetaData join    = new QJoinMetaData()
         .withName(joinName)
         .withLeftTable(parentTable)
         .withRightTable(childTable)
         .withType(JoinType.ONE_TO_MANY)
         .withJoinOn(new JoinOn(parentField, childField));
      qInstance.addJoin(join);

      QWidgetMetaData widget = ChildRecordListRenderer.widgetMetaDataBuilder(join).withLabel(label).withMaxRows(20).getWidgetMetaData();
      qInstance.addWidget(widget);
      sections.add(new QFieldSection(key, new QIcon(icon), Tier.T2).withLabel(label).withWidgetName(widget.getName()));
   }



   /*******************************************************************************
    ** Replace a table's sections (the enricher would otherwise skip the field
    ** sections once a widget section exists).
    *******************************************************************************/
   private static void applySections(QInstance qInstance, String tableName, List<QFieldSection> sections)
   {
      QTableMetaData table = qInstance.getTable(tableName);
      if(table != null)
      {
         table.setSections(sections);
      }
   }

}
