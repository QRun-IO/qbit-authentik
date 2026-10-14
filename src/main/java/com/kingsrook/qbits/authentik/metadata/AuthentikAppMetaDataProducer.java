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

package com.kingsrook.qbits.authentik.metadata;


import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.MetaDataProducerMultiOutput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppSection;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitComponentMetaDataProducer;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitProductionContext;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** The "Identity" app (DESIGN.md section 8.1): the qbit's tables (and, from
 ** phase 1, its widgets), gated by authentik.users.read. Hosts may re-parent it,
 ** for example under an Admin app; its name stays the same. Processes are only
 ** ever table or record actions, never navigation entries.
 *******************************************************************************/
public class AuthentikAppMetaDataProducer extends QBitComponentMetaDataProducer<QAppMetaData, AuthentikQBitConfig>
{
   public static final String APP_NAME = "admin";



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public QAppMetaData produce(QInstance qInstance) throws QException
   {
      AuthentikQBitConfig config = getQBitConfig();

      QAppMetaData app = new QAppMetaData()
         .withName(config.applyPrefix(APP_NAME))
         .withLabel("Identity")
         .withIcon(new QIcon("badge"))
         .withPermissionRules(IdentityPermission.USERS_READ.rules());

      MetaDataProducerMultiOutput produced = QBitProductionContext.peekMetaDataProducerMultiOutput();
      if(produced != null)
      {
         ///////////////////////////////////////////////////////////////////////////
         // the nav lists only the main tables; memberships, sessions, tokens,   //
         // events, bindings, roles and blueprints are reached from their parent //
         // records as child lists                                               //
         ///////////////////////////////////////////////////////////////////////////
         addSection(app, produced, config, "people", "People", "person", AuthentikTables.USER, AuthentikTables.INVITATION);
         addSection(app, produced, config, "access", "Access", "admin_panel_settings", AuthentikTables.GROUP, AuthentikLocalTables.POLICY, AuthentikTables.APPLICATION);
         addSection(app, produced, config, "activity", "Activity", "history", AuthentikLocalTables.APPROVAL_REQUEST, AuthentikLocalTables.ADMIN_ACTION);

         List<String> widgets = new ArrayList<>();
         for(String widgetName : List.of(config.applyPrefix(AuthentikHomeWidgetProducer.NAME), config.applyPrefix(AuthentikTokenWidgetProducer.NAME), config.applyPrefix(AuthentikDriftReportWidgetProducer.NAME),
            config.applyPrefix(com.kingsrook.qbits.authentik.policy.PolicyCutoverWidgets.COMPARE)))
         {
            if(produced.get(QWidgetMetaData.class, widgetName) != null)
            {
               widgets.add(widgetName);
            }
         }
         app.withWidgets(widgets);
      }
      return (app);
   }



   /*******************************************************************************
    ** Add a nav section with the main tables that were produced.
    *******************************************************************************/
   private static void addSection(QAppMetaData app, MetaDataProducerMultiOutput produced, AuthentikQBitConfig config, String name, String label, String icon, String... specNames)
   {
      List<String> names = new ArrayList<>();
      for(String specName : specNames)
      {
         String       tableName = config.applyTablePrefix(specName);
         QTableMetaData table   = produced.get(QTableMetaData.class, tableName);
         if(table != null)
         {
            app.withChild(table);
            names.add(tableName);
         }
      }
      if(!names.isEmpty())
      {
         app.withSection(new QAppSection().withName(name).withLabel(label).withIcon(new QIcon(icon)).withTables(names));
      }
   }



   /*******************************************************************************
    ** Last, so the tables exist in the output.
    *******************************************************************************/
   @Override
   public int getSortOrder()
   {
      return (900);
   }

}
