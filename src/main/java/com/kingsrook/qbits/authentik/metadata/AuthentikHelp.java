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


import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.help.QHelpContent;
import com.kingsrook.qqq.backend.core.model.metadata.help.bundles.HelpBundles;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** Applies help/qbit-authentik.yaml (the QQQ help-bundle format) to the Identity
 ** app and its authentik_* tables: what each table is for and how its rows get
 ** created (for the API-backed tables: that they are read live, and what an
 ** empty list means), shown on the table screen and when it is empty.
 **
 ** The bundle's keys use the default table prefix; a host's own tableNamePrefix
 ** is applied to them, so renamed tables get the same text.
 ** Inline fallback for hosts without help storage; core owns bundle validation
 ** and the producer also registers the bundle for startup synchronization.
 *******************************************************************************/
public final class AuthentikHelp
{
   public static final String RESOURCE = "/help/qbit-authentik.yaml";
   public static final String SLOT     = "help";

   private static final String DEFAULT_TABLE_PREFIX = "authentik_";



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikHelp()
   {
   }



   /*******************************************************************************
    ** The bundle's entries by key, validated (fails startup if malformed).
    *******************************************************************************/
   public static Map<String, JsonNode> entries() throws QException
   {
      Map<String, JsonNode> entries = new LinkedHashMap<>();
      var bundle = HelpBundles.load(RESOURCE.substring(1), AuthentikHelp.class.getClassLoader());
      ObjectMapper mapper = new ObjectMapper();
      for(var entry : bundle.getEntries())
      {
         entries.put(entry.getKey(), mapper.valueToTree(entry));
      }
      return (entries);
   }



   /*******************************************************************************
    ** Apply the help to the app and every table the qbit produced. A host's own
    ** help on a table or the app is kept (the bundle only fills the slot).
    *******************************************************************************/
   public static void apply(QInstance qInstance, AuthentikQBitConfig config) throws QException
   {
      for(var bundle : HelpBundles.of(qInstance).getBundles())
      {
         if("qbit-authentik".equals(bundle.getId()))
         {
            for(var entry : bundle.getEntries())
            {
               entry.setKey(configuredNames(entry.getKey(), config));
               entry.setSummary(configuredNames(entry.getSummary(), config));
               entry.setContent(configuredNames(entry.getContent(), config));
            }
         }
      }
      for(Map.Entry<String, JsonNode> entry : entries().entrySet())
      {
         String key = entry.getKey();
         if(key.startsWith("table:") && key.endsWith(";slot:help"))
         {
            String tableKey = key.substring("table:".length(), key.indexOf(';'));
            String unprefixed = tableKey.substring(DEFAULT_TABLE_PREFIX.length());
            QTableMetaData table = qInstance.getTable(config.applyTablePrefix(unprefixed));
            if(table != null && (table.getHelpContent() == null || !table.getHelpContent().containsKey(SLOT)))
            {
               table.withHelpContent(SLOT, content(entry.getValue(), config));
            }
         }
         else if(key.startsWith("app:") && key.endsWith(";slot:help"))
         {
            QAppMetaData app = qInstance.getApp(config.applyPrefix(AuthentikAppMetaDataProducer.APP_NAME));
            if(app != null && (app.getHelpContent() == null || !app.getHelpContent().containsKey(SLOT)))
            {
               app.withHelpContent(SLOT, content(entry.getValue(), config));
            }
         }
      }
   }




   /*******************************************************************************
    ** Summary as the first paragraph, then the content, as markdown.
    *******************************************************************************/
   static QHelpContent content(JsonNode entry, AuthentikQBitConfig config)
   {
      return (new QHelpContent().withContentAsMarkdown(configuredNames(entry.path("summary").asText().strip() + "\n\n" + entry.path("content").asText().strip(), config)));
   }



   /*******************************************************************************
    ** Follow the host prefix in keys and live references; status enums are fixed.
    *******************************************************************************/
   private static String configuredNames(String text, AuthentikQBitConfig config)
   {
      if(text == null)
      {
         return (null);
      }
      return (Pattern.compile("authentik_[a-zA-Z0-9_]+|authentik[A-Z][a-zA-Z0-9]*").matcher(text).replaceAll(match ->
      {
         String name = match.group();
         if(name.equals("authentik_action_status") || name.equals("authentik_approval_status"))
         {
            return (name);
         }
         if(name.startsWith(DEFAULT_TABLE_PREFIX))
         {
            return (config.applyTablePrefix(name.substring(DEFAULT_TABLE_PREFIX.length())));
         }
         return (config.applyPrefix(name.substring("authentik".length())));
      }));
   }

}
