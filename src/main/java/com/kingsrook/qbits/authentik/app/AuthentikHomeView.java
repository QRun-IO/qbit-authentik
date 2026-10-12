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


import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.utils.ValueUtils;


/*******************************************************************************
 ** Renders the Identity home as one responsive HTML block (no tables, so it
 ** stays readable at every width): cards stack to one column on narrow
 ** screens, long values wrap, every card has an honest empty or unavailable
 ** state, and it follows the app's light and dark theme (inherited colors).
 *******************************************************************************/
public final class AuthentikHomeView
{
   private static final DateTimeFormatter WHEN = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

   private static final String GRID  = "display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,22rem),1fr));gap:1rem;";
   private static final String CARD  = "border:1px solid rgba(127,127,127,.3);border-radius:8px;padding:1rem;min-width:0;overflow-wrap:anywhere;";
   private static final String LIST  = "display:grid;grid-template-columns:minmax(8rem,auto) 1fr;gap:.25rem .75rem;margin:0 0 .75rem;font-size:.9rem;";
   private static final String ITEMS = "margin:0 0 .75rem;padding-left:1.25rem;font-size:.9rem;";
   private static final String MUTED = "opacity:.75;";
   private static final String WARN  = "font-weight:600;";



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikHomeView()
   {
   }



   /*******************************************************************************
    ** The whole home.
    *******************************************************************************/
   public static String render(AuthentikHomeData data)
   {
      AuthentikQBitConfig config = data.getConfig();
      StringBuilder       html   = new StringBuilder("<div class=\"authentik-home\" style=\"" + GRID + "\">");
      attention(html, data, config);
      people(html, data, config);
      groups(html, data, config);
      activity(html, data, config);
      connection(html, data);
      return (html.append("</div>").toString());
   }



   /*******************************************************************************
    ** Needs attention: the first thing a person should see.
    *******************************************************************************/
   private static void attention(StringBuilder html, AuthentikHomeData data, AuthentikQBitConfig config)
   {
      open(html, "Needs attention");
      boolean any = false;
      html.append("<ul style=\"").append(ITEMS).append("\">");
      if(data.isApprovalsAvailable() && data.getPendingApprovals() > 0)
      {
         any = true;
         html.append("<li style=\"").append(WARN).append("\">").append(data.getPendingApprovals()).append(" change(s) waiting for a second person to approve. ")
            .append(link(config, AuthentikLocalTables.APPROVAL_REQUEST, "Open approval requests")).append("</li>");
      }
      if(data.isDriftAvailable() && data.getDriftErrors() + data.getDriftWarnings() > 0)
      {
         any = true;
         html.append("<li>").append(data.getDriftErrors()).append(" drift error(s) and ").append(data.getDriftWarnings()).append(" warning(s) in the identity drift report below.</li>");
      }
      for(String line : data.getAttention())
      {
         any = true;
         html.append("<li>").append(esc(line)).append("</li>");
      }
      if(data.isPeopleAvailable() && data.getNeverSignedIn() > 0)
      {
         any = true;
         html.append("<li>").append(data.getNeverSignedIn()).append(" active person(s) have never signed in.</li>");
      }
      html.append("</ul>");
      if(!any)
      {
         empty(html, "Nothing needs attention.");
      }
      close(html);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void people(StringBuilder html, AuthentikHomeData data, AuthentikQBitConfig config)
   {
      open(html, "People");
      if(!data.isPeopleAvailable())
      {
         empty(html, "People are unavailable right now (Authentik could not be reached).");
      }
      else
      {
         html.append("<dl style=\"").append(LIST).append("\">");
         row(html, "Active", String.valueOf(data.getActivePeople()));
         row(html, "Inactive", String.valueOf(data.getInactivePeople()));
         row(html, "Service accounts", String.valueOf(data.getServiceAccounts()));
         row(html, "Protected", data.getProtectedAccounts() + " (cannot be changed from here)");
         html.append("</dl>");
      }
      html.append(link(config, AuthentikTables.USER, "Users"));
      close(html);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void groups(StringBuilder html, AuthentikHomeData data, AuthentikQBitConfig config)
   {
      open(html, "Groups and permissions");
      if(!data.isGroupsAvailable())
      {
         empty(html, "Groups are unavailable right now (Authentik could not be reached).");
      }
      else
      {
         html.append("<dl style=\"").append(LIST).append("\">");
         row(html, "Groups", String.valueOf(data.getGroups()));
         row(html, "Grant QQQ permissions", String.valueOf(data.getGroupsWithPermissions()));
         row(html, "Grant app sign-in", String.valueOf(data.getGroupsWithAppAccess()));
         row(html, "Superuser (locked)", String.valueOf(data.getSuperuserGroups()));
         row(html, "Empty", String.valueOf(data.getEmptyGroups()));
         html.append("</dl>");
      }
      html.append(link(config, AuthentikTables.GROUP, "Groups"));
      close(html);
   }



   /*******************************************************************************
    ** Recent changes made from here (audit.read only).
    *******************************************************************************/
   private static void activity(StringBuilder html, AuthentikHomeData data, AuthentikQBitConfig config)
   {
      open(html, "Recent changes");
      if(!data.isMayAudit())
      {
         empty(html, "The change history needs the authentik.audit.read permission.");
      }
      else if(!data.isActionsAvailable())
      {
         empty(html, "The change history is unavailable right now.");
      }
      else if(data.getRecentActions().isEmpty())
      {
         empty(html, "No changes have been made from here yet.");
      }
      else
      {
         html.append("<ul style=\"").append(ITEMS).append("\">");
         for(QRecord row : data.getRecentActions())
         {
            Instant created = ValueUtils.getValueAsInstant(row.getValue("createDate"));
            html.append("<li><a href=\"").append(esc(prefix(config) + "/" + config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION) + "/" + row.getValue("id"))).append("\">")
               .append(esc(row.getValueString("actionName"))).append("</a> ").append(esc(row.getValueString("targetLabel"))).append(", ")
               .append(esc(row.getValueString("status"))).append(created == null ? "" : ", " + WHEN.format(created)).append("</li>");
         }
         html.append("</ul>");
      }
      if(data.isMayAudit())
      {
         html.append(link(config, AuthentikLocalTables.ADMIN_ACTION, "All changes"));
      }
      close(html);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void connection(StringBuilder html, AuthentikHomeData data)
   {
      open(html, "Connection");
      html.append("<dl style=\"").append(LIST).append("\">");
      row(html, "Authentik", data.getConfig().getBaseUrl());
      row(html, "Version", data.getVersion() == null ? "Not reachable" : data.getVersion());
      row(html, "Service account", data.getConfig().getEffectiveServiceAccountUsername());
      row(html, "Changes", Boolean.TRUE.equals(data.getConfig().getReadOnly()) ? "Off (read-only)" : "On, every change is audited here and in Authentik");
      html.append("</dl>");
      close(html);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String prefix(AuthentikQBitConfig config)
   {
      return (config.getLinkPrefix() == null ? "" : config.getLinkPrefix());
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String link(AuthentikQBitConfig config, String table, String text)
   {
      String name = AuthentikLocalTables.APPROVAL_REQUEST.equals(table) || AuthentikLocalTables.ADMIN_ACTION.equals(table)
         ? config.applyTablePrefix(table) : config.applyTablePrefix(table);
      return ("<a href=\"" + esc(prefix(config) + "/" + name) + "\">" + esc(text) + "</a>");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void open(StringBuilder html, String title)
   {
      html.append("<section style=\"").append(CARD).append("\"><h3 style=\"margin:0 0 .5rem;font-size:1rem;\">").append(esc(title)).append("</h3>");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void close(StringBuilder html)
   {
      html.append("</section>");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void empty(StringBuilder html, String text)
   {
      html.append("<p style=\"").append(MUTED).append("\">").append(esc(text)).append("</p>");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void row(StringBuilder html, String label, String value)
   {
      html.append("<dt style=\"").append(MUTED).append("\">").append(esc(label)).append("</dt><dd style=\"margin:0;\">").append(esc(value)).append("</dd>");
   }



   /*******************************************************************************
    ** HTML-escape.
    *******************************************************************************/
   static String esc(String text)
   {
      if(text == null)
      {
         return ("");
      }
      return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;"));
   }

}
