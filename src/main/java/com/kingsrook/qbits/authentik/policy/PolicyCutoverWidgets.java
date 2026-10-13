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

package com.kingsrook.qbits.authentik.policy;


import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.permissions.AccessComparison;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.RawHTML;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.TableData;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;


/*******************************************************************************
 ** The cut-over widgets (DESIGN.md section 12.8): the enforcement banner shown
 ** on group and policy screens and on Edit Policy, and the Compare Access
 ** report (read only).
 *******************************************************************************/
public final class PolicyCutoverWidgets
{
   /** Widget default value naming the qbit's API backend. */
   public static final String BACKEND_NAME_KEY = "backendName";

   /** Short name of the banner widget. */
   public static final String ENFORCEMENT = "policyEnforcement";

   /** Short name of the report widget. */
   public static final String COMPARE = "compareAccess";



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private PolicyCutoverWidgets()
   {
   }



   /*******************************************************************************
    ** The mapper state for a widget's backend.
    *******************************************************************************/
   static AccessComparison.State state(RenderWidgetInput input) throws QException
   {
      String backendName = String.valueOf(((QWidgetMetaData) input.getWidgetMetaData()).getDefaultValues().get(BACKEND_NAME_KEY));
      return (AccessComparison.state(AuthentikRuntime.forBackend(backendName), AuthentikActionUtil.forBackend(backendName)));
   }



   /*******************************************************************************
    ** The banner as HTML (also used by the home's health card).
    *******************************************************************************/
   public static String bannerHtml(AccessComparison.State state)
   {
      String style = state.enforced()
         ? "border:1px solid #16a34a;background:rgba(22,163,74,.10);"
         : "border:1px solid #d97706;background:rgba(217,119,6,.12);";
      return ("<div role=\"status\" data-qqq-id=\"authentik-policy-enforcement\" data-status=\"" + state.status().name() + "\" style=\"" + style
         + "border-radius:.375rem;padding:.5rem .75rem;font-size:.875rem;line-height:1.4;color:inherit;\"><strong>"
         + (state.enforced() ? "Enforced. " : "Not enforced. ") + "</strong>" + escape(state.message()) + "</div>");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   static String escape(String text)
   {
      return (text == null ? "" : text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;"));
   }



   /*******************************************************************************
    ** The enforcement banner (authentik.users.read).
    *******************************************************************************/
   public static class EnforcementRenderer extends AbstractWidgetRenderer
   {
      /*******************************************************************************
       **
       *******************************************************************************/
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         return (new RenderWidgetOutput(new RawHTML(null, bannerHtml(state(input)))));
      }
   }



   /*******************************************************************************
    ** Compare Access (authentik.admin): every active person's access today
    ** against what the mapper would grant. Read only.
    *******************************************************************************/
   public static class CompareRenderer extends AbstractWidgetRenderer
   {
      /*******************************************************************************
       **
       *******************************************************************************/
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         if(!AuthentikGuard.has(QContext.getQSession(), IdentityPermission.ADMIN))
         {
            throw (new QPermissionDeniedException("You do not have permission to compare access."));
         }
         String           backendName = String.valueOf(((QWidgetMetaData) input.getWidgetMetaData()).getDefaultValues().get(BACKEND_NAME_KEY));
         AuthentikRuntime runtime     = AuthentikRuntime.forBackend(backendName);
         List<AccessComparison.Row> rows = AccessComparison.run(runtime.getConfig(), AuthentikActionUtil.forBackend(backendName), runtime.getPermissionCatalog());

         List<Map<String, Object>> data = new ArrayList<>();
         int removedPeople = 0;
         for(AccessComparison.Row row : rows)
         {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("user", escape(row.username()) + (row.guarded() ? " (guarded)" : ""));
            map.put("groups", escape(String.join(", ", row.groups())));
            map.put("added", row.added().isEmpty() ? "-" : escape(String.join(", ", row.added())));
            map.put("removed", row.removed().isEmpty() ? "-" : escape(String.join(", ", row.removed())));
            map.put("unchanged", row.before().size() - row.removed().size());
            data.add(map);
            if(!row.removed().isEmpty())
            {
               removedPeople++;
            }
         }
         List<TableData.Column> columns = List.of(
            new TableData.Column("html", "User", "user", "15%", "left"),
            new TableData.Column("html", "Groups", "groups", "20%", "left"),
            new TableData.Column("html", "Added", "added", "27%", "left"),
            new TableData.Column("html", "Removed", "removed", "28%", "left"),
            new TableData.Column("default", "Unchanged", "unchanged", "10%", "right"));
         List<AccessComparison.Row> failures = AccessComparison.guardFailures(rows);
         String summary = rows.size() + " active people; " + removedPeople + " would lose permissions; guard "
            + (runtime.getConfig().getCutoverGuardGroups().isEmpty() ? "not configured" : failures.isEmpty() ? "passes" : "FAILS for " + failures.size())
            + (runtime.getConfig().getHostPermissionSource() == null ? ". No host permission source is configured, so today's access is shown as empty." : ".");
         TableData table = new TableData("Compare Access (today vs policies)", columns, data)
            .withRowsPerPage(25)
            .withNoRowsFoundHTML("No active people.");
         table.setFooterHTML("<p style=\"font-size:.875rem;\">" + escape(summary) + "</p>");
         return (new RenderWidgetOutput(table));
      }
   }
}
