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


import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.drift.AuthentikDriftReport;
import com.kingsrook.qbits.authentik.drift.DriftFinding;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.TableData;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;


/*******************************************************************************
 ** Renders the drift report as a TableData. Re-checks identity.admin itself
 ** (QQQ core does not enforce permissions for non-HTTP callers, qqq#1061).
 *******************************************************************************/
public class AuthentikDriftReportWidgetRenderer extends AbstractWidgetRenderer
{

   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public RenderWidgetOutput render(RenderWidgetInput input) throws QException
   {
      if(!AuthentikGuard.has(QContext.getQSession(), IdentityPermission.ADMIN))
      {
         throw (new QPermissionDeniedException("You do not have permission to view the identity drift report."));
      }

      String backendName = String.valueOf(((QWidgetMetaData) input.getWidgetMetaData()).getDefaultValues().get(AuthentikDriftReportWidgetProducer.BACKEND_NAME_KEY));
      AuthentikRuntime    runtime = AuthentikRuntime.forBackend(backendName);
      AuthentikActionUtil client  = AuthentikActionUtil.forBackend(backendName);
      List<DriftFinding>  findings = new AuthentikDriftReport(client, runtime.getConfig()).run();

      List<Map<String, Object>> rows = new ArrayList<>();
      for(DriftFinding finding : findings)
      {
         Map<String, Object> row = new LinkedHashMap<>();
         row.put("severity", finding.severity().name());
         row.put("check", finding.check());
         row.put("subject", finding.subject());
         row.put("message", finding.message());
         rows.add(row);
      }

      List<TableData.Column> columns = List.of(
         new TableData.Column("default", "Severity", "severity", "10%", "left"),
         new TableData.Column("default", "Check", "check", "15%", "left"),
         new TableData.Column("default", "Subject", "subject", "20%", "left"),
         new TableData.Column("default", "Finding", "message", "55%", "left"));

      TableData tableData = new TableData("Identity Drift Report", columns, rows)
         .withRowsPerPage(25)
         .withNoRowsFoundHTML("No findings.");
      return (new RenderWidgetOutput(tableData));
   }

}
