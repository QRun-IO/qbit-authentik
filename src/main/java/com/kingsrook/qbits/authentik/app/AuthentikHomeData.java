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
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikJson;
import com.kingsrook.qbits.authentik.drift.AuthentikDriftReport;
import com.kingsrook.qbits.authentik.drift.DriftFinding;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.actions.tables.CountAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.json.JSONObject;
import static com.kingsrook.qqq.backend.core.logging.LogUtils.logPair;


/*******************************************************************************
 ** Everything the Identity home shows (DESIGN.md section 8.3), read live from
 ** Authentik and the qbit's own tables. Each section is loaded on its own, so a
 ** failure shows as "unavailable" for that card instead of hiding the page.
 ** Sections that expose sensitive data need authentik.audit.read.
 *******************************************************************************/
public class AuthentikHomeData
{
   private static final QLogger LOG = QLogger.getLogger(AuthentikHomeData.class);

   public static final int TOKEN_WARNING_DAYS = 14;

   private boolean       peopleAvailable;
   private int           activePeople;
   private int           inactivePeople;
   private int           serviceAccounts;
   private int           neverSignedIn;
   private int           protectedAccounts;

   private boolean       groupsAvailable;
   private int           groups;
   private int           groupsWithPermissions;
   private int           groupsWithAppAccess;
   private int           superuserGroups;
   private int           emptyGroups;

   private boolean       approvalsAvailable;
   private int           pendingApprovals;

   private boolean       driftAvailable;
   private int           driftErrors;
   private int           driftWarnings;

   private boolean       mayAudit;
   private boolean       actionsAvailable;
   private List<QRecord> recentActions = new ArrayList<>();
   private List<String>  attention     = new ArrayList<>();

   private AuthentikQBitConfig config;
   private String              version;



   /*******************************************************************************
    ** Load everything for the current session.
    *******************************************************************************/
   public static AuthentikHomeData load(AuthentikQBitConfig config) throws Exception
   {
      AuthentikHomeData data = new AuthentikHomeData();
      data.config = config;
      data.mayAudit = AuthentikGuard.has(QContext.getQSession(), IdentityPermission.AUDIT_READ);
      AuthentikActionUtil util = AuthentikActionUtil.forBackend(config.getApiBackendName());

      data.loadPeople(util);
      data.loadGroups(util);
      data.loadApprovals();
      data.loadActions();
      data.loadAttention(util);
      data.version = util.fetchServerVersion().orElse(null);
      return (data);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private void loadPeople(AuthentikActionUtil util)
   {
      try
      {
         for(JSONObject user : util.allUsers())
         {
            String type = user.optString("type");
            if("service_account".equals(type))
            {
               serviceAccounts++;
            }
            else if(user.optBoolean("is_active", true))
            {
               activePeople++;
            }
            else
            {
               inactivePeople++;
            }
            if(user.isNull("last_login") && !"service_account".equals(type) && user.optBoolean("is_active", true))
            {
               neverSignedIn++;
            }
            if(util.getRuntime().getGuard().protection(user).isProtected())
            {
               protectedAccounts++;
            }
         }
         peopleAvailable = true;
      }
      catch(Exception e)
      {
         LOG.info("Identity home: people unavailable", logPair("error", e.getClass().getSimpleName()));
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private void loadGroups(AuthentikActionUtil util)
   {
      try
      {
         GroupGraph graph = util.groupGraphWithMembers();
         for(GroupGraph.Node node : graph.nodes())
         {
            groups++;
            if(!node.permissions().isEmpty())
            {
               groupsWithPermissions++;
            }
            if(!node.appAccess().isEmpty())
            {
               groupsWithAppAccess++;
            }
            if(graph.isSuperuserInherited(node.pk()))
            {
               superuserGroups++;
            }
            if(node.memberPks().isEmpty())
            {
               emptyGroups++;
            }
         }
         groupsAvailable = true;
      }
      catch(Exception e)
      {
         LOG.info("Identity home: groups unavailable", logPair("error", e.getClass().getSimpleName()));
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private void loadApprovals()
   {
      if(!hasLocal() || !config.getTwoPersonApproval() || !config.hasFeature(AuthentikFeature.GROUPS))
      {
         return;
      }
      try
      {
         CountInput countInput = new CountInput();
         countInput.setTableName(config.applyTablePrefix(AuthentikLocalTables.APPROVAL_REQUEST));
         countInput.setFilter(new QQueryFilter(new QFilterCriteria("status", QCriteriaOperator.EQUALS, AuthentikLocalTables.ApprovalStatus.PENDING.name())));
         pendingApprovals = new CountAction().execute(countInput).getCount();
         approvalsAvailable = true;
      }
      catch(Exception e)
      {
         LOG.info("Identity home: approvals unavailable", logPair("error", e.getClass().getSimpleName()));
      }
   }



   /*******************************************************************************
    ** The latest admin actions (audit.read only).
    *******************************************************************************/
   private void loadActions()
   {
      if(!hasLocal() || !mayAudit)
      {
         return;
      }
      try
      {
         QueryInput queryInput = new QueryInput();
         queryInput.setTableName(config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION));
         queryInput.setFilter(new QQueryFilter().withOrderBy(new QFilterOrderBy("id", false)).withLimit(8));
         recentActions = new QueryAction().execute(queryInput).getRecords();
         actionsAvailable = true;
      }
      catch(Exception e)
      {
         LOG.info("Identity home: admin actions unavailable", logPair("error", e.getClass().getSimpleName()));
      }
   }



   /*******************************************************************************
    ** Things that need a person: drift findings, blueprint state, tokens about
    ** to expire, bootstrap operators still set.
    *******************************************************************************/
   private void loadAttention(AuthentikActionUtil util)
   {
      if(!config.getResolvedBootstrapSubjects().isEmpty())
      {
         attention.add("bootstrapOperatorSubjects is still set: remove it once an identity administrator is set up in Authentik.");
      }
      if(Boolean.TRUE.equals(config.getReadOnly()))
      {
         attention.add("The Identity screens are in read-only mode: no change can be made from here.");
      }
      if(AuthentikGuard.has(QContext.getQSession(), IdentityPermission.ADMIN))
      {
         try
         {
            for(DriftFinding finding : new AuthentikDriftReport(util, config).run())
            {
               if(finding.severity() == DriftFinding.Severity.ERROR)
               {
                  driftErrors++;
               }
               else if(finding.severity() == DriftFinding.Severity.WARNING)
               {
                  driftWarnings++;
               }
            }
            driftAvailable = true;
         }
         catch(Exception e)
         {
            LOG.info("Identity home: drift report unavailable", logPair("error", e.getClass().getSimpleName()));
         }
      }
      if(mayAudit)
      {
         try
         {
            Instant soon = Instant.now().plus(TOKEN_WARNING_DAYS, ChronoUnit.DAYS);
            for(JSONObject token : util.getAllPages("/core/tokens/?user__username=" + java.net.URLEncoder.encode(config.getEffectiveServiceAccountUsername(), java.nio.charset.StandardCharsets.UTF_8), 50))
            {
               Instant expires = AuthentikJson.parseInstant(token.optString("expires", null));
               if(token.optBoolean("expiring", true) && expires != null && expires.isBefore(soon))
               {
                  attention.add("The qbit's API token (" + token.optString("identifier") + ") expires on "
                     + java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(java.time.ZoneOffset.UTC).format(expires) + ": rotate it (owner checklist).");
               }
            }
         }
         catch(Exception e)
         {
            LOG.debug("Identity home: token expiry not checked", e);
         }
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private boolean hasLocal()
   {
      return (config.getLocalBackendName() != null && QContext.getQInstance().getTable(config.applyTablePrefix(AuthentikLocalTables.ADMIN_ACTION)) != null);
   }



   /*******************************************************************************
    ** Getter for config
    *******************************************************************************/
   public AuthentikQBitConfig getConfig()
   {
      return (config);
   }



   /*******************************************************************************
    ** Getter for version
    *******************************************************************************/
   public String getVersion()
   {
      return (version);
   }



   /*******************************************************************************
    ** Getter for peopleAvailable
    *******************************************************************************/
   public boolean isPeopleAvailable()
   {
      return (peopleAvailable);
   }



   /*******************************************************************************
    ** Getter for activePeople
    *******************************************************************************/
   public int getActivePeople()
   {
      return (activePeople);
   }



   /*******************************************************************************
    ** Getter for inactivePeople
    *******************************************************************************/
   public int getInactivePeople()
   {
      return (inactivePeople);
   }



   /*******************************************************************************
    ** Getter for serviceAccounts
    *******************************************************************************/
   public int getServiceAccounts()
   {
      return (serviceAccounts);
   }



   /*******************************************************************************
    ** Getter for neverSignedIn
    *******************************************************************************/
   public int getNeverSignedIn()
   {
      return (neverSignedIn);
   }



   /*******************************************************************************
    ** Getter for protectedAccounts
    *******************************************************************************/
   public int getProtectedAccounts()
   {
      return (protectedAccounts);
   }



   /*******************************************************************************
    ** Getter for groupsAvailable
    *******************************************************************************/
   public boolean isGroupsAvailable()
   {
      return (groupsAvailable);
   }



   /*******************************************************************************
    ** Getter for groups
    *******************************************************************************/
   public int getGroups()
   {
      return (groups);
   }



   /*******************************************************************************
    ** Getter for groupsWithPermissions
    *******************************************************************************/
   public int getGroupsWithPermissions()
   {
      return (groupsWithPermissions);
   }



   /*******************************************************************************
    ** Getter for groupsWithAppAccess
    *******************************************************************************/
   public int getGroupsWithAppAccess()
   {
      return (groupsWithAppAccess);
   }



   /*******************************************************************************
    ** Getter for superuserGroups
    *******************************************************************************/
   public int getSuperuserGroups()
   {
      return (superuserGroups);
   }



   /*******************************************************************************
    ** Getter for emptyGroups
    *******************************************************************************/
   public int getEmptyGroups()
   {
      return (emptyGroups);
   }



   /*******************************************************************************
    ** Getter for approvalsAvailable
    *******************************************************************************/
   public boolean isApprovalsAvailable()
   {
      return (approvalsAvailable);
   }



   /*******************************************************************************
    ** Getter for pendingApprovals
    *******************************************************************************/
   public int getPendingApprovals()
   {
      return (pendingApprovals);
   }



   /*******************************************************************************
    ** Getter for driftAvailable
    *******************************************************************************/
   public boolean isDriftAvailable()
   {
      return (driftAvailable);
   }



   /*******************************************************************************
    ** Getter for driftErrors
    *******************************************************************************/
   public int getDriftErrors()
   {
      return (driftErrors);
   }



   /*******************************************************************************
    ** Getter for driftWarnings
    *******************************************************************************/
   public int getDriftWarnings()
   {
      return (driftWarnings);
   }



   /*******************************************************************************
    ** Getter for mayAudit
    *******************************************************************************/
   public boolean isMayAudit()
   {
      return (mayAudit);
   }



   /*******************************************************************************
    ** Getter for actionsAvailable
    *******************************************************************************/
   public boolean isActionsAvailable()
   {
      return (actionsAvailable);
   }



   /*******************************************************************************
    ** Getter for recentActions
    *******************************************************************************/
   public List<QRecord> getRecentActions()
   {
      return (recentActions);
   }



   /*******************************************************************************
    ** Getter for attention
    *******************************************************************************/
   public List<String> getAttention()
   {
      return (attention);
   }

}
