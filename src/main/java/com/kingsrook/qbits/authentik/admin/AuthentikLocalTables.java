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


import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.audits.QAuditRules;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.PossibleValueEnum;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValueSource;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.UniqueKey;


/*******************************************************************************
 ** The qbit's own tables (DESIGN.md section 6.2), standard visible QQQ tables on
 ** the host's local RDBMS backend, named authentik_* (lowercase snake_case).
 ** Both are written only by the qbit: the generic insert, update and delete
 ** capabilities are off for everyone, and the audit table is append-only.
 **
 ** The host creates the SQL tables (see docs/schema.sql).
 *******************************************************************************/
public final class AuthentikLocalTables
{
   public static final String TOKEN_SCOPE = "token_scope";
   public static final String ADMIN_ACTION        = "admin_action";
   public static final String APPROVAL_REQUEST    = "approval_request";
   public static final String POLICY              = "policy";
   public static final String PVS_ACTION_STATUS   = "authentik_action_status";
   public static final String PVS_APPROVAL_STATUS = "authentik_approval_status";



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikLocalTables()
   {
   }



   /*******************************************************************************
    ** Status of an audited action.
    *******************************************************************************/
   public enum ActionStatus implements PossibleValueEnum<String>
   {
      PENDING_APPROVAL("Waiting for approval"),
      RUNNING("Running"),
      SUCCEEDED("Succeeded"),
      FAILED("Failed"),
      REFUSED("Refused");

      private final String label;



      /*******************************************************************************
       ** Constructor.
       *******************************************************************************/
      ActionStatus(String label)
      {
         this.label = label;
      }



      /*******************************************************************************
       ** Getter for possibleValueId.
       *******************************************************************************/
      @Override
      public String getPossibleValueId()
      {
         return (name());
      }



      /*******************************************************************************
       ** Getter for possibleValueLabel.
       *******************************************************************************/
      @Override
      public String getPossibleValueLabel()
      {
         return (label);
      }
   }



   /*******************************************************************************
    ** Status of a two-person approval request.
    *******************************************************************************/
   public enum ApprovalStatus implements PossibleValueEnum<String>
   {
      PENDING("Waiting for approval"),
      APPROVED("Approved and applied"),
      REJECTED("Rejected"),
      EXPIRED("Expired"),
      FAILED("Approved but failed");

      private final String label;



      /*******************************************************************************
       ** Constructor.
       *******************************************************************************/
      ApprovalStatus(String label)
      {
         this.label = label;
      }



      /*******************************************************************************
       ** Getter for possibleValueId.
       *******************************************************************************/
      @Override
      public String getPossibleValueId()
      {
         return (name());
      }



      /*******************************************************************************
       ** Getter for possibleValueLabel.
       *******************************************************************************/
      @Override
      public String getPossibleValueLabel()
      {
         return (label);
      }
   }



   /*******************************************************************************
    ** The possible-value sources the local tables use.
    *******************************************************************************/
   public static List<QPossibleValueSource> possibleValueSources()
   {
      return (List.of(
         QPossibleValueSource.newForEnum(PVS_ACTION_STATUS, ActionStatus.values()),
         QPossibleValueSource.newForEnum(PVS_APPROVAL_STATUS, ApprovalStatus.values())));
   }



   /*******************************************************************************
    ** authentik_admin_action: append-only audit and outbox of every write the
    ** qbit attempts. The row is inserted BEFORE the API call.
    *******************************************************************************/
   public static QTableMetaData adminAction(AuthentikQBitConfig config)
   {
      return (base(config, ADMIN_ACTION, "Admin Actions", "history", IdentityPermission.AUDIT_READ)
         .withRecordLabelFormatAndFields("%s %s", "actionName", "targetLabel")
         .withField(ro("correlationId", QFieldType.STRING).withMaxLength(64))
         .withField(ro("actionName", QFieldType.STRING).withMaxLength(60))
         .withField(ro("operator", QFieldType.STRING).withMaxLength(255))
         .withField(ro("reason", QFieldType.TEXT))
         .withField(ro("targetType", QFieldType.STRING).withMaxLength(30))
         .withField(ro("targetKey", QFieldType.STRING).withMaxLength(100))
         .withField(ro("targetLabel", QFieldType.STRING).withMaxLength(255))
         .withField(ro("beforeText", QFieldType.TEXT))
         .withField(ro("afterText", QFieldType.TEXT))
         .withField(ro("status", QFieldType.STRING).withPossibleValueSourceName(PVS_ACTION_STATUS))
         .withField(ro("errorMessage", QFieldType.TEXT))
         .withField(ro("authentikEventPk", QFieldType.STRING).withMaxLength(64))
         .withField(ro("approver", QFieldType.STRING).withMaxLength(255)));
   }



   /*******************************************************************************
    ** authentik_approval_request: two-person requests (a second person with
    ** authentik.approve applies or rejects the stored change).
    *******************************************************************************/
   public static QTableMetaData approvalRequest(AuthentikQBitConfig config)
   {
      return (base(config, APPROVAL_REQUEST, "Approval Requests", "how_to_reg", IdentityPermission.APPROVE)
         .withRecordLabelFormatAndFields("%s %s", "actionName", "targetLabel")
         .withField(ro("actionName", QFieldType.STRING).withMaxLength(60))
         .withField(ro("targetKey", QFieldType.STRING).withMaxLength(100))
         .withField(ro("targetLabel", QFieldType.STRING).withMaxLength(255))
         .withField(ro("summary", QFieldType.TEXT))
         .withField(ro("reason", QFieldType.TEXT))
         .withField(ro("payloadJson", QFieldType.TEXT))
         .withField(ro("requester", QFieldType.STRING).withMaxLength(255))
         .withField(ro("approver", QFieldType.STRING).withMaxLength(255))
         .withField(ro("status", QFieldType.STRING).withPossibleValueSourceName(PVS_APPROVAL_STATUS))
         .withField(ro("expiresDate", QFieldType.DATE_TIME))
         .withField(ro("decidedDate", QFieldType.DATE_TIME))
         .withField(ro("errorMessage", QFieldType.TEXT)));
   }



   /*******************************************************************************
    ** authentik_policy: one row per group with a policy (DESIGN.md section 12).
    ** Authentik holds the live document; this row is the QQQ record of the last
    ** save, and field-level audit is its change history. Written only by the
    ** Edit Policy action.
    *******************************************************************************/
   public static QTableMetaData policy(AuthentikQBitConfig config)
   {
      return (base(config, POLICY, "Policies", "policy", IdentityPermission.USERS_READ)
         .withRecordLabelFormatAndFields("%s", "groupName")
         .withUniqueKey(new UniqueKey("groupPk"))
         .withAuditRules(new QAuditRules().withAuditLevel(AuditLevel.FIELD))
         .withField(ro("groupPk", QFieldType.STRING).withLabel("Group Id").withMaxLength(64))
         .withField(ro("groupName", QFieldType.STRING).withLabel("Group").withMaxLength(255))
         .withField(ro("policyJson", QFieldType.TEXT).withLabel("Policy Document"))
         .withField(ro("statementCount", QFieldType.INTEGER).withLabel("Statements"))
         .withField(ro("permissionCount", QFieldType.INTEGER).withLabel("Permissions"))
         .withField(ro("savedBy", QFieldType.STRING).withLabel("Saved By").withMaxLength(255))
         .withField(ro("savedDate", QFieldType.DATE_TIME).withLabel("Saved"))
         .withField(ro("authentikFingerprint", QFieldType.STRING).withLabel("Authentik Fingerprint").withMaxLength(64)));
   }



   /*******************************************************************************
    ** Common shape: id, create and modify dates, no generic writes.
    *******************************************************************************/
   private static QTableMetaData base(AuthentikQBitConfig config, String name, String label, String icon, IdentityPermission permission)
   {
      return (new QTableMetaData()
         .withName(config.applyTablePrefix(name))
         .withLabel(label)
         .withIcon(new QIcon(icon))
         .withBackendName(config.getLocalBackendName())
         .withPrimaryKeyField("id")
         .withPermissionRules(permission.rules())
         .withCapabilities(Capability.TABLE_QUERY, Capability.TABLE_GET, Capability.TABLE_COUNT, Capability.TABLE_EXPORT)
         .withoutCapabilities(Capability.TABLE_INSERT, Capability.TABLE_UPDATE, Capability.TABLE_DELETE)
         .withField(new QFieldMetaData("id", QFieldType.INTEGER).withIsEditable(false))
         .withField(new QFieldMetaData("createDate", QFieldType.DATE_TIME).withIsEditable(false))
         .withField(new QFieldMetaData("modifyDate", QFieldType.DATE_TIME).withIsEditable(false)));
   }



   /*******************************************************************************
    ** A read-only field.
    *******************************************************************************/
   private static QFieldMetaData ro(String name, QFieldType type)
   {
      return (new QFieldMetaData(name, type).withIsEditable(false));
   }



   /*******************************************************************************
    ** Non-secret scope metadata only (DESIGN section 13.5).
    *******************************************************************************/
   public static QTableMetaData tokenScope(AuthentikQBitConfig config)
   {
      QTableMetaData table = base(config, TOKEN_SCOPE, "Token Scopes", "key", IdentityPermission.TOKENS_MANAGE)
         .withPermissionRules(com.kingsrook.qbits.authentik.security.TokenReadPermission.rules())
         .withRecordLabelFormatAndFields("%s", "tokenIdentifier")
         .withUniqueKey(new UniqueKey("tokenIdentifier"))
         .withAuditRules(new QAuditRules().withAuditLevel(AuditLevel.RECORD))
         .withField(ro("tokenIdentifier", QFieldType.STRING).withMaxLength(255))
         .withField(ro("ownerUsername", QFieldType.STRING).withMaxLength(255))
         .withField(ro("ownerPk", QFieldType.INTEGER))
         .withField(ro("readOnly", QFieldType.BOOLEAN))
         .withField(ro("createdBy", QFieldType.STRING).withMaxLength(255));
      table.getFields().remove("createDate");
      table.getFields().remove("modifyDate");
      for(String name : List.of("apps", "tables", "processes", "reports", "widgets", "operationIds"))
      {
         table.withField(ro(name, QFieldType.TEXT));
      }
      for(String name : List.of("createdAt", "rotatedAt", "lastReminder7d", "lastReminder1d"))
      {
         table.withField(ro(name, QFieldType.DATE_TIME));
      }
      return (table);
   }

}
