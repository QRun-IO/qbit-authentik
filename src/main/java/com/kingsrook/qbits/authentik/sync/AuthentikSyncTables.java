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

package com.kingsrook.qbits.authentik.sync;

import java.util.List;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.audits.QAuditRules;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.UniqueKey;

/*******************************************************************************
 ** Local sync storage. These definitions are not produced until the complete
 ** MIRROR/WEBHOOK implementation is available. No generic writes are allowed.
 *******************************************************************************/
public final class AuthentikSyncTables
{
   public static final String USER = "user_mirror";
   public static final String GROUP = "group_mirror";
   public static final String MEMBERSHIP = "membership_mirror";
   public static final String INBOX = "webhook_inbox";
   public static final String STATE = "sync_state";
   public static final String SESSION_BINDING = "session_binding";
   public static final String INVITATION_ASSIGNMENT = "invitation_assignment";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikSyncTables()
   {
   }

   /*******************************************************************************
    ** Directory projection; no raw user attributes, IPs, or user agents.
    ** Blank email is stored as null; ambiguous identities must fail sync and
    ** must never be used to grant fallback permissions.
    *******************************************************************************/
   public static QTableMetaData user(AuthentikQBitConfig config)
   {
      return (base(config, USER, "User Mirror", IdentityPermission.USERS_READ)
         .withUniqueKey(new UniqueKey("pk"))
         .withUniqueKey(new UniqueKey("username"))
         .withUniqueKey(new UniqueKey("email"))
         .withField(field("pk", QFieldType.INTEGER).withIsRequired(true))
         .withField(text("uuid", 64))
         .withField(text("username", 255).withIsRequired(true))
         .withField(text("email", 255))
         .withField(text("name", 255))
         .withField(text("type", 40))
         .withField(text("path", 1024))
         .withField(field("sourceIsSuperuser", QFieldType.BOOLEAN))
         .withField(field("sourceIsProtected", QFieldType.BOOLEAN))
         .withField(field("isActive", QFieldType.BOOLEAN))
         .withField(field("lastLogin", QFieldType.DATE_TIME))
         .withField(field("isSuperuser", QFieldType.BOOLEAN))
         .withField(field("isProtected", QFieldType.BOOLEAN))
         .withField(field("groupNames", QFieldType.TEXT))
         .withField(field("effectivePermissions", QFieldType.TEXT))
         .withField(field("mfaDeviceCount", QFieldType.INTEGER))
         .withField(field("failedLogins24h", QFieldType.INTEGER)));
   }

   /*******************************************************************************
    ** Group projection, including only qqq.io/* attributes.
    *******************************************************************************/
   public static QTableMetaData group(AuthentikQBitConfig config)
   {
      return (base(config, GROUP, "Group Mirror", IdentityPermission.USERS_READ)
         .withUniqueKey(new UniqueKey("pk"))
         .withField(text("pk", 64).withIsRequired(true))
         .withField(text("name", 255))
         .withField(field("parentPks", QFieldType.TEXT))
         .withField(field("attributes", QFieldType.TEXT))
         .withField(field("memberCount", QFieldType.INTEGER))
         .withField(field("isSuperuser", QFieldType.BOOLEAN)));
   }

   /*******************************************************************************
    ** Stable user/group keys, independent of display-name changes.
    *******************************************************************************/
   public static QTableMetaData membership(AuthentikQBitConfig config)
   {
      return (base(config, MEMBERSHIP, "Membership Mirror", IdentityPermission.USERS_READ)
         .withUniqueKey(new UniqueKey("userPk", "groupPk"))
         .withField(field("userPk", QFieldType.INTEGER).withIsRequired(true))
         .withField(text("groupPk", 64).withIsRequired(true))
         .withField(text("groupName", 255)));
   }

   /*******************************************************************************
    ** Durable event deduplication and retry state. Only the validated compact
    ** webhook envelope is retained, never the source event's full context.
    *******************************************************************************/
   public static QTableMetaData inbox(AuthentikQBitConfig config)
   {
      QTableMetaData table = base(config, INBOX, "Webhook Inbox", IdentityPermission.ADMIN)
         .withUniqueKey(new UniqueKey("eventPk"))
         .withField(text("eventPk", 64).withIsRequired(true))
         .withField(field("payloadJson", QFieldType.TEXT).withIsRequired(true))
         .withField(text("status", 30).withIsRequired(true))
         .withField(field("attempts", QFieldType.INTEGER).withIsRequired(true))
         .withField(field("receivedAt", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("nextAttemptAt", QFieldType.DATE_TIME))
         .withField(field("processedAt", QFieldType.DATE_TIME))
         .withField(text("leaseOwner", 64))
         .withField(field("leaseUntil", QFieldType.DATE_TIME))
         .withField(text("errorCode", 100));
      table.getFields().remove("refreshedAt");
      return (table);
   }

   /*******************************************************************************
    ** Checkpoints advance only after successful synchronization. Lease fields
    ** support exclusive work claims across host processes using a transaction.
    *******************************************************************************/
   public static QTableMetaData state(AuthentikQBitConfig config)
   {
      QTableMetaData table = base(config, STATE, "Sync State", IdentityPermission.ADMIN)
         .withUniqueKey(new UniqueKey("syncKey"))
         .withField(text("syncKey", 64).withIsRequired(true))
         .withField(field("watermark", QFieldType.DATE_TIME))
         .withField(field("lastFullSync", QFieldType.DATE_TIME))
         .withField(text("scopeFingerprint", 64))
         .withField(text("leaseOwner", 64))
         .withField(field("leaseUntil", QFieldType.DATE_TIME));
      table.getFields().remove("refreshedAt");
      return (table);
   }

   /*******************************************************************************
    ** Complete storage set, for migration/schema validation.
    *******************************************************************************/
   public static List<QTableMetaData> all(AuthentikQBitConfig config)
   {
      return (List.of(user(config), group(config), membership(config), inbox(config), state(config), sessionBinding(config), invitationAssignment(config)));
   }

   /***************************************************************************
    ** Internal pending grants and replay protection; no generic mutation/export.
    ***************************************************************************/
   public static QTableMetaData invitationAssignment(AuthentikQBitConfig config)
   {
      var table = base(config, INVITATION_ASSIGNMENT, "Invitation Assignments", IdentityPermission.ADMIN)
         .withUniqueKey(new UniqueKey("reference")).withUniqueKey(new UniqueKey("invitationId"))
         .withField(text("reference", 36).withIsRequired(true))
         .withField(text("scopeFingerprint", 64).withIsRequired(true))
         .withField(text("invitationId", 36))
         .withField(text("status", 20).withIsRequired(true))
         .withField(field("payloadJson", QFieldType.TEXT).withIsRequired(true))
         .withField(field("createdAt", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("expiresAt", QFieldType.DATE_TIME).withIsRequired(true));
      table.getFields().remove("refreshedAt");
      return (table);
   }

   /*******************************************************************************
    ** Internal authentication identity storage; no token or session credential.
    *******************************************************************************/
   public static QTableMetaData sessionBinding(AuthentikQBitConfig config)
   {
      QTableMetaData table = base(config, SESSION_BINDING, "Session Identity Binding", IdentityPermission.ADMIN)
         .withUniqueKey(new UniqueKey("sessionHash"))
         .withField(text("sessionHash", 64).withIsRequired(true))
         .withField(text("issuerFingerprint", 64).withIsRequired(true))
         .withField(field("userPk", QFieldType.INTEGER))
         .withField(text("userUuid", 64))
         .withField(text("userReference", 1024))
         .withField(field("expiresAt", QFieldType.DATE_TIME).withIsRequired(true))
         .withField(field("revoked", QFieldType.BOOLEAN).withIsRequired(true));
      table.getFields().remove("refreshedAt");
      return (table);
   }

   /*******************************************************************************
    ** Explicit column mapping keeps host naming strategies out of the contract.
    *******************************************************************************/
   private static QFieldMetaData field(String name, QFieldType type)
   {
      return (new QFieldMetaData(name, type).withIsEditable(false)
         .withBackendName(name.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase(java.util.Locale.ROOT)));
   }

   /*******************************************************************************
    ** Bounded string column.
    *******************************************************************************/
   private static QFieldMetaData text(String name, int length)
   {
      return (field(name, QFieldType.STRING).withMaxLength(length));
   }

   /*******************************************************************************
    ** Read-only metadata; sync's internal persistence must bypass generic writes
    ** deliberately. Mirror changes retain RECORD-level QQQ audit.
    *******************************************************************************/
   private static QTableMetaData base(AuthentikQBitConfig config, String name, String label, IdentityPermission permission)
   {
      return (new QTableMetaData().withName(config.applyTablePrefix(name)).withLabel(label)
         .withBackendName(config.getLocalBackendName()).withPrimaryKeyField("id")
         .withPermissionRules(permission.rules())
         .withAuditRules(new QAuditRules().withAuditLevel(AuditLevel.RECORD))
         .withCapabilities(Capability.TABLE_QUERY, Capability.TABLE_GET, Capability.TABLE_COUNT)
         .withoutCapabilities(Capability.TABLE_INSERT, Capability.TABLE_UPDATE, Capability.TABLE_DELETE, Capability.TABLE_EXPORT)
         .withField(field("id", QFieldType.INTEGER))
         .withField(field("refreshedAt", QFieldType.DATE_TIME).withIsRequired(true)));
   }
}
