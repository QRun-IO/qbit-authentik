/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.sync;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.admin.AuthentikInvitationEvidence;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.module.rdbms.jdbc.ConnectionManager;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData;
import org.json.JSONObject;

/*******************************************************************************
 ** Internal durable intent and at-most-once automatic grant attempts. This store
 ** does not authorize writes or verify events; the admin integration must do so
 ** before using it. An interrupted remote write requires review, never replay.
 *******************************************************************************/
public final class AuthentikInvitationAssignments
{
   private final AuthentikQBitConfig config;
   private final AuthentikSyncLease.Connections connections;
   private final String table;

   /***************************************************************************
    ** Read-only facts for admin processing; suppress implicit PII in diagnostics.
    ***************************************************************************/
   public record Intent(String reference, String invitationId, String status, Integer operatorPk, String operatorUuid,
      String flow, String reason, Map<String, String> groups, Integer userPk, String userUuid, Instant createdAt, Instant expiresAt)
   {
      /***********************************************************************
       ** No mutable progress maps escape storage.
       ***********************************************************************/
      public Intent
      {
         groups = Map.copyOf(groups);
      }

      /***********************************************************************
       ** Safe diagnostics.
       ***********************************************************************/
      @Override
      public String toString()
      {
         return ("AuthentikInvitationIntent[" + status + "]");
      }
   }

   /***************************************************************************
    ** A persisted grant attempt can finish once and cannot be started again.
    ***************************************************************************/
   public record Attempt(String reference, String groupId, String id)
   {
   }

   /***************************************************************************
    ** Reuse the host provider rather than creating a private connection pool.
    ***************************************************************************/
   public AuthentikInvitationAssignments(AuthentikQBitConfig config)
   {
      this(config, () -> ConnectionManager.getConnection((RDBMSBackendMetaData) QContext.getQInstance().getBackend(config.getLocalBackendName())));
   }

   /***************************************************************************
    ** Isolated database seam for the shared H2/PostgreSQL contracts.
    ***************************************************************************/
   AuthentikInvitationAssignments(AuthentikQBitConfig config, AuthentikSyncLease.Connections connections)
   {
      this.config = config;
      this.connections = connections;
      table = config.applyTablePrefix(AuthentikSyncTables.INVITATION_ASSIGNMENT);
      if(!table.matches("[A-Za-z][A-Za-z0-9_]*"))
      {
         throw (new IllegalArgumentException("Invalid invitation storage table."));
      }
   }

   /***************************************************************************
    ** Create immutable intent before remote invitation/email side effects. The
    ** admin caller must have validated and audited the operator's selected groups.
    ***************************************************************************/
   public String create(Integer operatorPk, String operatorUuid, String flow, String reason, List<String> groupIds) throws Exception
   {
      guard();
      if(operatorPk == null || operatorPk < 1 || flow == null || !flow.matches("[A-Za-z0-9_-]{1,100}")
         || reason == null || reason.isBlank() || reason.length() > 2048 || groupIds == null || groupIds.isEmpty() || groupIds.size() > 100)
      {
         throw (new IllegalArgumentException("Invalid invitation assignment intent."));
      }
      JSONObject groups = new JSONObject();
      for(String group : groupIds)
      {
         String id = uuid(group);
         if(groups.has(id))
         {
            throw (new IllegalArgumentException("Duplicate invitation group."));
         }
         groups.put(id, new JSONObject().put("state", "PENDING"));
      }
      JSONObject payload = new JSONObject().put("operatorPk", operatorPk).put("operatorUuid", uuid(operatorUuid))
         .put("flow", flow).put("reason", reason).put("groups", groups);
      String reference = UUID.randomUUID().toString();
      try(var connection = connections.open(); var statement = connection.prepareStatement("INSERT INTO " + table
         + " (reference,scope_fingerprint,status,payload_json,created_at,expires_at) VALUES (?,?,'WAITING',?,?,?)"))
      {
         Instant now = AuthentikSyncLease.now(connection);
         statement.setString(1, reference);
         statement.setString(2, AuthentikSyncLease.scopeFingerprint(config));
         statement.setString(3, payload.toString());
         statement.setObject(4, now.atOffset(java.time.ZoneOffset.UTC));
         statement.setObject(5, now.plus(Duration.ofDays(7)).atOffset(java.time.ZoneOffset.UTC));
         statement.executeUpdate();
      }
      return (reference);
   }

   /***************************************************************************
    ** Attach the provider-created invitation once, before its email is sent.
    ***************************************************************************/
   public boolean attach(String reference, String invitationId) throws Exception
   {
      String id = uuid(invitationId);
      return (mutate(reference, row ->
      {
         if(!"WAITING".equals(row.status) || (row.invitationId != null && !row.invitationId.equals(id)))
         {
            return (false);
         }
         row.invitationId = id;
         return (true);
      }));
   }

   /***************************************************************************
    ** Persist verified consumption independently of enrollment delivery. The
    ** caller verifies the authoritative event and protected flow before this.
    ***************************************************************************/
   public boolean recordConsumption(String reference, AuthentikInvitationEvidence.Consumption evidence) throws Exception
   {
      return (recordConsumption(null, reference, evidence));
   }

   /***************************************************************************
    ** Join the inbox ownership transaction; never commit or close its connection.
    ***************************************************************************/
   boolean recordConsumption(Connection connection, String reference, AuthentikInvitationEvidence.Consumption evidence) throws Exception
   {
      guard();
      if(evidence == null || evidence.createdAt() == null)
      {
         return (false);
      }
      JSONObject fact = new JSONObject().put("eventId", uuid(evidence.eventId()))
         .put("invitationId", uuid(evidence.invitationId())).put("createdAt", evidence.createdAt().toString());
      return (mutate(connection, reference, true, row -> java.util.Objects.equals(row.invitationId, evidence.invitationId())
         && withinWindow(row, evidence.createdAt()) && recordFact(row, "consumption", fact)));
   }

   /***************************************************************************
    ** Persist the verified new account and its live immutable UUID even when
    ** the consumption hint has not arrived. No assignment starts until paired.
    ***************************************************************************/
   public boolean recordEnrollment(String reference, AuthentikInvitationEvidence.Enrollment evidence, String userUuid) throws Exception
   {
      return (recordEnrollment(null, reference, evidence, userUuid));
   }

   /***************************************************************************
    ** Enrollment and inbox ownership share the caller's transaction boundary.
    ***************************************************************************/
   boolean recordEnrollment(Connection connection, String reference, AuthentikInvitationEvidence.Enrollment evidence, String userUuid) throws Exception
   {
      guard();
      if(evidence == null || evidence.createdAt() == null || evidence.userPk() == null || evidence.userPk() < 1
         || !java.util.Objects.equals(reference, evidence.reference()))
      {
         return (false);
      }
      JSONObject fact = new JSONObject().put("eventId", uuid(evidence.eventId())).put("reference", uuid(evidence.reference()))
         .put("userPk", evidence.userPk()).put("userUuid", uuid(userUuid)).put("createdAt", evidence.createdAt().toString());
      return (mutate(connection, reference, true, row -> row.invitationId != null && withinWindow(row, evidence.createdAt())
         && recordFact(row, "enrollment", fact)));
   }

   /***************************************************************************
    ** First verified facts are immutable. Either arrival order atomically binds
    ** the same pair; duplicates cannot reset completed group attempts. Conflicting
    ** chronology is retained for review instead of becoming grant authority.
    ***************************************************************************/
   private static boolean recordFact(Row row, String key, JSONObject fact)
   {
      if(!List.of("WAITING", "READY", "COMPLETE").contains(row.status))
      {
         return (false);
      }
      if(row.payload.has(key))
      {
         return (row.payload.getJSONObject(key).similar(fact));
      }
      if(!"WAITING".equals(row.status))
      {
         return (false);
      }
      row.payload.put(key, fact);
      if(row.payload.has("consumption") && row.payload.has("enrollment"))
      {
         JSONObject consumed = row.payload.getJSONObject("consumption");
         JSONObject enrolled = row.payload.getJSONObject("enrollment");
         if(Instant.parse(enrolled.getString("createdAt")).isBefore(Instant.parse(consumed.getString("createdAt"))))
         {
            row.status = "REVIEW";
         }
         else
         {
            row.payload.put("binding", new JSONObject().put("userPk", enrolled.getInt("userPk")).put("userUuid", enrolled.getString("userUuid"))
               .put("consumptionEvent", consumed.getString("eventId")).put("enrollmentEvent", enrolled.getString("eventId")));
            row.status = "READY";
         }
      }
      return (true);
   }

   /***************************************************************************
    ** Evidence belongs to this saved intent's bounded enrollment window.
    ***************************************************************************/
   private static boolean withinWindow(Row row, Instant created)
   {
      return (!created.isBefore(row.createdAt) && !created.isAfter(row.expiresAt));
   }

   /***************************************************************************
    ** Bind one verified enrollment once. Evidence must have been fetched for
    ** this intent's flow; the caller also verifies the live user's immutable UUID.
    ** A conflicting replay cannot overwrite the first binding or reset progress.
    ***************************************************************************/
   public boolean bind(String reference, AuthentikInvitationEvidence.Consumption consumed,
      AuthentikInvitationEvidence.Enrollment enrolled, String userUuid) throws Exception
   {
      guard();
      if(consumed == null || enrolled == null || consumed.createdAt() == null || enrolled.createdAt() == null)
      {
         return (false);
      }
      String identity = uuid(userUuid);
      return (mutate(reference, row ->
      {
         if(consumed == null || enrolled == null || !reference.equals(enrolled.reference())
            || !java.util.Objects.equals(row.invitationId, consumed.invitationId()) || enrolled.userPk() == null || enrolled.userPk() < 1
            || consumed.createdAt().isBefore(row.createdAt) || enrolled.createdAt().isBefore(consumed.createdAt())
            || enrolled.createdAt().isAfter(row.expiresAt))
         {
            return (false);
         }
         JSONObject consumption = new JSONObject().put("eventId", uuid(consumed.eventId()))
            .put("invitationId", uuid(consumed.invitationId())).put("createdAt", consumed.createdAt().toString());
         JSONObject enrollment = new JSONObject().put("eventId", uuid(enrolled.eventId())).put("reference", uuid(enrolled.reference()))
            .put("userPk", enrolled.userPk()).put("userUuid", identity).put("createdAt", enrolled.createdAt().toString());
         return (recordFact(row, "consumption", consumption) && recordFact(row, "enrollment", enrollment));
      }));
   }

   /***************************************************************************
    ** Persist IN_FLIGHT before calling Authentik. No automatic reset exists:
    ** losing the response or crashing requires review of the remote outcome.
    ***************************************************************************/
   public Attempt begin(String reference, String groupId) throws Exception
   {
      return (begin(null, reference, groupId));
   }

   /***************************************************************************
    ** Persist the exclusive remote attempt while the event is still owned. Its
    ** ticket remains finishable after lease expiry; no other worker may replay it.
    ***************************************************************************/
   public Attempt begin(String reference, String groupId, AuthentikWebhookInbox inbox, AuthentikWebhookInbox.Claim claim) throws Exception
   {
      guard();
      var ticket = new java.util.concurrent.atomic.AtomicReference<Attempt>();
      boolean owned = inbox.withClaim(claim, connection -> ticket.set(begin(connection, reference, groupId)));
      return (owned ? ticket.get() : null);
   }

   /***************************************************************************
    ** Share the transition with standalone and inbox-owned transactions.
    ***************************************************************************/
   private Attempt begin(Connection connection, String reference, String groupId) throws Exception
   {
      String group = uuid(groupId);
      String attempt = UUID.randomUUID().toString();
      boolean started = mutate(connection, reference, true, row ->
      {
         JSONObject groups = row.payload.getJSONObject("groups");
         if(!"READY".equals(row.status) || !groups.has(group) || !"PENDING".equals(groups.getJSONObject(group).getString("state"))
            || groups.keySet().stream().anyMatch(key -> "IN_FLIGHT".equals(groups.getJSONObject(key).getString("state"))))
         {
            return (false);
         }
         groups.put(group, new JSONObject().put("state", "IN_FLIGHT").put("attempt", attempt));
         return (true);
      });
      return (started ? new Attempt(reference, group, attempt) : null);
   }

   /***************************************************************************
    ** Record known success once; failure requires review and stops later groups.
    ***************************************************************************/
   public boolean finish(Attempt attempt, boolean success) throws Exception
   {
      return (mutate(attempt.reference(), false, row ->
      {
         JSONObject groups = row.payload.getJSONObject("groups");
         JSONObject group = groups.optJSONObject(attempt.groupId());
         if(!"READY".equals(row.status) || group == null || !"IN_FLIGHT".equals(group.optString("state"))
            || !attempt.id().equals(group.optString("attempt")))
         {
            return (false);
         }
         group.put("state", success ? "APPLIED" : "REVIEW");
         if(!success)
         {
            row.status = "REVIEW";
         }
         else if(groups.keySet().stream().allMatch(key -> "APPLIED".equals(groups.getJSONObject(key).getString("state"))))
         {
            row.status = "COMPLETE";
         }
         return (true);
      }));
   }

   /***************************************************************************
    ** Stop pending work; an in-flight call cannot be promised cancelled.
    ***************************************************************************/
   public boolean cancel(String reference) throws Exception
   {
      return (mutate(reference, false, row ->
      {
         if(!List.of("WAITING", "READY").contains(row.status))
         {
            return (false);
         }
         var groups = row.payload.getJSONObject("groups");
         if(groups.keySet().stream().anyMatch(key -> "IN_FLIGHT".equals(groups.getJSONObject(key).getString("state"))))
         {
            return (false);
         }
         row.status = "CANCELLED";
         return (true);
      }));
   }

   /***************************************************************************
    ** Locate the intent for an administrative cancellation without email or
    ** mutable username matching. Scope and internal-session checks still apply.
    ***************************************************************************/
   public Intent findByInvitation(String invitationId) throws Exception
   {
      guard();
      String reference = null;
      try(var connection = connections.open(); var query = connection.prepareStatement("SELECT reference FROM " + table
         + " WHERE invitation_id=? AND scope_fingerprint=?"))
      {
         query.setString(1, uuid(invitationId));
         query.setString(2, AuthentikSyncLease.scopeFingerprint(config));
         try(var result = query.executeQuery())
         {
            if(result.next())
            {
               reference = result.getString(1);
            }
         }
      }
      return (reference == null ? null : find(reference));
   }

   /***************************************************************************
    ** Return saved intent even after expiry for review, but never across scope.
    ***************************************************************************/
   public Intent find(String reference) throws Exception
   {
      guard();
      try(var connection = connections.open())
      {
         Row row = load(connection, uuid(reference), false);
         if(row == null)
         {
            return (null);
         }
         var groups = new TreeMap<String, String>();
         row.payload.getJSONObject("groups").keySet().forEach(key -> groups.put(key, row.payload.getJSONObject("groups").getJSONObject(key).getString("state")));
         var binding = row.payload.optJSONObject("binding");
         return (new Intent(reference, row.invitationId, row.status, row.payload.getInt("operatorPk"), row.payload.getString("operatorUuid"),
            row.payload.getString("flow"), row.payload.getString("reason"), groups, binding == null ? null : binding.getInt("userPk"),
            binding == null ? null : binding.getString("userUuid"), row.createdAt, row.expiresAt));
      }
   }

   /***************************************************************************
    ** Serialize transitions in host SQL; no network work happens under this lock.
    ***************************************************************************/
   private boolean mutate(String reference, java.util.function.Predicate<Row> change) throws Exception
   {
      return (mutate(reference, true, change));
   }

   /***************************************************************************
    ** Expiry stops new work, but cannot discard the outcome of an existing call.
    ***************************************************************************/
   private boolean mutate(String reference, boolean requireUnexpired, java.util.function.Predicate<Row> change) throws Exception
   {
      guard();
      try(var connection = connections.open())
      {
         connection.setAutoCommit(false);
         try
         {
            if(!mutate(connection, reference, requireUnexpired, change))
            {
               connection.rollback();
               return (false);
            }
            connection.commit();
            return (true);
         }
         catch(Exception failure)
         {
            connection.rollback();
            throw (failure);
         }
      }
   }

   /***************************************************************************
    ** Apply a local transition under the caller's lock/commit boundary. A null
    ** connection selects the standalone transaction used by admin operations.
    ***************************************************************************/
   private boolean mutate(Connection connection, String reference, boolean requireUnexpired, java.util.function.Predicate<Row> change) throws Exception
   {
      guard();
      if(connection == null)
      {
         return (mutate(reference, requireUnexpired, change));
      }
      if(connection.getAutoCommit())
      {
         throw (new SQLException("Invitation evidence requires a transaction."));
      }
      Row row = load(connection, uuid(reference), true);
      if(row == null || (requireUnexpired && !row.expiresAt.isAfter(AuthentikSyncLease.now(connection))) || !change.test(row))
      {
         return (false);
      }
      try(var statement = connection.prepareStatement("UPDATE " + table + " SET invitation_id=?,status=?,payload_json=? WHERE reference=?"))
      {
         statement.setString(1, row.invitationId);
         statement.setString(2, row.status);
         statement.setString(3, row.payload.toString());
         statement.setString(4, reference);
         statement.executeUpdate();
      }
      return (true);
   }

   /***************************************************************************
    ** Retain settled intent for thirty days after expiry. Pending and ambiguous
    ** outcomes remain available for review; cleanup never resets grant progress.
    ***************************************************************************/
   public int purgeSettled() throws SQLException, QPermissionDeniedException
   {
      guard();
      try(var connection = connections.open(); var statement = connection.prepareStatement("DELETE FROM " + table
         + " WHERE scope_fingerprint=? AND status IN ('COMPLETE','CANCELLED') AND expires_at < ?"))
      {
         connection.setAutoCommit(true);
         statement.setString(1, AuthentikSyncLease.scopeFingerprint(config));
         statement.setObject(2, AuthentikSyncLease.now(connection).minus(Duration.ofDays(30)).atOffset(java.time.ZoneOffset.UTC));
         return (statement.executeUpdate());
      }
   }

   /***************************************************************************
    ** Read one scope-bound row, optionally under the transition lock.
    ***************************************************************************/
   private Row load(Connection connection, String reference, boolean lock) throws SQLException
   {
      try(var statement = connection.prepareStatement("SELECT invitation_id,status,payload_json,created_at,expires_at FROM " + table
         + " WHERE reference=? AND scope_fingerprint=?" + (lock ? " FOR UPDATE" : "")))
      {
         statement.setString(1, reference);
         statement.setString(2, AuthentikSyncLease.scopeFingerprint(config));
         try(var result = statement.executeQuery())
         {
            if(!result.next())
            {
               return (null);
            }
            var row = new Row();
            row.invitationId = result.getString(1);
            row.status = result.getString(2);
            row.payload = new JSONObject(result.getString(3));
            row.createdAt = result.getTimestamp(4).toInstant();
            row.expiresAt = result.getTimestamp(5).toInstant();
            return (row);
         }
      }
   }

   /***************************************************************************
    ** Private mutable transaction snapshot, never returned to callers.
    ***************************************************************************/
   private static final class Row
   {
      private String invitationId;
      private String status;
      private JSONObject payload;
      private Instant createdAt;
      private Instant expiresAt;
   }

   /***************************************************************************
    ** No interactive caller may create or advance deferred authorization state.
    ***************************************************************************/
   private static void guard() throws QPermissionDeniedException
   {
      if(!(QContext.getQSession() instanceof QSystemUserSession))
      {
         throw (new QPermissionDeniedException("Invitation assignment storage requires the internal session."));
      }
   }

   /***************************************************************************
    ** Strict canonical identifiers prevent ambiguous keys and path injection.
    ***************************************************************************/
   private static String uuid(String value)
   {
      if(value == null || !value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
      {
         throw (new IllegalArgumentException("Invalid invitation assignment identifier."));
      }
      return (value);
   }
}
