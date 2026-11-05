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

import java.time.Instant;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Directory projections preserve effective access without copying raw context.
 *******************************************************************************/
class AuthentikMirrorSnapshotTest
{
   private AuthentikQBitConfig config;
   private QInstance instance;
   private JSONObject user;
   private JSONObject role;
   private JSONObject team;

   /*******************************************************************************
    ** One scoped user inherits a role through a group. Another group member is
    ** outside the supplied user directory and must not become a mirror member.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws Exception
   {
      config = AuthentikTestSupport.unitConfig();
      instance = AuthentikTestSupport.produce(config);
      user = new JSONObject().put("pk", 1).put("username", "sam").put("type", "internal").put("path", "users/core")
         .put("is_active", true).put("email", " Sam@Example.Test ").put("groups", new JSONArray().put("team"))
         .put("attributes", new JSONObject().put("private", "user-private-value")).put("client_ip", "192.0.2.1");
      role = new JSONObject().put("pk", "role").put("name", "Viewer").put("parents", new JSONArray()).put("users", new JSONArray())
         .put("attributes", new JSONObject().put("qqq.io/permissions", new JSONArray().put("authentik.users.read"))
            .put("qqq.io/application-role", true).put("private", "group-private-value").put("qqq.io/unrecognized", "unknown-private-value"));
      team = new JSONObject().put("pk", "team").put("name", "Team").put("parents", new JSONArray().put("role"))
         .put("users", new JSONArray().put(1).put(999)).put("attributes", new JSONObject());
   }

   /*******************************************************************************
    ** Project via the production resolver and explicit field allowlists.
    *******************************************************************************/
   private AuthentikMirrorSnapshot snapshot()
   {
      return (AuthentikMirrorSnapshot.build(config, instance, List.of(user), List.of(role, team), Map.of(), Instant.parse("2026-11-04T12:00:00Z")));
   }

   /*******************************************************************************
    ** Role changes affect retained profiles even with no user timestamp change.
    ** Derived protection is recomputed, never persisted as a source attribute.
    *******************************************************************************/
   @Test
   void incrementalGraphChangesRevokeInheritedPermissionsAndProtection()
   {
      role.put("is_superuser", true);
      var baseline = snapshot();
      assertThat(baseline.users().getFirst().getValueBoolean("isProtected")).isTrue();
      role.put("is_superuser", false).put("attributes", new JSONObject());
      var merged = AuthentikMirrorSnapshot.incrementalUsers(config, baseline.users(), List.of(), List.of(role, team));
      var updated = AuthentikMirrorSnapshot.build(config, instance, merged, List.of(role, team), Map.of(), Instant.now());
      assertThat(updated.users()).hasSize(1);
      assertThat(updated.users().getFirst().getValueString("effectivePermissions")).isEqualTo("[]");
      assertThat(updated.users().getFirst().getValueBoolean("isProtected")).isFalse();
      assertThat(updated.users().getFirst().getValueBoolean("isSuperuser")).isFalse();
      assertThat(updated.users().getFirst().getValueString("username")).isEqualTo("sam");
   }

   /*******************************************************************************
    ** Local scope exits become preflight candidates; newly changed API users
    ** still have to satisfy scope. Missing baseline source facts force a full run.
    *******************************************************************************/
   @Test
   void incrementalMergePreservesSourceProtectionAndRejectsIncompleteBaseline()
   {
      user.getJSONObject("attributes").put("qqq.io/protected", true);
      var baseline = snapshot();
      team.put("users", new JSONArray());
      var merged = AuthentikMirrorSnapshot.incrementalUsers(config, baseline.users(), List.of(), List.of(role, team));
      var updated = AuthentikMirrorSnapshot.build(config, instance, merged, List.of(role, team), Map.of(), Instant.now());
      assertThat(updated.users().getFirst().getValueBoolean("isProtected")).isTrue();
      assertThat(updated.memberships()).isEmpty();
      config.withUserScopeGroupNames(List.of("Team"));
      assertThat(AuthentikMirrorSnapshot.incrementalUsers(config, baseline.users(), List.of(), List.of(role, team))).isEmpty();
      assertThatThrownBy(() -> AuthentikMirrorSnapshot.incrementalUsers(config, baseline.users(), List.of(user), List.of(role, team)))
         .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("out-of-scope");
      baseline.users().getFirst().setValue("sourceIsProtected", null);
      assertThatThrownBy(() -> AuthentikMirrorSnapshot.incrementalUsers(config, baseline.users(), List.of(), List.of(role, team)))
         .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("full refresh");
   }

   /*******************************************************************************
    ** Inheritance, normalized identity, privacy and unknown metrics are retained.
    *******************************************************************************/
   @Test
   void producesScopedPrivateProjectionWithInheritedPermissions()
   {
      var snapshot = snapshot();
      assertThat(snapshot.users()).hasSize(1);
      var row = snapshot.users().get(0);
      assertThat(row.getValue("email")).isEqualTo("sam@example.test");
      assertThat(row.getValue("effectivePermissions")).isEqualTo("[\"authentik.users.read.hasAccess\"]");
      assertThat(row.getValue("mfaDeviceCount")).isNull();
      assertThat(row.getValue("failedLogins24h")).isNull();
      assertThat(row.getValues()).doesNotContainKeys("attributes", "client_ip", "user_agent");
      assertThat(snapshot.memberships()).hasSize(1);
      assertThat(snapshot.memberships().get(0).getValue("userPk")).isEqualTo(1);
      assertThat(snapshot.groups().get(0).getValueString("attributes"))
         .contains("qqq.io/permissions", "qqq.io/application-role").doesNotContain("private-value", "unrecognized");
   }

   /*******************************************************************************
    ** Ambiguous identity or a changing membership view is not a usable refresh.
    *******************************************************************************/
   @Test
   void rejectsAmbiguousIdentitiesAndInconsistentMemberships()
   {
      JSONObject duplicate = new JSONObject(user.toString()).put("pk", 2).put("username", "other").put("email", "sam@example.test");
      assertThatThrownBy(() -> AuthentikMirrorSnapshot.build(config, instance, List.of(user, duplicate), List.of(role, team), Map.of(), Instant.now()))
         .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("ambiguous");
      user.put("groups", new JSONArray());
      assertThatThrownBy(this::snapshot).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("membership changed");
      user.remove("groups");
      assertThatThrownBy(this::snapshot).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("missing membership");
      team.put("parents", new JSONArray().put("missing"));
      assertThatThrownBy(this::snapshot).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("unresolved parent");
   }

   /*******************************************************************************
    ** Revocation creates a new projection; inactive users get no dynamic grant.
    *******************************************************************************/
   @Test
   void refreshReflectsRevocationDeactivationAndInheritedProtection()
   {
      var old = snapshot();
      role.getJSONObject("attributes").put("qqq.io/permissions", new JSONArray());
      assertThat(snapshot().users().get(0).getValue("effectivePermissions")).isEqualTo("[]");
      assertThat(old.users().get(0).getValueString("effectivePermissions")).contains("authentik.users.read");
      role.getJSONObject("attributes").put("qqq.io/permissions", new JSONArray().put("authentik.users.read"));
      role.put("is_superuser", true);
      user.put("is_active", false).put("email", " ");
      var row = snapshot().users().get(0);
      assertThat(row.getValue("effectivePermissions")).isEqualTo("[]");
      assertThat(row.getValue("isProtected")).isEqualTo(true);
      assertThat(row.getValue("isSuperuser")).isEqualTo(true);
      assertThat(row.getValue("email")).isNull();
   }
}
