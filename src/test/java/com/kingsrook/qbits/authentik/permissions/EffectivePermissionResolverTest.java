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

package com.kingsrook.qbits.authentik.permissions;


import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Tests for GroupGraph and EffectivePermissionResolver.
 *******************************************************************************/
class EffectivePermissionResolverTest
{

   /*******************************************************************************
    ** admins (superuser) <- under-admins; identity-admins <- editors <- interns;
    ** publishers (string attribute); a cycle a <-> b.
    *******************************************************************************/
   private static GroupGraph graph()
   {
      return (GroupGraph.fromGroups(List.of(
         group("admins", "authentik Admins", true, List.of(), null, null, List.of(1)),
         group("under", "under-admins", false, List.of("admins"), List.of("cms.publish"), null, List.of(2)),
         group("ida", "identity-admins", false, List.of(), List.of("authentik.*"), List.of("kof22-website-prod"), List.of(3)),
         group("editors", "editors", false, List.of("ida"), List.of("cms.edit", "cms.*"), null, List.of(4)),
         group("interns", "interns", false, List.of("editors"), List.of("authentik.users.read", "nope.unknown"), null, List.of(5)),
         new JSONObject().put("pk", "pub").put("name", "publishers").put("is_superuser", false).put("parents", new JSONArray())
            .put("attributes", new JSONObject().put("qqq.io/permissions", "cms.publish").put("qqq.io/app-access", "kof22-website-prod")).put("users", new JSONArray().put(6)),
         group("a", "cycle-a", false, List.of("b"), List.of("cms.edit"), null, List.of()),
         group("b", "cycle-b", false, List.of("a"), List.of(), null, List.of(7)))));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static JSONObject group(String pk, String name, boolean superuser, List<String> parents, List<String> permissions, List<String> appAccess, List<Integer> users)
   {
      JSONObject attributes = new JSONObject();
      if(permissions != null)
      {
         attributes.put("qqq.io/permissions", new JSONArray(permissions));
      }
      if(appAccess != null)
      {
         attributes.put("qqq.io/app-access", new JSONArray(appAccess));
      }
      return (new JSONObject().put("pk", pk).put("name", name).put("is_superuser", superuser).put("parents", new JSONArray(parents))
         .put("attributes", attributes).put("users", new JSONArray(users)));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static final Set<String> CATALOG = Set.of("cms.publish", "cms.edit", "cms.delete", "adminEsb.hasAccess");



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void ancestryAndInheritedSuperuser()
   {
      GroupGraph graph = graph();
      assertThat(graph.ancestorPks("interns")).containsExactly("editors", "ida");
      assertThat(graph.isSuperuserInherited("under")).isTrue();
      assertThat(graph.isSuperuserInherited("admins")).isTrue();
      assertThat(graph.isSuperuserInherited("interns")).isFalse();
      assertThat(graph.ancestorPks("a")).containsExactly("b");
      assertThat(graph.ancestorPks("unknown")).isEmpty();
      assertThat(graph.byName("editors").pk()).isEqualTo("editors");
      assertThat(graph.groupsOfUser(4)).containsExactly("editors");
   }



   /*******************************************************************************
    ** Inheritance, wildcards, identity names, unknown names, the catalog.
    *******************************************************************************/
   @Test
   void resolvesWithInheritanceAndWildcards()
   {
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph(), CATALOG);

      EffectivePermissionResolver.Resolution interns = resolver.resolveUser(5);
      for(IdentityPermission permission : IdentityPermission.values())
      {
         assertThat(interns.sessionPermissions()).contains(permission.getSessionPermission());
      }
      assertThat(interns.sessionPermissions()).contains("cms.edit", "cms.publish", "cms.delete").doesNotContain("adminEsb.hasAccess", "nope.unknown");
      assertThat(interns.unknown()).containsExactly("nope.unknown");
      assertThat(interns.grantedBy().get("cms.delete")).containsExactly("editors");
      assertThat(interns.grantedBy().get(IdentityPermission.USERS_READ.getSessionPermission())).containsExactlyInAnyOrder("identity-admins", "interns");
      assertThat(interns.appAccess()).containsExactly("kof22-website-prod");

      assertThat(EffectivePermissionResolver.holdsAll(interns, List.of(IdentityPermission.MEMBERSHIPS_MANAGE, IdentityPermission.PERMISSIONS_MANAGE))).isTrue();
      assertThat(EffectivePermissionResolver.holdsAll(resolver.resolveUser(6), List.of(IdentityPermission.USERS_READ))).isFalse();
   }



   /*******************************************************************************
    ** Pre-rename identity.* grants (owner naming rule, 2026-10-12) are reported
    ** as unknown and grant nothing until the group attribute is updated.
    *******************************************************************************/
   @Test
   @SuppressWarnings("deprecation")
   void legacyIdentityNamesAreUnknown()
   {
      GroupGraph graph = GroupGraph.fromGroups(List.of(
         group("old", "identity-admins", false, List.of(), List.of(IdentityPermission.LEGACY_WILDCARD, IdentityPermission.USERS_READ.getLegacyShortName()), null, List.of(9))));

      EffectivePermissionResolver.Resolution old = new EffectivePermissionResolver(graph, CATALOG).resolveUser(9);
      assertThat(old.sessionPermissions()).isEmpty();
      assertThat(old.unknown()).containsExactlyInAnyOrder("identity.*", "identity.users.read");
      assertThat(EffectivePermissionResolver.holdsAll(old, List.of(IdentityPermission.USERS_READ))).isFalse();
   }



   /*******************************************************************************
    ** A single string attribute is a list of one; cycles terminate.
    *******************************************************************************/
   @Test
   void stringAttributesAndCycles()
   {
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph(), CATALOG);
      assertThat(resolver.resolveUser(6).sessionPermissions()).containsExactly("cms.publish");
      assertThat(resolver.resolveUser(6).appAccess()).containsExactly("kof22-website-prod");
      assertThat(resolver.resolveUser(7).sessionPermissions()).containsExactly("cms.edit");
      assertThat(resolver.resolveUser(99).sessionPermissions()).isEmpty();
   }



   /*******************************************************************************
    ** Without a catalog: names pass through, but wildcards are never granted
    ** literally.
    *******************************************************************************/
   @Test
   void withoutCatalog()
   {
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph(), null);
      assertThat(resolver.expand("anything.goes")).containsExactly("anything.goes");
      assertThat(resolver.expand("cms.*")).isEmpty();
      assertThat(resolver.expand(" authentik.audit.read ")).containsExactly(IdentityPermission.AUDIT_READ.getSessionPermission());
      assertThat(resolver.expand("authentik.audit.read.hasAccess")).containsExactly(IdentityPermission.AUDIT_READ.getSessionPermission());
      assertThat(resolver.expand("")).isEmpty();
      assertThat(resolver.expand(null)).isEmpty();
   }

}
