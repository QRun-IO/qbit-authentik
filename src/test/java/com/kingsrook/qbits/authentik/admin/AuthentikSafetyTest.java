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
import java.util.Set;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** The pure rules of DESIGN.md section 5.4.
 *******************************************************************************/
class AuthentikSafetyTest
{
   /*******************************************************************************
    **
    *******************************************************************************/
   private static GroupGraph.Node node(String pk, List<String> parents, List<String> permissions, List<Integer> members)
   {
      return (new GroupGraph.Node(pk, pk, false, parents, permissions, List.of(), members, List.of()));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void missingIsTheSubsetRule()
   {
      assertThat(AuthentikSafety.missing(Set.of("a", "b"), Set.of("a", "b", "c"))).isEmpty();
      assertThat(AuthentikSafety.missing(Set.of("a", "b"), Set.of("a"))).containsExactly("b");
      assertThat(AuthentikSafety.missing(Set.of(), Set.of())).isEmpty();
   }



   /*******************************************************************************
    ** Administrators are active, human, not protected, and hold both manage
    ** permissions, directly or through a parent group.
    *******************************************************************************/
   @Test
   void qualifyingAdmins()
   {
      GroupGraph graph = new GroupGraph()
         .add(node("admins", List.of(), List.of("authentik.*"), List.of(1, 2, 3, 4, 5)))
         .add(node("child", List.of("admins"), List.of(), List.of(6)))
         .add(node("readers", List.of(), List.of("authentik.users.read"), List.of(7)));
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph, null);

      Set<Integer> admins = AuthentikSafety.qualifyingAdmins(graph, resolver, List.of(
         new AuthentikSafety.UserFacts(1, true, true, false),
         new AuthentikSafety.UserFacts(2, false, true, false),
         new AuthentikSafety.UserFacts(3, true, false, false),
         new AuthentikSafety.UserFacts(4, true, true, true),
         new AuthentikSafety.UserFacts(5, true, true, false),
         new AuthentikSafety.UserFacts(6, true, true, false),
         new AuthentikSafety.UserFacts(7, true, true, false)));
      assertThat(admins).containsExactlyInAnyOrder(1, 5, 6);
   }



   /*******************************************************************************
    ** Last-admin: only a change that takes the last one away is refused; a
    ** state with none already is not blocked again.
    *******************************************************************************/
   @Test
   void removesLastAdmin()
   {
      assertThat(AuthentikSafety.removesLastAdmin(Set.of(1), Set.of())).isTrue();
      assertThat(AuthentikSafety.removesLastAdmin(Set.of(1, 2), Set.of(2))).isFalse();
      assertThat(AuthentikSafety.removesLastAdmin(Set.of(), Set.of())).isFalse();
   }



   /*******************************************************************************
    ** Simulations never change the original graph.
    *******************************************************************************/
   @Test
   void simulationsCopy()
   {
      GroupGraph original = new GroupGraph().add(node("g", List.of(), List.of("authentik.*"), List.of(1, 2)));
      GroupGraph.Node g = original.byPk("g");

      GroupGraph removed = AuthentikSafety.withNodes(original, AuthentikSafety.withoutMember(g, 1));
      assertThat(removed.byPk("g").memberPks()).containsExactly(2);
      assertThat(original.byPk("g").memberPks()).containsExactly(1, 2);

      GroupGraph stripped = AuthentikSafety.withNodes(original, AuthentikSafety.withPermissions(g, List.of(), List.of()));
      assertThat(stripped.byPk("g").permissions()).isEmpty();
      assertThat(original.byPk("g").permissions()).containsExactly("authentik.*");

      GroupGraph moved = AuthentikSafety.withNodes(original, AuthentikSafety.withParents(g, List.of("x")));
      assertThat(moved.byPk("g").parentPks()).containsExactly("x");
   }



   /*******************************************************************************
    ** Descendants include grandchildren and survive cycles.
    *******************************************************************************/
   @Test
   void descendants()
   {
      GroupGraph graph = new GroupGraph()
         .add(node("a", List.of(), List.of(), List.of()))
         .add(node("b", List.of("a"), List.of(), List.of()))
         .add(node("c", List.of("b"), List.of(), List.of()))
         .add(node("d", List.of(), List.of(), List.of()))
         .add(node("loop1", List.of("loop2"), List.of(), List.of()))
         .add(node("loop2", List.of("loop1"), List.of(), List.of()));
      assertThat(AuthentikSafety.descendantPks(graph, "a")).containsExactlyInAnyOrder("b", "c");
      assertThat(AuthentikSafety.descendantPks(graph, "d")).isEmpty();
      assertThat(AuthentikSafety.descendantPks(graph, "loop1")).containsExactly("loop2");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void parseList()
   {
      assertThat(AuthentikSafety.parseList("a\nb, c;d\r\n\n a ")).containsExactly("a", "b", "c", "d");
      assertThat(AuthentikSafety.parseList("")).isEmpty();
      assertThat(AuthentikSafety.parseList(null)).isEmpty();
   }



   /*******************************************************************************
    ** The group fingerprint tracks the editable state (name, parents, qqq.io
    ** attributes, member count) and ignores everything else.
    *******************************************************************************/
   @Test
   void groupFingerprint()
   {
      JSONObject base = new JSONObject().put("name", "g").put("parents", new JSONArray(List.of("p"))).put("users", new JSONArray(List.of(1)))
         .put("attributes", new JSONObject().put("qqq.io/permissions", new JSONArray(List.of("a"))).put("other", "x"));
      String fingerprint = AuthentikSafety.groupFingerprint(base);

      assertThat(AuthentikSafety.groupFingerprint(new JSONObject(base.toString()).put("pk", "ignored"))).isEqualTo(fingerprint);
      assertThat(AuthentikSafety.groupFingerprint(new JSONObject(base.toString()).put("attributes", base.getJSONObject("attributes").put("other", "changed")))).isEqualTo(fingerprint);
      assertThat(AuthentikSafety.groupFingerprint(new JSONObject(base.toString()).put("name", "h"))).isNotEqualTo(fingerprint);
      assertThat(AuthentikSafety.groupFingerprint(new JSONObject(base.toString()).put("users", new JSONArray(List.of(1, 2))))).isNotEqualTo(fingerprint);
      assertThat(AuthentikSafety.groupFingerprint(new JSONObject(base.toString()).put("parents", new JSONArray()))).isNotEqualTo(fingerprint);
      assertThat(AuthentikSafety.groupFingerprint(new JSONObject(base.toString()).put("attributes",
         new JSONObject().put("qqq.io/permissions", new JSONArray(List.of("b")))))).isNotEqualTo(fingerprint);
   }



   /*******************************************************************************
    ** The user fingerprint changes with any editable field or with last_updated.
    *******************************************************************************/
   @Test
   void userFingerprint()
   {
      JSONObject user = new JSONObject().put("username", "u").put("name", "N").put("email", "e@x.test").put("path", "users").put("type", "internal")
         .put("is_active", true).put("last_updated", "2026-10-01T00:00:00Z");
      String fingerprint = AuthentikSafety.userFingerprint(user);
      assertThat(AuthentikSafety.userFingerprint(new JSONObject(user.toString()))).isEqualTo(fingerprint);
      assertThat(AuthentikSafety.userFingerprint(new JSONObject(user.toString()).put("name", "M"))).isNotEqualTo(fingerprint);
      assertThat(AuthentikSafety.userFingerprint(new JSONObject(user.toString()).put("is_active", false))).isNotEqualTo(fingerprint);
      assertThat(AuthentikSafety.userFingerprint(new JSONObject(user.toString()).put("last_updated", "2026-10-02T00:00:00Z"))).isNotEqualTo(fingerprint);
   }

}
