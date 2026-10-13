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


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.client.AuthentikJson;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** The pure rules of DESIGN.md section 5.4, separated from I/O so they can be
 ** tested exhaustively: the subset (no escalation) rule, last-admin
 ** protection, descendant checks and group fingerprints.
 *******************************************************************************/
public final class AuthentikSafety
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikSafety()
   {
   }



   /*******************************************************************************
    ** What a user is, for last-admin protection.
    **
    ** @param pk        Authentik user pk
    ** @param active    whether the account is active
    ** @param human     internal or external (not a service account)
    ** @param protectedAccount break-glass, superuser, service account
    *******************************************************************************/
   public record UserFacts(int pk, boolean active, boolean human, boolean protectedAccount)
   {
   }



   /*******************************************************************************
    ** The permissions in needed that held does not contain (the subset rule:
    ** an operator may only grant what they hold).
    *******************************************************************************/
   public static Set<String> missing(Collection<String> needed, Collection<String> held)
   {
      Set<String> rs = new TreeSet<>(needed);
      rs.removeAll(held);
      return (rs);
   }



   /*******************************************************************************
    ** pks of the users who qualify as identity administrators in a graph: active,
    ** human, not protected, and holding both authentik.memberships.manage and
    ** authentik.permissions.manage through their groups (inherited included).
    *******************************************************************************/
   public static Set<Integer> qualifyingAdmins(GroupGraph graph, EffectivePermissionResolver resolver, Collection<UserFacts> users)
   {
      Set<Integer> rs = new LinkedHashSet<>();
      for(UserFacts user : users)
      {
         if(!user.active() || !user.human() || user.protectedAccount())
         {
            continue;
         }
         EffectivePermissionResolver.Resolution resolution = resolver.resolveGroups(graph.groupsOfUser(user.pk()));
         if(EffectivePermissionResolver.holdsAll(resolution, List.of(IdentityPermission.MEMBERSHIPS_MANAGE, IdentityPermission.PERMISSIONS_MANAGE)))
         {
            rs.add(user.pk());
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** Whether a change leaves the qbit without an administrator that it had
    ** before: some admin existed, and none does after. A state that already had
    ** none (for example a bootstrap window) is not made worse, so it never
    ** blocks.
    *******************************************************************************/
   public static boolean removesLastAdmin(Set<Integer> before, Set<Integer> after)
   {
      return (!before.isEmpty() && after.isEmpty());
   }



   /*******************************************************************************
    ** A copy of a graph with some nodes replaced (matched by pk), for
    ** simulating a change.
    *******************************************************************************/
   public static GroupGraph withNodes(GroupGraph graph, GroupGraph.Node... replacements)
   {
      GroupGraph copy = new GroupGraph();
      graph.nodes().forEach(copy::add);
      for(GroupGraph.Node node : replacements)
      {
         copy.add(node);
      }
      return (copy);
   }



   /*******************************************************************************
    ** A node without a member.
    *******************************************************************************/
   public static GroupGraph.Node withoutMember(GroupGraph.Node node, int userPk)
   {
      List<Integer> members = new ArrayList<>(node.memberPks());
      members.remove(Integer.valueOf(userPk));
      return (new GroupGraph.Node(node.pk(), node.name(), node.ownSuperuser(), node.parentPks(), node.permissions(), node.appAccess(), members, node.malformed(), node.policyPermissions()));
   }



   /*******************************************************************************
    ** A node with other permissions and app access.
    *******************************************************************************/
   public static GroupGraph.Node withPermissions(GroupGraph.Node node, List<String> permissions, List<String> appAccess)
   {
      return (new GroupGraph.Node(node.pk(), node.name(), node.ownSuperuser(), node.parentPks(), permissions, appAccess, node.memberPks(), node.malformed(), node.policyPermissions()));
   }



   /*******************************************************************************
    ** A node with other parents.
    *******************************************************************************/
   public static GroupGraph.Node withParents(GroupGraph.Node node, List<String> parentPks)
   {
      return (new GroupGraph.Node(node.pk(), node.name(), node.ownSuperuser(), parentPks, node.permissions(), node.appAccess(), node.memberPks(), node.malformed(), node.policyPermissions()));
   }



   /*******************************************************************************
    ** Every group below a group (children, their children, ...), cycle-safe.
    *******************************************************************************/
   public static Set<String> descendantPks(GroupGraph graph, String pk)
   {
      Set<String> rs = new HashSet<>();
      for(GroupGraph.Node node : graph.nodes())
      {
         if(!node.pk().equals(pk) && graph.ancestorPks(node.pk()).contains(pk))
         {
            rs.add(node.pk());
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** Split free text (new lines or commas) into distinct trimmed entries.
    *******************************************************************************/
   public static List<String> parseList(String text)
   {
      List<String> rs = new ArrayList<>();
      if(text == null)
      {
         return (rs);
      }
      for(String part : text.split("[\\r\\n,;]+"))
      {
         String trimmed = part.trim();
         if(!trimmed.isEmpty() && !rs.contains(trimmed))
         {
            rs.add(trimmed);
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** A short fingerprint of a group's editable state: name, parents,
    ** qqq.io/* attributes and member count. Authentik groups have no
    ** last_updated (DESIGN.md section 0.2 vi), so this is how a change made in
    ** the Authentik UI after a preview is noticed.
    *******************************************************************************/
   public static String groupFingerprint(JSONObject group)
   {
      JSONObject         attributes = group.optJSONObject("attributes");
      Map<String, Object> qqq        = new java.util.TreeMap<>();
      if(attributes != null)
      {
         for(String key : attributes.keySet())
         {
            if(key.startsWith(AuthentikJson.QQQ_ATTRIBUTE_PREFIX))
            {
               qqq.put(key, String.valueOf(attributes.get(key)));
            }
         }
      }

      List<String> parents = new ArrayList<>();
      JSONArray    array   = group.optJSONArray("parents");
      for(int i = 0; array != null && i < array.length(); i++)
      {
         Object value = array.get(i);
         parents.add(value instanceof JSONObject object ? object.optString("pk") : String.valueOf(value));
      }
      java.util.Collections.sort(parents);

      int members = group.optJSONArray("users") == null ? -1 : group.getJSONArray("users").length();
      return (sha(group.optString("name") + "|" + parents + "|" + qqq + "|" + members));
   }



   /*******************************************************************************
    ** A short fingerprint of a user's editable state (name, email, path, type,
    ** active, last_updated).
    *******************************************************************************/
   public static String userFingerprint(JSONObject user)
   {
      return (sha(user.optString("username") + "|" + user.optString("name") + "|" + user.optString("email") + "|" + user.optString("path") + "|"
         + user.optString("type") + "|" + user.optBoolean("is_active", true) + "|" + user.optString("last_updated")));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String sha(String text)
   {
      try
      {
         byte[]        digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
         StringBuilder hex    = new StringBuilder();
         for(int i = 0; i < 8; i++)
         {
            hex.append(String.format("%02x", digest[i]));
         }
         return (hex.toString());
      }
      catch(NoSuchAlgorithmException e)
      {
         throw (new IllegalStateException(e));
      }
   }

}
