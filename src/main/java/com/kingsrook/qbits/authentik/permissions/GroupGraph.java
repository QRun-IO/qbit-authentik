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


import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.authentik.client.AuthentikJson;
import com.kingsrook.qbits.authentik.policy.PolicyFormat;
import com.kingsrook.qbits.authentik.policy.PolicyParseException;
import com.kingsrook.qbits.authentik.policy.PolicyParser;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Snapshot of Authentik's group hierarchy: groups by pk with their parents
 ** (many-to-many since 2025.12), own superuser flag, qqq.io/* attributes and
 ** member pks. Ancestry closures are computed on demand and cycle-safe.
 *******************************************************************************/
public class GroupGraph
{

   /*******************************************************************************
    ** One group.
    *******************************************************************************/
   public record Node(String pk, String name, boolean ownSuperuser, List<String> parentPks, List<String> permissions, List<String> appAccess, List<Integer> memberPks, List<String> malformed,
                      List<String> policyPermissions)
   {
      /*******************************************************************************
       ** A group without a policy document.
       *******************************************************************************/
      public Node(String pk, String name, boolean ownSuperuser, List<String> parentPks, List<String> permissions, List<String> appAccess, List<Integer> memberPks, List<String> malformed)
      {
         this(pk, name, ownSuperuser, parentPks, permissions, appAccess, memberPks, malformed, List.of());
      }
   }



   private final Map<String, Node>        byPk      = new LinkedHashMap<>();
   private final Map<String, Node>        byName    = new LinkedHashMap<>();
   private final Map<String, Set<String>> ancestors = new java.util.concurrent.ConcurrentHashMap<>();



   /*******************************************************************************
    ** Build from Authentik group objects (as returned by /core/groups/).
    *******************************************************************************/
   public static GroupGraph fromGroups(Collection<JSONObject> groups)
   {
      return (fromGroups(groups, PolicyFormat.DEFAULT));
   }



   /*******************************************************************************
    ** Build from Authentik group objects, reading each group's policy document
    ** (docs/POLICY-FORMAT.md) from the format's attribute. A document that does
    ** not parse grants nothing and is listed in the node's malformed entries.
    *******************************************************************************/
   public static GroupGraph fromGroups(Collection<JSONObject> groups, PolicyFormat format)
   {
      PolicyFormat f     = format == null ? PolicyFormat.DEFAULT : format;
      GroupGraph   graph = new GroupGraph();
      for(JSONObject group : groups)
      {
         JSONObject   attributes = group.optJSONObject("attributes");
         List<String> malformed  = malformed(attributes);
         List<String> policy     = policyPermissions(attributes, f, malformed);
         graph.add(new Node(
            group.getString("pk"),
            group.optString("name", ""),
            group.optBoolean("is_superuser", false),
            strings(group.optJSONArray("parents")),
            nonNull(AuthentikJson.stringList(group.optJSONObject("attributes"), AuthentikJson.ATTR_PERMISSIONS)),
            nonNull(AuthentikJson.stringList(group.optJSONObject("attributes"), AuthentikJson.ATTR_APP_ACCESS)),
            ints(group.optJSONArray("users")),
            malformed,
            policy));
      }
      return (graph);
   }



   /*******************************************************************************
    ** Add a node.
    *******************************************************************************/
   public GroupGraph add(Node node)
   {
      byPk.put(node.pk(), node);
      byName.put(node.name(), node);
      ancestors.clear();
      return (this);
   }



   /*******************************************************************************
    ** All groups.
    *******************************************************************************/
   public Collection<Node> nodes()
   {
      return (byPk.values());
   }



   /*******************************************************************************
    ** A group by pk, or null.
    *******************************************************************************/
   public Node byPk(String pk)
   {
      return (byPk.get(pk));
   }



   /*******************************************************************************
    ** A group by name, or null.
    *******************************************************************************/
   public Node byName(String name)
   {
      return (byName.get(name));
   }



   /*******************************************************************************
    ** All ancestors of a group (parents, their parents, ...), not including the
    ** group itself. Unknown parents are ignored; cycles terminate.
    *******************************************************************************/
   public Set<String> ancestorPks(String pk)
   {
      Set<String> cached = ancestors.get(pk);
      if(cached != null)
      {
         return (cached);
      }

      Set<String>   seen  = new LinkedHashSet<>();
      Deque<String> queue = new ArrayDeque<>();
      Node          start = byPk.get(pk);
      if(start != null)
      {
         queue.addAll(start.parentPks());
      }
      while(!queue.isEmpty())
      {
         String next = queue.removeFirst();
         if(next.equals(pk) || !seen.add(next))
         {
            continue;
         }
         Node parent = byPk.get(next);
         if(parent != null)
         {
            queue.addAll(parent.parentPks());
         }
      }
      Set<String> immutable = java.util.Collections.unmodifiableSet(seen);
      ancestors.put(pk, immutable);
      return (immutable);
   }



   /*******************************************************************************
    ** The group and all of its ancestors.
    *******************************************************************************/
   public List<Node> selfAndAncestors(String pk)
   {
      List<Node> rs   = new ArrayList<>();
      Node       self = byPk.get(pk);
      if(self != null)
      {
         rs.add(self);
      }
      for(String ancestor : ancestorPks(pk))
      {
         Node node = byPk.get(ancestor);
         if(node != null)
         {
            rs.add(node);
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** Whether a group grants superuser status, itself or through any ancestor
    ** (Authentik's User.all_groups() includes ancestors).
    *******************************************************************************/
   public boolean isSuperuserInherited(String pk)
   {
      return (selfAndAncestors(pk).stream().anyMatch(Node::ownSuperuser));
   }



   /*******************************************************************************
    ** pks of the groups a user is a direct member of.
    *******************************************************************************/
   public List<String> groupsOfUser(int userPk)
   {
      List<String> rs = new ArrayList<>();
      for(Node node : byPk.values())
      {
         if(node.memberPks().contains(userPk))
         {
            rs.add(node.pk());
         }
      }
      return (rs);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static List<String> strings(JSONArray array)
   {
      List<String> rs = new ArrayList<>();
      if(array != null)
      {
         for(int i = 0; i < array.length(); i++)
         {
            Object value = array.get(i);
            rs.add(value instanceof JSONObject object ? object.optString("pk") : String.valueOf(value));
         }
      }
      return (rs);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static List<Integer> ints(JSONArray array)
   {
      List<Integer> rs = new ArrayList<>();
      if(array != null)
      {
         for(int i = 0; i < array.length(); i++)
         {
            Object value = array.get(i);
            if(value instanceof Number number)
            {
               rs.add(number.intValue());
            }
            else if(value instanceof JSONObject object && object.has("pk"))
            {
               rs.add(object.getInt("pk"));
            }
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** The permissions of a group's policy document; none (and a malformed entry)
    ** when it does not parse.
    *******************************************************************************/
   private static List<String> policyPermissions(JSONObject attributes, PolicyFormat format, List<String> malformed)
   {
      Object document = attributes == null ? null : attributes.opt(format.attribute());
      if(document == null || JSONObject.NULL.equals(document) || "".equals(document))
      {
         return (List.of());
      }
      try
      {
         return (List.copyOf(PolicyParser.parseStrict(document, format).permissions()));
      }
      catch(PolicyParseException e)
      {
         malformed.add(format.attribute() + ": " + e.getMessage());
         return (List.of());
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static List<String> malformed(JSONObject attributes)
   {
      List<String> rs = new ArrayList<>();
      for(String key : List.of(AuthentikJson.ATTR_PERMISSIONS, AuthentikJson.ATTR_APP_ACCESS))
      {
         for(String bad : AuthentikJson.malformedEntries(attributes, key))
         {
            rs.add(key + ": " + bad);
         }
      }
      return (rs);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static List<String> nonNull(List<String> list)
   {
      return (list == null ? List.of() : list);
   }

}
