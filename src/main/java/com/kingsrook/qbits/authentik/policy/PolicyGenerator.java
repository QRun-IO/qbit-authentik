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

package com.kingsrook.qbits.authentik.policy;


import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Builds the canonical policy document for a set of QQQ permissions
 ** (docs/POLICY-FORMAT.md, "Canonical form"): one Allow statement per granted
 ** action in the order hasAccess, read, insert, edit, delete, then features
 ** sorted by name; resources sorted;
 ** full access is a single Action/Resource "*" statement. Every document is checked to round-trip through
 ** PolicyParser to exactly the permissions it came from; one that does not is
 ** never returned.
 *******************************************************************************/
public final class PolicyGenerator
{

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private PolicyGenerator()
   {
   }



   /*******************************************************************************
    ** The canonical document for these permissions ({resource}.{action} names).
    **
    ** @throws PolicyParseException when a permission is not {resource}.{action}
    **         with a known action and a valid resource, or the document does not
    **         round-trip
    *******************************************************************************/
   public static JSONObject generate(Collection<String> permissions, PolicyFormat format) throws PolicyParseException
   {
      return (generate(permissions, format, null));
   }



   /*******************************************************************************
    ** Generate with the catalog of explicitly grantable table features.
    *******************************************************************************/
   public static JSONObject generate(Collection<String> permissions, PolicyFormat format, PolicyCatalog catalog) throws PolicyParseException
   {
      PolicyFormat f = format == null ? PolicyFormat.DEFAULT : format;
      if(permissions.contains(PolicyPermissions.FULL_ACCESS))
      {
         JSONObject document = new JSONObject().put("PolicySpec", f.spec()).put("PolicyVersion", f.version())
            .put("Statement", new JSONArray().put(new JSONObject().put("Effect", PolicyParser.ALLOW)
               .put("Action", new JSONArray().put("*")).put("Resource", new JSONArray().put("*"))));
         if(!PolicyParser.parseStrict(toCompact(document), f, catalog).permissions().equals(Set.of(PolicyPermissions.FULL_ACCESS)))
         {
            throw (new PolicyParseException("The full-access document does not round-trip"));
         }
         return (document);
      }

      Map<String, Set<String>> byAction = new LinkedHashMap<>();
      Map<String, Set<String>> byFeature = new TreeMap<>();
      for(PolicyAction action : PolicyAction.values())
      {
         byAction.put(action.getJsonName(), new TreeSet<>());
      }

      Set<String> expected = new TreeSet<>();
      for(String permission : permissions)
      {
         int dot = permission == null ? -1 : permission.lastIndexOf('.');
         if(dot <= 0 || dot == permission.length() - 1)
         {
            throw (new PolicyParseException("\"" + permission + "\" is not {resource}.{action}"));
         }
         String resource = permission.substring(0, dot);
         String name     = permission.substring(dot + 1);
         if(PolicyAction.fromJsonName(name).isEmpty() && (catalog == null || !catalog.hasFeature(resource, name)))
         {
            throw (new PolicyParseException("\"" + permission + "\": unknown action \"" + name + "\""));
         }
         if(!PolicyParser.RESOURCE_PATTERN.matcher(resource).matches())
         {
            throw (new PolicyParseException("\"" + permission + "\": resource must match [A-Za-z0-9_]+"));
         }
         Map<String, Set<String>> target = byAction.containsKey(name) ? byAction : byFeature;
         target.computeIfAbsent(name, key -> new TreeSet<>()).add(resource);
         expected.add(permission);
      }

      JSONArray statements = new JSONArray();
      byAction.putAll(byFeature);
      for(Map.Entry<String, Set<String>> entry : byAction.entrySet())
      {
         if(!entry.getValue().isEmpty())
         {
            statements.put(new JSONObject()
               .put("Effect", PolicyParser.ALLOW)
               .put("Action", new JSONArray().put(entry.getKey()))
               .put("Resource", new JSONArray(entry.getValue())));
         }
      }

      JSONObject document = new JSONObject()
         .put("PolicySpec", f.spec())
         .put("PolicyVersion", f.version())
         .put("Statement", statements);

      Set<String> parsed = PolicyParser.parseStrict(toCompact(document), f, catalog).permissions();
      if(!parsed.equals(expected))
      {
         Set<String> missing = new TreeSet<>(expected);
         missing.removeAll(parsed);
         Set<String> extra = new TreeSet<>(parsed);
         extra.removeAll(expected);
         throw (new PolicyParseException("The generated document does not round-trip. Missing: " + missing + "; unexpected: " + extra));
      }
      return (document);
   }



   /*******************************************************************************
    ** Re-generate any valid document in canonical form (parse, then generate).
    *******************************************************************************/
   public static JSONObject canonical(Object document, PolicyFormat format) throws PolicyParseException
   {
      return (canonical(document, format, null));
   }



   /*******************************************************************************
    ** Canonicalize a document using the registered table features.
    *******************************************************************************/
   public static JSONObject canonical(Object document, PolicyFormat format, PolicyCatalog catalog) throws PolicyParseException
   {
      return (generate(PolicyParser.parseStrict(document, format, catalog).permissions(), format, catalog));
   }



   /*******************************************************************************
    ** Compact JSON in a fixed key order (PolicySpec, PolicyVersion, Statement;
    ** Effect, Action, Resource), as stored in the group attribute.
    *******************************************************************************/
   public static String toCompact(JSONObject document)
   {
      return (write(document, false));
   }



   /*******************************************************************************
    ** Pretty JSON (2-space indent, LF, trailing newline) in the fixed key order.
    *******************************************************************************/
   public static String toPretty(JSONObject document)
   {
      return (write(document, true));
   }



   /*******************************************************************************
    ** Write in the fixed key order (org.json does not keep insertion order).
    *******************************************************************************/
   private static String write(JSONObject document, boolean pretty)
   {
      String nl  = pretty ? "\n" : "";
      String i1  = pretty ? "  " : "";
      String i2  = pretty ? "    " : "";
      String i3  = pretty ? "      " : "";
      String i4  = pretty ? "        " : "";
      String sep = pretty ? ": " : ":";

      StringBuilder sb = new StringBuilder("{").append(nl);
      sb.append(i1).append(JSONObject.quote("PolicySpec")).append(sep).append(JSONObject.quote(document.optString("PolicySpec"))).append(",").append(nl);
      sb.append(i1).append(JSONObject.quote("PolicyVersion")).append(sep).append(JSONObject.quote(document.optString("PolicyVersion"))).append(",").append(nl);
      sb.append(i1).append(JSONObject.quote("Statement")).append(sep).append("[");

      JSONArray statements = document.optJSONArray("Statement");
      int       count      = statements == null ? 0 : statements.length();
      for(int s = 0; s < count; s++)
      {
         JSONObject statement = statements.getJSONObject(s);
         sb.append(s == 0 ? nl : "," + nl).append(i2).append("{").append(nl);
         sb.append(i3).append(JSONObject.quote("Effect")).append(sep).append(JSONObject.quote(statement.optString("Effect"))).append(",").append(nl);
         sb.append(i3).append(JSONObject.quote("Action")).append(sep).append(inline(statement.optJSONArray("Action"), pretty)).append(",").append(nl);
         sb.append(i3).append(JSONObject.quote("Resource")).append(sep).append("[");
         JSONArray resources = statement.optJSONArray("Resource");
         int       n         = resources == null ? 0 : resources.length();
         for(int r = 0; r < n; r++)
         {
            sb.append(r == 0 ? nl : "," + nl).append(i4).append(JSONObject.quote(resources.optString(r)));
         }
         sb.append(n == 0 ? "" : nl + i3).append("]").append(nl);
         sb.append(i2).append("}");
      }
      sb.append(count == 0 ? "" : nl + i1).append("]").append(nl);
      sb.append("}").append(nl);
      return (sb.toString());
   }



   /*******************************************************************************
    ** A short string array on one line.
    *******************************************************************************/
   private static String inline(JSONArray array, boolean pretty)
   {
      StringBuilder sb = new StringBuilder("[");
      int           n  = array == null ? 0 : array.length();
      for(int i = 0; i < n; i++)
      {
         sb.append(i == 0 ? "" : (pretty ? ", " : ",")).append(JSONObject.quote(array.optString(i)));
      }
      return (sb.append("]").toString());
   }
}
