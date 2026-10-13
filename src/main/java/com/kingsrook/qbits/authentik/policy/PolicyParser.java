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


import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import static com.kingsrook.qqq.backend.core.logging.LogUtils.logPair;


/*******************************************************************************
 ** Parses a policy document (docs/POLICY-FORMAT.md) into QQQ permission names.
 **
 ** parse() FAILS CLOSED: any problem (unknown spec, unsupported version, a
 ** statement that is not Allow, an unknown action, a bad resource, malformed
 ** JSON, ...) grants zero permissions and logs a warning. parseStrict() throws
 ** a PolicyParseException naming the problem instead (for the editor).
 *******************************************************************************/
public final class PolicyParser
{
   private static final QLogger LOG = QLogger.getLogger(PolicyParser.class);

   /** A valid resource: a QQQ permission base name. */
   public static final Pattern RESOURCE_PATTERN = Pattern.compile("[A-Za-z0-9_]+");

   /** The only effect in 1.0.0. */
   public static final String ALLOW = "Allow";



   /*******************************************************************************
    ** The result of a successful parse.
    **
    ** @param permissions QQQ permission names ({resource}.{action}), sorted
    ** @param resources   every resource named, in document order
    *******************************************************************************/
   public record Parsed(Set<String> permissions, Set<String> resources)
   {
   }



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private PolicyParser()
   {
   }



   /*******************************************************************************
    ** The permissions a document grants, or none (with a warning) when it is
    ** missing or invalid in any way.
    **
    ** @param document a JSONObject, a Map, or a JSON string (as stored in a group
    **                 attribute or a token claim); null grants nothing
    *******************************************************************************/
   public static Set<String> parse(Object document, PolicyFormat format)
   {
      return (parse(document, format, null));
   }



   /*******************************************************************************
    ** Parse with the catalog of explicitly grantable table features; an invalid
    ** document still grants nothing.
    *******************************************************************************/
   public static Set<String> parse(Object document, PolicyFormat format, PolicyCatalog catalog)
   {
      if(document == null || JSONObject.NULL.equals(document))
      {
         return (Collections.emptySet());
      }
      try
      {
         return (parseStrict(document, format, catalog).permissions());
      }
      catch(PolicyParseException e)
      {
         LOG.warn("Policy document rejected; it grants no permissions", logPair("reason", e.getMessage()));
         return (Collections.emptySet());
      }
   }



   /*******************************************************************************
    ** Parse, throwing a PolicyParseException that names the first problem.
    *******************************************************************************/
   public static Parsed parseStrict(Object document, PolicyFormat format) throws PolicyParseException
   {
      return (parseStrict(document, format, null));
   }



   /*******************************************************************************
    ** Parse standard actions and features registered for every listed resource.
    ** Without a catalog only the five standard actions are accepted.
    *******************************************************************************/
   public static Parsed parseStrict(Object document, PolicyFormat format, PolicyCatalog catalog) throws PolicyParseException
   {
      JSONObject json = asObject(document);
      PolicyFormat f = format == null ? PolicyFormat.DEFAULT : format;

      Object spec = json.opt("PolicySpec");
      if(!(spec instanceof String s) || !s.equals(f.spec()))
      {
         throw (new PolicyParseException("PolicySpec must be \"" + f.spec() + "\" (found " + describe(spec) + ")"));
      }
      Object version = json.opt("PolicyVersion");
      if(!(version instanceof String v) || !v.equals(f.version()))
      {
         throw (new PolicyParseException("PolicyVersion must be \"" + f.version() + "\" (found " + describe(version) + ")"));
      }

      Set<String> permissions = new TreeSet<>();
      Set<String> resources   = new LinkedHashSet<>();
      Object      statements  = json.opt("Statement");
      if(statements == null)
      {
         return (new Parsed(permissions, resources));
      }
      if(!(statements instanceof JSONArray array))
      {
         throw (new PolicyParseException("Statement must be an array"));
      }

      for(int i = 0; i < array.length(); i++)
      {
         if(!(array.opt(i) instanceof JSONObject statement))
         {
            throw (new PolicyParseException("Statement " + (i + 1) + " must be an object"));
         }
         Object effect = statement.opt("Effect");
         if(!ALLOW.equals(effect))
         {
            throw (new PolicyParseException("Statement " + (i + 1) + ": Effect must be \"Allow\" (found " + describe(effect) + "); Deny is not supported yet"));
         }

         Set<String> statementResources = strings(statement.opt("Resource"), "Statement " + (i + 1) + ": Resource");
         Set<String> actions = new LinkedHashSet<>();
         for(String name : strings(statement.opt("Action"), "Statement " + (i + 1) + ": Action"))
         {
            if(PolicyAction.WILDCARD.equals(name))
            {
               for(PolicyAction action : PolicyAction.values())
               {
                  actions.add(action.getJsonName());
               }
            }
            else
            {
               if(PolicyAction.fromJsonName(name).isEmpty()
                  && (catalog == null || statementResources.isEmpty() || !statementResources.stream().allMatch(resource -> catalog.hasFeature(resource, name))))
               {
                  throw (new PolicyParseException("Statement " + (i + 1) + ": unknown action \"" + name + "\""));
               }
               actions.add(name);
            }
         }

         for(String resource : statementResources)
         {
            if(!RESOURCE_PATTERN.matcher(resource).matches())
            {
               throw (new PolicyParseException("Statement " + (i + 1) + ": resource \"" + resource + "\" must match [A-Za-z0-9_]+"));
            }
            resources.add(resource);
            for(String action : actions)
            {
               permissions.add(resource + "." + action);
            }
         }
      }
      return (new Parsed(permissions, resources));
   }



   /*******************************************************************************
    ** The document as a JSON object.
    *******************************************************************************/
   static JSONObject asObject(Object document) throws PolicyParseException
   {
      if(document instanceof JSONObject object)
      {
         return (object);
      }
      if(document instanceof Map<?, ?> map)
      {
         return (new JSONObject(map));
      }
      if(document instanceof String text)
      {
         if(text.isBlank())
         {
            throw (new PolicyParseException("The document is empty"));
         }
         try
         {
            return (new JSONObject(text));
         }
         catch(JSONException e)
         {
            throw (new PolicyParseException("The document is not a JSON object"));
         }
      }
      throw (new PolicyParseException("The document is not a JSON object"));
   }



   /*******************************************************************************
    ** An array of strings, or a PolicyParseException.
    *******************************************************************************/
   private static Set<String> strings(Object value, String what) throws PolicyParseException
   {
      if(!(value instanceof JSONArray array))
      {
         throw (new PolicyParseException(what + " must be an array of strings"));
      }
      Set<String> rs = new LinkedHashSet<>();
      for(int i = 0; i < array.length(); i++)
      {
         if(!(array.opt(i) instanceof String text))
         {
            throw (new PolicyParseException(what + " must be an array of strings"));
         }
         rs.add(text);
      }
      return (rs);
   }



   /*******************************************************************************
    ** A short description of a found value for messages (never the whole value).
    *******************************************************************************/
   private static String describe(Object value)
   {
      if(value == null)
      {
         return ("nothing");
      }
      if(value instanceof String text)
      {
         return ("\"" + (text.length() > 40 ? text.substring(0, 40) + "..." : text) + "\"");
      }
      return (value.getClass().getSimpleName());
   }
}
