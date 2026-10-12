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

package com.kingsrook.qbits.authentik.client;


import java.io.Serializable;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Function;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** Null-safe readers for Authentik JSON objects, used as field extractors.
 *******************************************************************************/
public final class AuthentikJson
{
   /** Attribute-key prefix the qbit owns (DESIGN.md section 5.2). */
   public static final String QQQ_ATTRIBUTE_PREFIX = "qqq.io/";

   public static final String ATTR_PERMISSIONS = "qqq.io/permissions";
   public static final String ATTR_APP_ACCESS  = "qqq.io/app-access";
   public static final String ATTR_PROTECTED   = "qqq.io/protected";



   /*******************************************************************************
    ** Not instantiable.
    *******************************************************************************/
   private AuthentikJson()
   {
   }



   /*******************************************************************************
    ** String value, or null.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> string(String key)
   {
      return (o -> o.has(key) && !o.isNull(key) ? String.valueOf(o.get(key)) : null);
   }



   /*******************************************************************************
    ** Integer value, or null.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> integer(String key)
   {
      return (o -> o.has(key) && !o.isNull(key) ? o.getInt(key) : null);
   }



   /*******************************************************************************
    ** Boolean value, or null.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> bool(String key)
   {
      return (o -> o.has(key) && !o.isNull(key) ? o.getBoolean(key) : null);
   }



   /*******************************************************************************
    ** ISO-8601 date-time as an Instant, or null.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> instant(String key)
   {
      return (o -> parseInstant(o.has(key) && !o.isNull(key) ? o.getString(key) : null));
   }



   /*******************************************************************************
    ** A nested object (or array) rendered as JSON text, or null.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> json(String key)
   {
      return (o -> o.has(key) && !o.isNull(key) ? o.get(key).toString() : null);
   }



   /*******************************************************************************
    ** A value at a nested path (e.g. "user", "username"), as a string, or null.
    ** Objects and arrays are rendered as JSON text.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> at(String... path)
   {
      return (o ->
      {
         Object current = o;
         for(String key : path)
         {
            if(!(current instanceof JSONObject object) || !object.has(key) || object.isNull(key))
            {
               return (null);
            }
            current = object.get(key);
         }
         return (String.valueOf(current));
      });
   }



   /*******************************************************************************
    ** An integer at a nested path, or null.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> intAt(String... path)
   {
      Function<JSONObject, Serializable> text = at(path);
      return (o ->
      {
         Serializable value = text.apply(o);
         try
         {
            return (value == null ? null : Integer.valueOf(String.valueOf(value)));
         }
         catch(NumberFormatException e)
         {
            return (null);
         }
      });
   }



   /*******************************************************************************
    ** Length of an array value, or null.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> arrayLength(String key)
   {
      return (o -> o.optJSONArray(key) == null ? null : o.getJSONArray(key).length());
   }



   /*******************************************************************************
    ** Comma-joined values of a property across an array of objects, e.g. the
    ** names in groups_obj. Null when the array is absent.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> joined(String arrayKey, String property)
   {
      return (o ->
      {
         JSONArray array = o.optJSONArray(arrayKey);
         if(array == null)
         {
            return (null);
         }
         List<String> values = new ArrayList<>();
         for(int i = 0; i < array.length(); i++)
         {
            Object element = array.get(i);
            if(element instanceof JSONObject object && object.has(property) && !object.isNull(property))
            {
               values.add(String.valueOf(object.get(property)));
            }
            else if(!(element instanceof JSONObject) && property == null)
            {
               values.add(String.valueOf(element));
            }
         }
         return (String.join(", ", values));
      });
   }



   /*******************************************************************************
    ** Comma-joined values of a string array inside "attributes", e.g.
    ** qqq.io/permissions. Null when absent.
    *******************************************************************************/
   public static Function<JSONObject, Serializable> attributeList(String attributeKey)
   {
      return (o ->
      {
         List<String> values = stringList(o.optJSONObject("attributes"), attributeKey);
         return (values == null ? null : String.join(", ", values));
      });
   }



   /*******************************************************************************
    ** Only the qqq.io/* attribute keys, as JSON text (non-sensitive view).
    *******************************************************************************/
   public static Function<JSONObject, Serializable> qqqAttributes()
   {
      return (o ->
      {
         JSONObject attributes = o.optJSONObject("attributes");
         if(attributes == null)
         {
            return (null);
         }
         JSONObject       rs   = new JSONObject();
         Iterator<String> keys = attributes.keys();
         while(keys.hasNext())
         {
            String key = keys.next();
            if(key.startsWith(QQQ_ATTRIBUTE_PREFIX))
            {
               rs.put(key, attributes.get(key));
            }
         }
         return (rs.isEmpty() ? null : rs.toString());
      });
   }



   /*******************************************************************************
    ** Read a list of strings from an object property; null when absent, and
    ** non-string elements are skipped. A single string is treated as a list of
    ** one (Authentik attributes are free-form JSON).
    *******************************************************************************/
   public static List<String> stringList(JSONObject object, String key)
   {
      if(object == null || !object.has(key) || object.isNull(key))
      {
         return (null);
      }

      Object       value  = object.get(key);
      List<String> values = new ArrayList<>();
      if(value instanceof JSONArray array)
      {
         for(int i = 0; i < array.length(); i++)
         {
            if(array.get(i) instanceof String s && !s.isBlank())
            {
               values.add(s.trim());
            }
         }
      }
      else if(value instanceof String s && !s.isBlank())
      {
         values.add(s.trim());
      }
      return (values);
   }



   /*******************************************************************************
    ** Entries of a list attribute that stringList() drops: a value that is not a
    ** string or array, or non-string / blank array elements. Empty when fine.
    *******************************************************************************/
   public static List<String> malformedEntries(JSONObject object, String key)
   {
      List<String> rs = new ArrayList<>();
      if(object == null || !object.has(key) || object.isNull(key))
      {
         return (rs);
      }
      Object value = object.get(key);
      if(value instanceof JSONArray array)
      {
         for(int i = 0; i < array.length(); i++)
         {
            Object element = array.get(i);
            if(!(element instanceof String s) || s.isBlank())
            {
               rs.add(String.valueOf(element));
            }
         }
      }
      else if(!(value instanceof String))
      {
         rs.add(String.valueOf(value));
      }
      return (rs);
   }



   /*******************************************************************************
    ** Parse an Authentik timestamp (ISO-8601 with offset or Z).
    *******************************************************************************/
   public static Instant parseInstant(String value)
   {
      if(value == null || value.isBlank())
      {
         return (null);
      }
      return (OffsetDateTime.parse(value).toInstant());
   }

}
