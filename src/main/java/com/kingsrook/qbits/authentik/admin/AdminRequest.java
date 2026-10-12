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


import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONObject;


/*******************************************************************************
 ** One requested change: the action, its target key (a user pk, a group uuid,
 ** "groupPk:userPk" for memberships, an invitation uuid, or blank when
 ** creating), its parameters, and the operator's reason. Serializable to JSON
 ** so a two-person request can be stored and applied later.
 **
 ** @param action    what to do
 ** @param targetKey the target (see above)
 ** @param params    action parameters (strings and booleans)
 ** @param reason    why (required for every write)
 *******************************************************************************/
public record AdminRequest(AdminAction action, String targetKey, Map<String, Serializable> params, String reason)
{

   /*******************************************************************************
    ** A request with no parameters.
    *******************************************************************************/
   public static AdminRequest of(AdminAction action, String targetKey, String reason)
   {
      return (new AdminRequest(action, targetKey, new LinkedHashMap<>(), reason));
   }



   /*******************************************************************************
    ** Fluent parameter setter (returns this request).
    *******************************************************************************/
   public AdminRequest with(String name, Serializable value)
   {
      params.put(name, value);
      return (this);
   }



   /*******************************************************************************
    ** A parameter as trimmed text, or "" when absent.
    *******************************************************************************/
   public String str(String name)
   {
      Serializable value = params.get(name);
      return (value == null ? "" : String.valueOf(value).trim());
   }



   /*******************************************************************************
    ** A parameter as a boolean (true for true or "true").
    *******************************************************************************/
   public boolean bool(String name)
   {
      Serializable value = params.get(name);
      return (value instanceof Boolean b ? b : value != null && "true".equalsIgnoreCase(String.valueOf(value).trim()));
   }



   /*******************************************************************************
    ** To JSON (for a stored approval request).
    *******************************************************************************/
   public String toJson()
   {
      return (new JSONObject()
         .put("action", action.name())
         .put("targetKey", targetKey)
         .put("reason", reason)
         .put("params", new JSONObject(params)).toString());
   }



   /*******************************************************************************
    ** From JSON written by toJson.
    *******************************************************************************/
   public static AdminRequest fromJson(String json)
   {
      JSONObject object = new JSONObject(json);
      Map<String, Serializable> params = new LinkedHashMap<>();
      JSONObject stored = object.optJSONObject("params");
      if(stored != null)
      {
         for(String key : stored.keySet())
         {
            Object value = stored.get(key);
            params.put(key, value instanceof Boolean || value instanceof Number ? (Serializable) value : String.valueOf(value));
         }
      }
      return (new AdminRequest(AdminAction.valueOf(object.getString("action")), object.optString("targetKey", ""), params, object.optString("reason", "")));
   }

}
