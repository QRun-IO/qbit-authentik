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


import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;


/*******************************************************************************
 ** Definition of one Authentik-backed QQQ table: its endpoint, key, fields,
 ** default query parameters and the permission needed to read it.
 *******************************************************************************/
public class AuthentikTableSpec
{
   private final String                          name;
   private final String                          label;
   private final String                          icon;
   private final String                          path;
   private final String                          keyFieldName;
   private final Map<String, AuthentikFieldSpec> fields                = new LinkedHashMap<>();
   private final List<NameValuePair>             defaultListParams     = new ArrayList<>();
   private final List<NameValuePair>             defaultGetParams      = new ArrayList<>();
   private IdentityPermission                    readPermission        = IdentityPermission.USERS_READ;
   private String                                defaultOrdering;
   private List<String>                          recordLabelFields     = new ArrayList<>();
   private String                                requiredFilterField;
   private boolean                               virtual;



   /*******************************************************************************
    ** Constructor.
    **
    ** @param name         unprefixed table name, e.g. "user"
    ** @param label        UI label
    ** @param icon         material icon name
    ** @param path         API path below /api/v3, with leading and trailing slash
    ** @param keyFieldName name of the primary-key field
    *******************************************************************************/
   public AuthentikTableSpec(String name, String label, String icon, String path, String keyFieldName)
   {
      this.name = name;
      this.label = label;
      this.icon = icon;
      this.path = path;
      this.keyFieldName = keyFieldName;
   }



   /*******************************************************************************
    ** Add a field.
    *******************************************************************************/
   public AuthentikTableSpec withField(AuthentikFieldSpec field)
   {
      fields.put(field.getName(), field);
      return (this);
   }



   /*******************************************************************************
    ** Add a query parameter sent with every list request.
    *******************************************************************************/
   public AuthentikTableSpec withDefaultListParam(String param, String value)
   {
      defaultListParams.add(new BasicNameValuePair(param, value));
      return (this);
   }



   /*******************************************************************************
    ** Add a query parameter sent with every single-record GET.
    *******************************************************************************/
   public AuthentikTableSpec withDefaultGetParam(String param, String value)
   {
      defaultGetParams.add(new BasicNameValuePair(param, value));
      return (this);
   }



   /*******************************************************************************
    ** Set the permission needed to read the table.
    *******************************************************************************/
   public AuthentikTableSpec withReadPermission(IdentityPermission readPermission)
   {
      this.readPermission = readPermission;
      return (this);
   }



   /*******************************************************************************
    ** Set the Authentik ordering used when the query has no orderBy.
    *******************************************************************************/
   public AuthentikTableSpec withDefaultOrdering(String defaultOrdering)
   {
      this.defaultOrdering = defaultOrdering;
      return (this);
   }



   /*******************************************************************************
    ** Set the record label fields.
    *******************************************************************************/
   public AuthentikTableSpec withRecordLabelFields(String... recordLabelFields)
   {
      this.recordLabelFields = new ArrayList<>(List.of(recordLabelFields));
      return (this);
   }



   /*******************************************************************************
    ** Require a criterion on this field for every query (e.g. MFA devices are
    ** only listed per user).
    *******************************************************************************/
   public AuthentikTableSpec withRequiredFilterField(String requiredFilterField)
   {
      this.requiredFilterField = requiredFilterField;
      return (this);
   }



   /*******************************************************************************
    ** Mark as virtual: served by custom logic in AuthentikActionUtil rather than
    ** by one list endpoint (its filter "params" are field names, not Authentik
    ** query parameters).
    *******************************************************************************/
   public AuthentikTableSpec withVirtual()
   {
      this.virtual = true;
      return (this);
   }



   /*******************************************************************************
    ** Getter for virtual
    *******************************************************************************/
   public boolean isVirtual()
   {
      return (virtual);
   }



   /*******************************************************************************
    ** Get a field spec, or null.
    *******************************************************************************/
   public AuthentikFieldSpec getField(String fieldName)
   {
      return (fields.get(fieldName));
   }



   /*******************************************************************************
    ** All field specs, in display order.
    *******************************************************************************/
   public Collection<AuthentikFieldSpec> getFields()
   {
      return (fields.values());
   }



   /*******************************************************************************
    ** Getter for name
    *******************************************************************************/
   public String getName()
   {
      return (name);
   }



   /*******************************************************************************
    ** Getter for label
    *******************************************************************************/
   public String getLabel()
   {
      return (label);
   }



   /*******************************************************************************
    ** Getter for icon
    *******************************************************************************/
   public String getIcon()
   {
      return (icon);
   }



   /*******************************************************************************
    ** Getter for path
    *******************************************************************************/
   public String getPath()
   {
      return (path);
   }



   /*******************************************************************************
    ** Getter for keyFieldName
    *******************************************************************************/
   public String getKeyFieldName()
   {
      return (keyFieldName);
   }



   /*******************************************************************************
    ** Getter for defaultListParams
    *******************************************************************************/
   public List<NameValuePair> getDefaultListParams()
   {
      return (defaultListParams);
   }



   /*******************************************************************************
    ** Getter for defaultGetParams
    *******************************************************************************/
   public List<NameValuePair> getDefaultGetParams()
   {
      return (defaultGetParams);
   }



   /*******************************************************************************
    ** Getter for readPermission
    *******************************************************************************/
   public IdentityPermission getReadPermission()
   {
      return (readPermission);
   }



   /*******************************************************************************
    ** Getter for defaultOrdering
    *******************************************************************************/
   public String getDefaultOrdering()
   {
      return (defaultOrdering);
   }



   /*******************************************************************************
    ** Getter for recordLabelFields
    *******************************************************************************/
   public List<String> getRecordLabelFields()
   {
      return (recordLabelFields);
   }



   /*******************************************************************************
    ** Getter for requiredFilterField
    *******************************************************************************/
   public String getRequiredFilterField()
   {
      return (requiredFilterField);
   }

}
