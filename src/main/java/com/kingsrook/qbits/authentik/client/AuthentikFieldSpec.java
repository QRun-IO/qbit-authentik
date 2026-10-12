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
import java.util.EnumMap;
import java.util.Map;
import java.util.function.Function;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import org.json.JSONObject;


/*******************************************************************************
 ** One field of an Authentik-backed table: how to read it from the Authentik
 ** JSON, which QQQ criteria map to which Authentik query parameters, and
 ** whether it is sensitive (stripped without identity.audit.read).
 *******************************************************************************/
public class AuthentikFieldSpec
{
   private final String                                  name;
   private final String                                  label;
   private final QFieldType                              type;
   private final Function<JSONObject, Serializable>      extractor;
   private final Map<QCriteriaOperator, String>          filterParams = new EnumMap<>(QCriteriaOperator.class);
   private boolean                                       sensitive;
   private boolean                                       searchable;
   private String                                        orderingName;
   private boolean                                       hidden;



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   public AuthentikFieldSpec(String name, String label, QFieldType type, Function<JSONObject, Serializable> extractor)
   {
      this.name = name;
      this.label = label;
      this.type = type;
      this.extractor = extractor;
   }



   /*******************************************************************************
    ** Map a QQQ operator to an Authentik query parameter for this field.
    *******************************************************************************/
   public AuthentikFieldSpec withFilter(QCriteriaOperator operator, String param)
   {
      filterParams.put(operator, param);
      return (this);
   }



   /*******************************************************************************
    ** Mark as sensitive (needs identity.audit.read to see or filter on).
    *******************************************************************************/
   public AuthentikFieldSpec withSensitive()
   {
      this.sensitive = true;
      return (this);
   }



   /*******************************************************************************
    ** CONTAINS / STARTS_WITH on this field map to Authentik's search param.
    *******************************************************************************/
   public AuthentikFieldSpec withSearchable()
   {
      this.searchable = true;
      return (this);
   }



   /*******************************************************************************
    ** Allow ordering on this field, by the given Authentik ordering name.
    *******************************************************************************/
   public AuthentikFieldSpec withOrdering(String orderingName)
   {
      this.orderingName = orderingName;
      return (this);
   }



   /*******************************************************************************
    ** Hide the field in the UI (it still exists on records).
    *******************************************************************************/
   public AuthentikFieldSpec withHidden()
   {
      this.hidden = true;
      return (this);
   }



   /*******************************************************************************
    ** Read this field's value from an Authentik object.
    *******************************************************************************/
   public Serializable extract(JSONObject object)
   {
      return (extractor.apply(object));
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
    ** Getter for type
    *******************************************************************************/
   public QFieldType getType()
   {
      return (type);
   }



   /*******************************************************************************
    ** Getter for filterParams
    *******************************************************************************/
   public Map<QCriteriaOperator, String> getFilterParams()
   {
      return (filterParams);
   }



   /*******************************************************************************
    ** Getter for sensitive
    *******************************************************************************/
   public boolean isSensitive()
   {
      return (sensitive);
   }



   /*******************************************************************************
    ** Getter for searchable
    *******************************************************************************/
   public boolean isSearchable()
   {
      return (searchable);
   }



   /*******************************************************************************
    ** Getter for orderingName
    *******************************************************************************/
   public String getOrderingName()
   {
      return (orderingName);
   }



   /*******************************************************************************
    ** Getter for hidden
    *******************************************************************************/
   public boolean isHidden()
   {
      return (hidden);
   }

}
