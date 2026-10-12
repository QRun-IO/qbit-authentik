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
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.expressions.AbstractFilterExpression;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.utils.CollectionUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;


/*******************************************************************************
 ** Maps a QQQ filter to Authentik query parameters (DESIGN.md section 6.1).
 **
 ** Exactly what Authentik can evaluate server-side is accepted. Everything
 ** else (OR, sub-filters, NOT_* operators, unmapped fields or operators,
 ** field-to-field criteria) is REJECTED with a user-facing message: filtering
 ** client-side over 100-row pages would silently truncate results.
 **
 ** Notes:
 ** - Authentik date filters are strict (__gt / __lt). GREATER_THAN_OR_EQUALS
 **   and LESS_THAN_OR_EQUALS are widened by one millisecond; BETWEEN uses both.
 ** - CONTAINS / STARTS_WITH on a searchable field use Authentik's "search"
 **   parameter, which matches the term across several fields (a superset of
 **   the field criterion). Only one search term per query.
 ** - A filter made only of key EQUALS / IN criteria is returned as a key
 **   lookup (the caller fetches each record by id), since Authentik has no
 **   list filter on every table's key.
 *******************************************************************************/
public class AuthentikFilterMapper
{

   /*******************************************************************************
    ** Result of mapping a filter.
    *******************************************************************************/
   public record MappedFilter(List<NameValuePair> params, List<Serializable> keyLookup, Set<String> filteredFields)
   {
      /*******************************************************************************
       ** Whether this mapping is a key lookup (fetch-by-id) rather than a list query.
       *******************************************************************************/
      public boolean isKeyLookup()
      {
         return (keyLookup != null);
      }
   }



   /*******************************************************************************
    ** Map a filter for a table.
    **
    ** @param spec            the table
    ** @param filter          the QQQ filter (may be null)
    ** @param mayUseSensitive whether the session may filter on sensitive fields
    *******************************************************************************/
   public MappedFilter map(AuthentikTableSpec spec, QQueryFilter filter, boolean mayUseSensitive) throws QException
   {
      List<NameValuePair> params         = new ArrayList<>();
      Set<String>         usedParams     = new HashSet<>();
      Set<String>         filteredFields = new HashSet<>();

      if(filter == null)
      {
         addOrdering(spec, null, params);
         return (new MappedFilter(params, null, filteredFields));
      }

      if(CollectionUtils.nullSafeHasContents(filter.getSubFilters()))
      {
         throw (new QUserFacingException("Nested filters (sub-filters) are not supported for " + spec.getLabel() + "."));
      }

      List<QFilterCriteria> criteria = CollectionUtils.nonNullList(filter.getCriteria());
      if(criteria.size() > 1 && filter.getBooleanOperator() == QQueryFilter.BooleanOperator.OR)
      {
         throw (new QUserFacingException("\"Any of\" (OR) filters are not supported for " + spec.getLabel() + "; use \"all of\" (AND)."));
      }

      List<Serializable> keyLookup = keyLookup(spec, criteria);
      if(keyLookup != null)
      {
         filteredFields.add(spec.getKeyFieldName());
         return (new MappedFilter(params, keyLookup, filteredFields));
      }

      boolean usedSearch = false;
      for(QFilterCriteria criterion : criteria)
      {
         if(criterion == null || criterion.getFieldName() == null)
         {
            continue;
         }

         if(criterion.getOtherFieldName() != null || criterion.getFieldFunction() != null)
         {
            throw (new QUserFacingException("Field-to-field and function criteria are not supported for " + spec.getLabel() + "."));
         }

         AuthentikFieldSpec field = spec.getField(criterion.getFieldName());
         if(field == null)
         {
            throw (new QUserFacingException("Unknown field for " + spec.getLabel() + ": " + criterion.getFieldName()));
         }
         if(field.isSensitive() && !mayUseSensitive)
         {
            throw (new QUserFacingException("You do not have permission to filter " + spec.getLabel() + " by " + field.getLabel() + "."));
         }

         QCriteriaOperator  operator = criterion.getOperator();
         List<Serializable> values   = evaluateValues(field, criterion.getValues());
         filteredFields.add(field.getName());

         if((operator == QCriteriaOperator.CONTAINS || operator == QCriteriaOperator.STARTS_WITH) && !field.getFilterParams().containsKey(operator) && field.isSearchable())
         {
            if(usedSearch)
            {
               throw (new QUserFacingException("Only one text-search criterion is supported for " + spec.getLabel() + "."));
            }
            usedSearch = true;
            add(params, usedParams, "search", singleString(field, operator, values));
            continue;
         }

         switch(operator)
         {
            case EQUALS, STARTS_WITH -> add(params, usedParams, param(field, operator), formatValue(field, singleValue(field, operator, values)));
            case IN ->
            {
               String param = param(field, operator);
               if(values.isEmpty())
               {
                  throw (new QUserFacingException("An empty \"is any of\" list is not supported for " + field.getLabel() + "."));
               }
               if(!usedParams.add(param))
               {
                  throw (duplicate(field));
               }
               for(Serializable value : values)
               {
                  params.add(new BasicNameValuePair(param, formatValue(field, value)));
               }
            }
            case GREATER_THAN, LESS_THAN -> add(params, usedParams, param(field, operator), formatValue(field, singleValue(field, operator, values)));
            case GREATER_THAN_OR_EQUALS -> add(params, usedParams, param(field, QCriteriaOperator.GREATER_THAN), formatInstant(shift(field, singleValue(field, operator, values), -1)));
            case LESS_THAN_OR_EQUALS -> add(params, usedParams, param(field, QCriteriaOperator.LESS_THAN), formatInstant(shift(field, singleValue(field, operator, values), 1)));
            case BETWEEN ->
            {
               if(values.size() != 2)
               {
                  throw (new QUserFacingException("\"Between\" needs two values for " + field.getLabel() + "."));
               }
               add(params, usedParams, param(field, QCriteriaOperator.GREATER_THAN), formatInstant(shift(field, values.get(0), -1)));
               add(params, usedParams, param(field, QCriteriaOperator.LESS_THAN), formatInstant(shift(field, values.get(1), 1)));
            }
            case IS_BLANK -> add(params, usedParams, param(field, operator), "true");
            case IS_NOT_BLANK -> add(params, usedParams, param(field, operator), "false");
            default -> throw (unsupported(field, operator));
         }
      }

      addOrdering(spec, filter.getOrderBys(), params);
      return (new MappedFilter(params, null, filteredFields));
   }



   /*******************************************************************************
    ** If every criterion is key EQUALS / IN, return the keys; else null.
    *******************************************************************************/
   private List<Serializable> keyLookup(AuthentikTableSpec spec, List<QFilterCriteria> criteria)
   {
      if(criteria.isEmpty())
      {
         return (null);
      }

      List<Serializable> keys = null;
      for(QFilterCriteria criterion : criteria)
      {
         if(criterion == null || !spec.getKeyFieldName().equals(criterion.getFieldName()) || criterion.getOtherFieldName() != null)
         {
            return (null);
         }
         if(criterion.getOperator() != QCriteriaOperator.EQUALS && criterion.getOperator() != QCriteriaOperator.IN)
         {
            return (null);
         }

         List<Serializable> these = new ArrayList<>(CollectionUtils.nonNullList(criterion.getValues()));
         if(keys == null)
         {
            keys = these;
         }
         else
         {
            keys.retainAll(these);
         }
      }
      return (keys);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private void addOrdering(AuthentikTableSpec spec, List<QFilterOrderBy> orderBys, List<NameValuePair> params) throws QUserFacingException
   {
      List<String> orderings = new ArrayList<>();
      for(QFilterOrderBy orderBy : CollectionUtils.nonNullList(orderBys))
      {
         AuthentikFieldSpec field = spec.getField(orderBy.getFieldName());
         if(field == null || field.getOrderingName() == null)
         {
            throw (new QUserFacingException(spec.getLabel() + " cannot be sorted by " + (field == null ? orderBy.getFieldName() : field.getLabel()) + "."));
         }
         orderings.add((orderBy.getIsAscending() ? "" : "-") + field.getOrderingName());
      }

      if(orderings.isEmpty() && spec.getDefaultOrdering() != null)
      {
         orderings.add(spec.getDefaultOrdering());
      }

      if(!orderings.isEmpty())
      {
         params.add(new BasicNameValuePair("ordering", String.join(",", orderings)));
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void add(List<NameValuePair> params, Set<String> usedParams, String param, String value) throws QUserFacingException
   {
      if(!usedParams.add(param))
      {
         throw (new QUserFacingException("Two criteria map to the same Authentik filter (" + param + "); combine them into one."));
      }
      params.add(new BasicNameValuePair(param, value));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String param(AuthentikFieldSpec field, QCriteriaOperator operator) throws QUserFacingException
   {
      String param = field.getFilterParams().get(operator);
      if(param == null)
      {
         throw (unsupported(field, operator));
      }
      return (param);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static QUserFacingException unsupported(AuthentikFieldSpec field, QCriteriaOperator operator)
   {
      return (new QUserFacingException("Filtering " + field.getLabel() + " with \"" + operator.name().toLowerCase().replace('_', ' ') + "\" is not supported by Authentik."));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static QUserFacingException duplicate(AuthentikFieldSpec field)
   {
      return (new QUserFacingException("Only one criterion per field is supported (" + field.getLabel() + ")."));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static Serializable singleValue(AuthentikFieldSpec field, QCriteriaOperator operator, List<Serializable> values) throws QUserFacingException
   {
      if(values.size() != 1 || values.get(0) == null)
      {
         throw (new QUserFacingException("\"" + operator.name().toLowerCase().replace('_', ' ') + "\" needs exactly one value for " + field.getLabel() + "."));
      }
      return (values.get(0));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String singleString(AuthentikFieldSpec field, QCriteriaOperator operator, List<Serializable> values) throws QUserFacingException
   {
      String value = String.valueOf(singleValue(field, operator, values)).trim();
      if(value.isEmpty())
      {
         throw (new QUserFacingException("A search term is required for " + field.getLabel() + "."));
      }
      return (value);
   }



   /*******************************************************************************
    ** Evaluate filter expressions (e.g. "now minus 90 days") into plain values.
    *******************************************************************************/
   private static List<Serializable> evaluateValues(AuthentikFieldSpec field, List<Serializable> values) throws QException
   {
      List<Serializable> rs = new ArrayList<>();
      for(Serializable value : CollectionUtils.nonNullList(values))
      {
         if(value instanceof AbstractFilterExpression<?> expression)
         {
            rs.add(expression.evaluate(new QFieldMetaData(field.getName(), field.getType())));
         }
         else
         {
            rs.add(value);
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** Format a value for a query string.
    *******************************************************************************/
   static String formatValue(AuthentikFieldSpec field, Serializable value) throws QUserFacingException
   {
      if(field.getType() == QFieldType.DATE_TIME || field.getType() == QFieldType.DATE)
      {
         return (formatInstant(toInstant(field, value)));
      }
      if(field.getType() == QFieldType.BOOLEAN)
      {
         String text = String.valueOf(value).trim().toLowerCase();
         return (text.equals("true") || text.equals("1") || text.equals("yes") ? "true" : "false");
      }
      return (String.valueOf(value));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static Instant shift(AuthentikFieldSpec field, Serializable value, long millis) throws QUserFacingException
   {
      return (toInstant(field, value).plusMillis(millis));
   }



   /*******************************************************************************
    ** Convert a date-ish value to an Instant (a date means its start, UTC).
    *******************************************************************************/
   static Instant toInstant(AuthentikFieldSpec field, Serializable value) throws QUserFacingException
   {
      if(value instanceof Instant instant)
      {
         return (instant);
      }
      if(value instanceof LocalDate localDate)
      {
         return (localDate.atStartOfDay(ZoneOffset.UTC).toInstant());
      }
      if(value instanceof java.util.Date date)
      {
         return (date.toInstant());
      }

      String text = value == null ? "" : String.valueOf(value).trim();
      try
      {
         return (Instant.parse(text));
      }
      catch(DateTimeParseException e)
      {
         try
         {
            return (AuthentikJson.parseInstant(text));
         }
         catch(DateTimeParseException e2)
         {
            try
            {
               return (LocalDate.parse(text).atStartOfDay(ZoneOffset.UTC).toInstant());
            }
            catch(DateTimeParseException e3)
            {
               throw (new QUserFacingException("Not a valid date/time for " + field.getLabel() + ": " + text));
            }
         }
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String formatInstant(Instant instant)
   {
      return (instant.toString());
   }

}
