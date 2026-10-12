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


import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.expressions.NowWithOffset;
import org.apache.http.NameValuePair;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Tests for AuthentikFilterMapper.
 *******************************************************************************/
class AuthentikFilterMapperTest
{
   private final AuthentikFilterMapper mapper = new AuthentikFilterMapper();
   private final AuthentikTableSpec    users  = AuthentikTables.get(AuthentikTables.USER);
   private final AuthentikTableSpec    groups = AuthentikTables.get(AuthentikTables.GROUP);



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<String> params(AuthentikTableSpec spec, QQueryFilter filter) throws QException
   {
      return (mapper.map(spec, filter, false).params().stream().map(p -> p.getName() + "=" + p.getValue()).toList());
   }



   /*******************************************************************************
    ** Appendix A example of the design.
    *******************************************************************************/
   @Test
   void designAppendixExample() throws QException
   {
      QQueryFilter filter = new QQueryFilter(
         new QFilterCriteria("isActive", QCriteriaOperator.EQUALS, false),
         new QFilterCriteria("lastLogin", QCriteriaOperator.LESS_THAN, LocalDate.of(2026, 7, 13)))
         .withOrderBy(new QFilterOrderBy("username"));
      assertThat(params(users, filter)).containsExactly("is_active=false", "last_login__lt=2026-07-13T00:00:00Z", "ordering=username");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void nullFilterUsesDefaultOrdering() throws QException
   {
      assertThat(params(users, null)).containsExactly("ordering=username");
      assertThat(params(groups, new QQueryFilter())).containsExactly("ordering=name");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void inUsesRepeatedPlainNames() throws QException
   {
      assertThat(params(users, new QQueryFilter(new QFilterCriteria("type", QCriteriaOperator.IN, List.of("internal", "external")))))
         .containsExactly("type=internal", "type=external", "ordering=username");
      assertThat(params(groups, new QQueryFilter(new QFilterCriteria("memberUsername", QCriteriaOperator.IN, List.of("a", "b")))))
         .containsExactly("members_by_username=a", "members_by_username=b", "ordering=name");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void inclusiveDateBoundsAndBetween() throws QException
   {
      Instant at = Instant.parse("2026-01-01T00:00:00Z");
      assertThat(params(users, new QQueryFilter(new QFilterCriteria("dateJoined", QCriteriaOperator.GREATER_THAN_OR_EQUALS, at))))
         .contains("date_joined__gt=2025-12-31T23:59:59.999Z");
      assertThat(params(users, new QQueryFilter(new QFilterCriteria("dateJoined", QCriteriaOperator.LESS_THAN_OR_EQUALS, "2026-01-01T00:00:00Z"))))
         .contains("date_joined__lt=2026-01-01T00:00:00.001Z");
      assertThat(params(users, new QQueryFilter(new QFilterCriteria("lastLogin", QCriteriaOperator.BETWEEN, List.of("2026-01-01", "2026-02-01")))))
         .contains("last_login__gt=2025-12-31T23:59:59.999Z", "last_login__lt=2026-02-01T00:00:00.001Z");
      assertThat(params(users, new QQueryFilter(new QFilterCriteria("lastLogin", QCriteriaOperator.GREATER_THAN, "2026-03-04T05:06:07+02:00"))))
         .contains("last_login__gt=2026-03-04T03:06:07Z");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void expressionsAreEvaluated() throws QException
   {
      List<String> params = params(users, new QQueryFilter(new QFilterCriteria("lastLogin", QCriteriaOperator.LESS_THAN, NowWithOffset.minus(90, java.time.temporal.ChronoUnit.DAYS))));
      assertThat(params.get(0)).startsWith("last_login__lt=20");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void blankChecksAndSearch() throws QException
   {
      assertThat(params(users, new QQueryFilter(new QFilterCriteria("lastLogin", QCriteriaOperator.IS_BLANK)))).contains("last_login__isnull=true");
      assertThat(params(users, new QQueryFilter(new QFilterCriteria("lastLogin", QCriteriaOperator.IS_NOT_BLANK)))).contains("last_login__isnull=false");
      assertThat(params(users, new QQueryFilter(new QFilterCriteria("email", QCriteriaOperator.CONTAINS, " kof22 ")))).contains("search=kof22");
      assertThat(params(users, new QQueryFilter(new QFilterCriteria("path", QCriteriaOperator.STARTS_WITH, "users/")))).contains("path_startswith=users/");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void orderingDescendingAndMultiple() throws QException
   {
      assertThat(params(users, new QQueryFilter().withOrderBy(new QFilterOrderBy("lastLogin", false)).withOrderBy(new QFilterOrderBy("username"))))
         .containsExactly("ordering=-last_login,username");
      assertThatThrownBy(() -> params(users, new QQueryFilter().withOrderBy(new QFilterOrderBy("groupNames")))).isInstanceOf(QUserFacingException.class);
   }



   /*******************************************************************************
    ** Key-only filters become key lookups (users have no pk list filter).
    *******************************************************************************/
   @Test
   void keyLookups() throws QException
   {
      AuthentikFilterMapper.MappedFilter mapped = mapper.map(users, new QQueryFilter(new QFilterCriteria("pk", QCriteriaOperator.IN, List.of(1, 2, 3)), new QFilterCriteria("pk", QCriteriaOperator.EQUALS, 2)), false);
      assertThat(mapped.isKeyLookup()).isTrue();
      assertThat(mapped.keyLookup()).containsExactly(2);
      assertThat(mapper.map(users, new QQueryFilter(new QFilterCriteria("pk", QCriteriaOperator.EQUALS, 7)), false).keyLookup()).containsExactly(7);
   }



   /*******************************************************************************
    ** Everything Authentik cannot evaluate is rejected, never post-filtered.
    *******************************************************************************/
   @Test
   void unsupportedFiltersAreRejected()
   {
      QFilterCriteria a = new QFilterCriteria("username", QCriteriaOperator.EQUALS, "a");
      QFilterCriteria b = new QFilterCriteria("email", QCriteriaOperator.EQUALS, "b");

      assertThatThrownBy(() -> params(users, new QQueryFilter(a, b).withBooleanOperator(QQueryFilter.BooleanOperator.OR))).isInstanceOf(QUserFacingException.class).hasMessageContaining("OR");
      assertThatThrownBy(() -> params(users, new QQueryFilter(a).withSubFilters(List.of(new QQueryFilter(b))))).isInstanceOf(QUserFacingException.class).hasMessageContaining("sub-filters");
      assertThatThrownBy(() -> params(users, new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.NOT_EQUALS, "a")))).isInstanceOf(QUserFacingException.class);
      assertThatThrownBy(() -> params(users, new QQueryFilter(new QFilterCriteria("nope", QCriteriaOperator.EQUALS, "a")))).isInstanceOf(QUserFacingException.class).hasMessageContaining("Unknown field");
      assertThatThrownBy(() -> params(users, new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS, "a"), new QFilterCriteria("username", QCriteriaOperator.EQUALS, "b")))).isInstanceOf(QUserFacingException.class);
      assertThatThrownBy(() -> params(users, new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.CONTAINS, "a"), new QFilterCriteria("email", QCriteriaOperator.CONTAINS, "b")))).isInstanceOf(QUserFacingException.class).hasMessageContaining("one text-search");
      assertThatThrownBy(() -> params(users, new QQueryFilter(new QFilterCriteria("type", QCriteriaOperator.IN, List.of())))).isInstanceOf(QUserFacingException.class);
      assertThatThrownBy(() -> params(users, new QQueryFilter(new QFilterCriteria("lastLogin", QCriteriaOperator.BETWEEN, List.of("2026-01-01"))))).isInstanceOf(QUserFacingException.class);
      assertThatThrownBy(() -> params(users, new QQueryFilter(new QFilterCriteria("lastLogin", QCriteriaOperator.LESS_THAN, "yesterday-ish")))).isInstanceOf(QUserFacingException.class).hasMessageContaining("valid date");
      assertThatThrownBy(() -> params(users, new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.EQUALS)))).isInstanceOf(QUserFacingException.class);
      assertThatThrownBy(() -> params(users, new QQueryFilter(new QFilterCriteria("username", QCriteriaOperator.CONTAINS, "  ")))).isInstanceOf(QUserFacingException.class);

      QFilterCriteria fieldToField = new QFilterCriteria("username", QCriteriaOperator.EQUALS, List.of());
      fieldToField.setOtherFieldName("email");
      assertThatThrownBy(() -> params(users, new QQueryFilter(fieldToField))).isInstanceOf(QUserFacingException.class);
   }



   /*******************************************************************************
    ** Sensitive fields can't be filtered without identity.audit.read.
    *******************************************************************************/
   @Test
   void sensitiveFieldFilters() throws QException
   {
      QQueryFilter filter = new QQueryFilter(new QFilterCriteria("passwordChangeDate", QCriteriaOperator.IS_BLANK));
      assertThatThrownBy(() -> mapper.map(users, filter, false)).isInstanceOf(QUserFacingException.class).hasMessageContaining("permission");
      assertThatThrownBy(() -> mapper.map(users, filter, true)).isInstanceOf(QUserFacingException.class).hasMessageContaining("not supported");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void booleanFormatting() throws QException
   {
      for(java.io.Serializable value : List.<java.io.Serializable>of(true, "TRUE", 1, "yes"))
      {
         List<NameValuePair> mapped = mapper.map(users, new QQueryFilter(new QFilterCriteria("isActive", QCriteriaOperator.EQUALS, value)), false).params();
         assertThat(mapped.get(0).getValue()).isEqualTo("true");
      }
      assertThat(mapper.map(users, new QQueryFilter(new QFilterCriteria("isActive", QCriteriaOperator.EQUALS, "no")), false).params().get(0).getValue()).isEqualTo("false");
   }

}
