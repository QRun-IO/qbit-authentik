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


import java.util.LinkedHashMap;
import java.util.Map;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.attributeList;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.bool;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.instant;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.integer;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.joined;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.json;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.qqqAttributes;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.string;


/*******************************************************************************
 ** The Authentik-backed tables (DESIGN.md section 6.1), mapped against the
 ** pinned 2026.8.3 schema (src/test/resources/authentik/schema-2026.8.3.yml).
 **
 ** Multi-value query parameters are sent as repeated plain names
 ** (type=internal&type=external). Authentik silently IGNORES the bracketed
 ** form (type[]=internal), returning unfiltered results (phase 0 finding).
 *******************************************************************************/
public final class AuthentikTables
{
   public static final String USER  = "user";
   public static final String GROUP = "group";

   /** User types the qbit shows by default: everything but outposts' internal service accounts. */
   public static final String[] DEFAULT_USER_TYPES = { "internal", "external", "service_account" };

   private static final Map<String, AuthentikTableSpec> SPECS = new LinkedHashMap<>();

   static
   {
      register(users());
      register(groups());
   }



   /*******************************************************************************
    ** Not instantiable.
    *******************************************************************************/
   private AuthentikTables()
   {
   }



   /*******************************************************************************
    ** Look up a spec by unprefixed table name, or null.
    *******************************************************************************/
   public static AuthentikTableSpec get(String name)
   {
      return (SPECS.get(name));
   }



   /*******************************************************************************
    ** All specs.
    *******************************************************************************/
   public static Map<String, AuthentikTableSpec> all()
   {
      return (SPECS);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void register(AuthentikTableSpec spec)
   {
      SPECS.put(spec.getName(), spec);
   }



   /*******************************************************************************
    ** /core/users/ (int pk). The detail GET takes no include_* parameters and
    ** always returns groups_obj and roles_obj.
    *******************************************************************************/
   static AuthentikTableSpec users()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(USER, "Users", "person", "/core/users/", "pk")
         .withDefaultListParam("include_groups", "true")
         .withDefaultListParam("include_roles", "true")
         .withDefaultOrdering("username")
         .withRecordLabelFields("username");

      spec.withField(new AuthentikFieldSpec("pk", "Id", QFieldType.INTEGER, integer("pk")));
      spec.withField(new AuthentikFieldSpec("username", "Username", QFieldType.STRING, string("username"))
         .withFilter(QCriteriaOperator.EQUALS, "username").withSearchable().withOrdering("username"));
      spec.withField(new AuthentikFieldSpec("name", "Name", QFieldType.STRING, string("name"))
         .withFilter(QCriteriaOperator.EQUALS, "name").withSearchable().withOrdering("name"));
      spec.withField(new AuthentikFieldSpec("email", "Email", QFieldType.STRING, string("email"))
         .withFilter(QCriteriaOperator.EQUALS, "email").withSearchable().withOrdering("email"));
      spec.withField(new AuthentikFieldSpec("isActive", "Active", QFieldType.BOOLEAN, bool("is_active"))
         .withFilter(QCriteriaOperator.EQUALS, "is_active").withOrdering("is_active"));
      spec.withField(new AuthentikFieldSpec("type", "Type", QFieldType.STRING, string("type"))
         .withFilter(QCriteriaOperator.EQUALS, "type").withFilter(QCriteriaOperator.IN, "type"));
      spec.withField(new AuthentikFieldSpec("isSuperuser", "Superuser", QFieldType.BOOLEAN, bool("is_superuser"))
         .withFilter(QCriteriaOperator.EQUALS, "is_superuser"));
      spec.withField(new AuthentikFieldSpec("isProtected", "Protected", QFieldType.BOOLEAN, o -> null));
      spec.withField(new AuthentikFieldSpec("groupNames", "Groups", QFieldType.STRING, joined("groups_obj", "name"))
         .withFilter(QCriteriaOperator.EQUALS, "groups_by_name").withFilter(QCriteriaOperator.IN, "groups_by_name"));
      spec.withField(new AuthentikFieldSpec("roleNames", "Roles", QFieldType.STRING, joined("roles_obj", "name"))
         .withFilter(QCriteriaOperator.EQUALS, "roles_by_name").withFilter(QCriteriaOperator.IN, "roles_by_name"));
      spec.withField(new AuthentikFieldSpec("lastLogin", "Last Login", QFieldType.DATE_TIME, instant("last_login"))
         .withFilter(QCriteriaOperator.GREATER_THAN, "last_login__gt").withFilter(QCriteriaOperator.LESS_THAN, "last_login__lt")
         .withFilter(QCriteriaOperator.IS_BLANK, "last_login__isnull").withFilter(QCriteriaOperator.IS_NOT_BLANK, "last_login__isnull")
         .withOrdering("last_login"));
      spec.withField(new AuthentikFieldSpec("dateJoined", "Date Joined", QFieldType.DATE_TIME, instant("date_joined"))
         .withFilter(QCriteriaOperator.GREATER_THAN, "date_joined__gt").withFilter(QCriteriaOperator.LESS_THAN, "date_joined__lt")
         .withOrdering("date_joined"));
      spec.withField(new AuthentikFieldSpec("lastUpdated", "Last Updated", QFieldType.DATE_TIME, instant("last_updated"))
         .withFilter(QCriteriaOperator.GREATER_THAN, "last_updated__gt").withFilter(QCriteriaOperator.LESS_THAN, "last_updated__lt"));
      spec.withField(new AuthentikFieldSpec("path", "Path", QFieldType.STRING, string("path"))
         .withFilter(QCriteriaOperator.EQUALS, "path").withFilter(QCriteriaOperator.STARTS_WITH, "path_startswith"));
      spec.withField(new AuthentikFieldSpec("uuid", "UUID", QFieldType.STRING, string("uuid"))
         .withFilter(QCriteriaOperator.EQUALS, "uuid").withHidden());
      spec.withField(new AuthentikFieldSpec("qqqAttributes", "QQQ Attributes", QFieldType.TEXT, qqqAttributes()));
      spec.withField(new AuthentikFieldSpec("passwordChangeDate", "Password Changed", QFieldType.DATE_TIME, instant("password_change_date"))
         .withSensitive());
      spec.withField(new AuthentikFieldSpec("attributes", "Attributes", QFieldType.TEXT, json("attributes"))
         .withSensitive());
      return (spec);
   }



   /*******************************************************************************
    ** /core/groups/ (uuid pk). Note: Group has no last_updated in 2026.8.3.
    *******************************************************************************/
   static AuthentikTableSpec groups()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(GROUP, "Groups", "groups", "/core/groups/", "pk")
         .withDefaultListParam("include_users", "false")
         .withDefaultListParam("include_parents", "true")
         .withDefaultListParam("include_children", "true")
         .withDefaultGetParam("include_users", "false")
         .withDefaultGetParam("include_parents", "true")
         .withDefaultGetParam("include_children", "true")
         .withDefaultOrdering("name")
         .withRecordLabelFields("name");

      spec.withField(new AuthentikFieldSpec("pk", "Id", QFieldType.STRING, string("pk")));
      spec.withField(new AuthentikFieldSpec("name", "Name", QFieldType.STRING, string("name"))
         .withFilter(QCriteriaOperator.EQUALS, "name").withSearchable().withOrdering("name"));
      spec.withField(new AuthentikFieldSpec("isSuperuser", "Superuser (own flag)", QFieldType.BOOLEAN, bool("is_superuser"))
         .withFilter(QCriteriaOperator.EQUALS, "is_superuser"));
      spec.withField(new AuthentikFieldSpec("isSuperuserInherited", "Superuser (incl. parents)", QFieldType.BOOLEAN, o -> null));
      spec.withField(new AuthentikFieldSpec("parentNames", "Parents", QFieldType.STRING, joined("parents_obj", "name")));
      spec.withField(new AuthentikFieldSpec("childNames", "Children", QFieldType.STRING, joined("children_obj", "name")));
      spec.withField(new AuthentikFieldSpec("memberCount", "Members", QFieldType.INTEGER, AuthentikJson.arrayLength("users")));
      spec.withField(new AuthentikFieldSpec("memberUsername", "Member Username", QFieldType.STRING, o -> null)
         .withFilter(QCriteriaOperator.EQUALS, "members_by_username").withFilter(QCriteriaOperator.IN, "members_by_username").withHidden());
      spec.withField(new AuthentikFieldSpec("permissions", "QQQ Permissions", QFieldType.TEXT, attributeList(AuthentikJson.ATTR_PERMISSIONS)));
      spec.withField(new AuthentikFieldSpec("appAccess", "App Access", QFieldType.TEXT, attributeList(AuthentikJson.ATTR_APP_ACCESS)));
      spec.withField(new AuthentikFieldSpec("roleNames", "Roles", QFieldType.STRING, joined("roles_obj", "name")));
      spec.withField(new AuthentikFieldSpec("numPk", "Numeric Id", QFieldType.INTEGER, integer("num_pk")).withHidden());
      spec.withField(new AuthentikFieldSpec("parentPks", "Parent Ids", QFieldType.TEXT, json("parents")).withHidden());
      spec.withField(new AuthentikFieldSpec("attributes", "Attributes", QFieldType.TEXT, json("attributes")).withSensitive());
      return (spec);
   }

}
