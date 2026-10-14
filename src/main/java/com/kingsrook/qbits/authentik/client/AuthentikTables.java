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
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.at;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.attributeList;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.bool;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.instant;
import static com.kingsrook.qbits.authentik.client.AuthentikJson.intAt;
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
   public static final String USER         = "user";
   public static final String GROUP        = "group";
   public static final String GROUP_MEMBER = "groupMember";
   public static final String SESSION      = "session";
   public static final String EVENT        = "event";
   public static final String APPLICATION  = "application";
   public static final String POLICY_BINDING = "policyBinding";
   public static final String BLUEPRINT    = "blueprint";
   public static final String ROLE         = "role";
   public static final String TOKEN        = "token";
   public static final String INVITATION   = "invitation";

   /*******************************************************************************
    ** Table names produced before the owner naming rule (2026-10-12), with the
    ** default prefix. Kept only to find stored references (permissions, saved
    ** views, audit table names) when upgrading; see UPGRADE.md.
    *******************************************************************************/
   @Deprecated
   public static final String LEGACY_USER_TABLE_NAME         = "authentikUser";
   @Deprecated
   public static final String LEGACY_GROUP_TABLE_NAME        = "authentikGroup";
   @Deprecated
   public static final String LEGACY_GROUP_MEMBER_TABLE_NAME = "authentikGroupMember";
   @Deprecated
   public static final String LEGACY_SESSION_TABLE_NAME      = "authentikSession";
   @Deprecated
   public static final String LEGACY_EVENT_TABLE_NAME        = "authentikEvent";

   /** User types the qbit shows by default: everything but outposts' internal service accounts. */
   public static final String[] DEFAULT_USER_TYPES = { "internal", "external", "service_account" };

   private static final Map<String, AuthentikTableSpec> SPECS = new LinkedHashMap<>();

   static
   {
      register(users());
      register(groups());
      register(groupMembers());
      register(sessions());
      register(events());
      register(applications());
      register(policyBindings());
      register(blueprints());
      register(roles());
      register(tokens());
      register(invitations());
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
      spec.withField(new AuthentikFieldSpec("effectivePermissions", "Effective QQQ Permissions", QFieldType.TEXT, o -> null));
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
         .withDefaultListParam("include_users", "true")
         .withDefaultListParam("include_parents", "true")
         .withDefaultListParam("include_children", "true")
         .withDefaultGetParam("include_users", "true")
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
      spec.withField(new AuthentikFieldSpec("effectivePermissions", "Effective QQQ Permissions (incl. parents)", QFieldType.TEXT, o -> null));
      spec.withField(new AuthentikFieldSpec("appAccess", "App Access", QFieldType.TEXT, attributeList(AuthentikJson.ATTR_APP_ACCESS)));
      spec.withField(new AuthentikFieldSpec("roleNames", "Roles", QFieldType.STRING, joined("roles_obj", "name")));
      spec.withField(new AuthentikFieldSpec("numPk", "Numeric Id", QFieldType.INTEGER, integer("num_pk")).withHidden());
      spec.withField(new AuthentikFieldSpec("parentPks", "Parent Ids", QFieldType.TEXT, json("parents")).withHidden());
      spec.withField(new AuthentikFieldSpec("attributes", "Attributes", QFieldType.TEXT, json("attributes")).withSensitive());
      return (spec);
   }



   /*******************************************************************************
    ** Virtual membership table (group x user). Served by AuthentikActionUtil
    ** from GET /core/groups/{pk}/?include_users=true, GET /core/users/{pk}/
    ** (groups_obj) or a group sweep; rows are synthetic objects keyed by these
    ** field names. Key: "groupPk:userPk".
    *******************************************************************************/
   static AuthentikTableSpec groupMembers()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(GROUP_MEMBER, "Group Memberships", "group_add", "/core/groups/", "id")
         .withVirtual()
         .withDefaultOrdering("groupName")
         .withRecordLabelFields("groupName", "username");

      spec.withField(new AuthentikFieldSpec("id", "Id", QFieldType.STRING, string("id")));
      spec.withField(new AuthentikFieldSpec("groupName", "Group", QFieldType.STRING, string("groupName"))
         .withFilter(QCriteriaOperator.EQUALS, "groupName").withOrdering("groupName"));
      spec.withField(new AuthentikFieldSpec("username", "Username", QFieldType.STRING, string("username"))
         .withFilter(QCriteriaOperator.EQUALS, "username").withOrdering("username"));
      spec.withField(new AuthentikFieldSpec("name", "Name", QFieldType.STRING, string("name")));
      spec.withField(new AuthentikFieldSpec("email", "Email", QFieldType.STRING, string("email")));
      spec.withField(new AuthentikFieldSpec("isActive", "Active", QFieldType.BOOLEAN, bool("isActive")));
      spec.withField(new AuthentikFieldSpec("groupPk", "Group Id", QFieldType.STRING, string("groupPk"))
         .withFilter(QCriteriaOperator.EQUALS, "groupPk").withFilter(QCriteriaOperator.IN, "groupPk"));
      spec.withField(new AuthentikFieldSpec("userPk", "User Id", QFieldType.INTEGER, integer("userPk"))
         .withFilter(QCriteriaOperator.EQUALS, "userPk"));
      return (spec);
   }



   /*******************************************************************************
    ** /core/authenticated_sessions/ (uuid). IPs and user agents need audit.read.
    *******************************************************************************/
   static AuthentikTableSpec sessions()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(SESSION, "Sessions", "devices", "/core/authenticated_sessions/", "uuid")
         .withReadPermission(IdentityPermission.AUDIT_READ)
         .withRecordLabelFields("uuid");

      spec.withField(new AuthentikFieldSpec("uuid", "Id", QFieldType.STRING, string("uuid")));
      spec.withField(new AuthentikFieldSpec("userPk", "User Id", QFieldType.INTEGER, integer("user")));
      spec.withField(new AuthentikFieldSpec("username", "Username", QFieldType.STRING, o -> null)
         .withFilter(QCriteriaOperator.EQUALS, "user__username").withHidden());
      spec.withField(new AuthentikFieldSpec("lastIp", "Last IP", QFieldType.STRING, string("last_ip"))
         .withFilter(QCriteriaOperator.EQUALS, "session__last_ip"));
      spec.withField(new AuthentikFieldSpec("lastUserAgent", "Last User Agent", QFieldType.TEXT, string("last_user_agent")));
      spec.withField(new AuthentikFieldSpec("lastUsed", "Last Used", QFieldType.DATE_TIME, instant("last_used")));
      spec.withField(new AuthentikFieldSpec("expires", "Expires", QFieldType.DATE_TIME, instant("expires")));
      spec.withField(new AuthentikFieldSpec("current", "Current", QFieldType.BOOLEAN, bool("current")));
      spec.withField(new AuthentikFieldSpec("geoIp", "Geo IP", QFieldType.TEXT, json("geo_ip")));
      spec.withField(new AuthentikFieldSpec("asn", "ASN", QFieldType.TEXT, json("asn")));
      return (spec);
   }



   /*******************************************************************************
    ** /events/events/ (uuid). Event contexts and client IPs need audit.read.
    *******************************************************************************/
   static AuthentikTableSpec events()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(EVENT, "Events", "receipt_long", "/events/events/", "pk")
         .withReadPermission(IdentityPermission.AUDIT_READ)
         .withDefaultOrdering("-created")
         .withRecordLabelFields("action", "created");

      spec.withField(new AuthentikFieldSpec("pk", "Id", QFieldType.STRING, string("pk")));
      spec.withField(new AuthentikFieldSpec("created", "Created", QFieldType.DATE_TIME, instant("created")).withOrdering("created"));
      spec.withField(new AuthentikFieldSpec("action", "Action", QFieldType.STRING, string("action"))
         .withFilter(QCriteriaOperator.EQUALS, "action").withFilter(QCriteriaOperator.IN, "actions"));
      spec.withField(new AuthentikFieldSpec("username", "Username", QFieldType.STRING, at("user", "username"))
         .withFilter(QCriteriaOperator.EQUALS, "username"));
      spec.withField(new AuthentikFieldSpec("userPk", "User Id", QFieldType.INTEGER, intAt("user", "pk")));
      spec.withField(new AuthentikFieldSpec("app", "App", QFieldType.STRING, string("app")));
      spec.withField(new AuthentikFieldSpec("clientIp", "Client IP", QFieldType.STRING, string("client_ip"))
         .withFilter(QCriteriaOperator.EQUALS, "client_ip"));
      spec.withField(new AuthentikFieldSpec("modelApp", "Model App", QFieldType.STRING, at("context", "model", "app"))
         .withFilter(QCriteriaOperator.EQUALS, "context_model_app"));
      spec.withField(new AuthentikFieldSpec("modelName", "Model", QFieldType.STRING, at("context", "model", "model_name"))
         .withFilter(QCriteriaOperator.EQUALS, "context_model_name"));
      spec.withField(new AuthentikFieldSpec("modelPk", "Model Id", QFieldType.STRING, at("context", "model", "pk"))
         .withFilter(QCriteriaOperator.EQUALS, "context_model_pk"));
      spec.withField(new AuthentikFieldSpec("modelLabel", "Object", QFieldType.STRING, at("context", "model", "name")));
      spec.withField(new AuthentikFieldSpec("authorizedApp", "Authorized App", QFieldType.STRING, at("context", "authorized_application", "slug"))
         .withFilter(QCriteriaOperator.EQUALS, "context_authorized_app"));
      spec.withField(new AuthentikFieldSpec("context", "Context", QFieldType.TEXT, json("context")));
      spec.withField(new AuthentikFieldSpec("expires", "Expires", QFieldType.DATE_TIME, instant("expires")));
      return (spec);
   }

   /*******************************************************************************
    ** /core/applications/ (slug). Read only. A non-superuser caller (the service
    ** account) sees only applications it can itself access, so the qbit never
    ** relies on this list for access decisions (DESIGN.md 0.2 iii).
    *******************************************************************************/
   static AuthentikTableSpec applications()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(APPLICATION, "Applications", "apps", "/core/applications/", "slug")
         .withDefaultOrdering("name")
         .withRecordLabelFields("name");
      spec.withField(new AuthentikFieldSpec("slug", "Slug", QFieldType.STRING, string("slug")).withFilter(QCriteriaOperator.EQUALS, "slug"));
      spec.withField(new AuthentikFieldSpec("name", "Name", QFieldType.STRING, string("name")).withSearchable().withOrdering("name"));
      spec.withField(new AuthentikFieldSpec("group", "Group", QFieldType.STRING, string("group")).withFilter(QCriteriaOperator.EQUALS, "group"));
      spec.withField(new AuthentikFieldSpec("providerName", "Provider", QFieldType.STRING, at("provider_obj", "name")));
      spec.withField(new AuthentikFieldSpec("policyEngineMode", "Policy Engine Mode", QFieldType.STRING, string("policy_engine_mode")));
      spec.withField(new AuthentikFieldSpec("launchUrl", "Launch URL", QFieldType.STRING, string("launch_url")));
      spec.withField(new AuthentikFieldSpec("publisher", "Publisher", QFieldType.STRING, string("meta_publisher")).withFilter(QCriteriaOperator.EQUALS, "meta_publisher"));
      spec.withField(new AuthentikFieldSpec("hiddenFromLibrary", "Hidden", QFieldType.BOOLEAN, bool("meta_hide")));
      spec.withField(new AuthentikFieldSpec("bindingTarget", "Binding Target", QFieldType.STRING, string("pbm_uuid")).withHidden());
      return (spec);
   }



   /*******************************************************************************
    ** /policies/bindings/ (uuid): who or what an application's access policy
    ** binds. Read only.
    *******************************************************************************/
   static AuthentikTableSpec policyBindings()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(POLICY_BINDING, "Policy Bindings", "rule", "/policies/bindings/", "pk")
         .withDefaultOrdering("order")
         .withRecordLabelFields("pk");
      spec.withField(new AuthentikFieldSpec("pk", "Id", QFieldType.STRING, string("pk")));
      spec.withField(new AuthentikFieldSpec("target", "Target Id", QFieldType.STRING, string("target")).withFilter(QCriteriaOperator.EQUALS, "target").withHidden());
      spec.withField(new AuthentikFieldSpec("policyName", "Policy", QFieldType.STRING, at("policy_obj", "name")));
      spec.withField(new AuthentikFieldSpec("groupName", "Group", QFieldType.STRING, at("group_obj", "name")));
      spec.withField(new AuthentikFieldSpec("username", "User", QFieldType.STRING, at("user_obj", "username")));
      spec.withField(new AuthentikFieldSpec("negate", "Negate", QFieldType.BOOLEAN, bool("negate")));
      spec.withField(new AuthentikFieldSpec("enabled", "Enabled", QFieldType.BOOLEAN, bool("enabled")).withFilter(QCriteriaOperator.EQUALS, "enabled"));
      spec.withField(new AuthentikFieldSpec("order", "Order", QFieldType.INTEGER, integer("order")).withFilter(QCriteriaOperator.EQUALS, "order").withOrdering("order"));
      spec.withField(new AuthentikFieldSpec("expires", "Expires", QFieldType.DATE_TIME, instant("expires")));
      return (spec);
   }



   /*******************************************************************************
    ** /managed/blueprints/ (uuid). Read only; the drift report uses it too.
    *******************************************************************************/
   static AuthentikTableSpec blueprints()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(BLUEPRINT, "Blueprints", "description", "/managed/blueprints/", "pk")
         .withDefaultOrdering("name")
         .withRecordLabelFields("name");
      spec.withField(new AuthentikFieldSpec("pk", "Id", QFieldType.STRING, string("pk")));
      spec.withField(new AuthentikFieldSpec("name", "Name", QFieldType.STRING, string("name")).withSearchable().withOrdering("name"));
      spec.withField(new AuthentikFieldSpec("path", "Path", QFieldType.STRING, string("path")).withFilter(QCriteriaOperator.EQUALS, "path"));
      spec.withField(new AuthentikFieldSpec("status", "Status", QFieldType.STRING, string("status")));
      spec.withField(new AuthentikFieldSpec("enabled", "Enabled", QFieldType.BOOLEAN, bool("enabled")));
      spec.withField(new AuthentikFieldSpec("lastApplied", "Last Applied", QFieldType.DATE_TIME, instant("last_applied")));
      return (spec);
   }



   /*******************************************************************************
    ** /rbac/roles/ (uuid). Read only in v1 (role management is phase 4);
    ** system-managed roles are hidden.
    *******************************************************************************/
   static AuthentikTableSpec roles()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(ROLE, "Roles", "admin_panel_settings", "/rbac/roles/", "pk")
         .withDefaultListParam("managed__isnull", "true")
         .withDefaultOrdering("name")
         .withRecordLabelFields("name");
      spec.withField(new AuthentikFieldSpec("pk", "Id", QFieldType.STRING, string("pk")));
      spec.withField(new AuthentikFieldSpec("name", "Name", QFieldType.STRING, string("name")).withSearchable().withOrdering("name"));
      return (spec);
   }



   /*******************************************************************************
    ** /core/tokens/ (identifier). Metadata only: there is NO key field, and the
    ** service account never reads token keys. Auditors and token managers may read.
    *******************************************************************************/
   static AuthentikTableSpec tokens()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(TOKEN, "Tokens", "key", "/core/tokens/", "identifier")
         .withReadPermission(IdentityPermission.AUDIT_READ)
         .withAlternativeReadPermission(IdentityPermission.TOKENS_MANAGE)
         .withDefaultOrdering("identifier")
         .withRecordLabelFields("identifier");
      spec.withField(new AuthentikFieldSpec("identifier", "Identifier", QFieldType.STRING, string("identifier")).withSearchable().withOrdering("identifier"));
      spec.withField(new AuthentikFieldSpec("intent", "Intent", QFieldType.STRING, string("intent")).withFilter(QCriteriaOperator.EQUALS, "intent"));
      spec.withField(new AuthentikFieldSpec("username", "User", QFieldType.STRING, at("user_obj", "username")).withFilter(QCriteriaOperator.EQUALS, "user__username"));
      spec.withField(new AuthentikFieldSpec("description", "Description", QFieldType.STRING, string("description")));
      spec.withField(new AuthentikFieldSpec("expires", "Expires", QFieldType.DATE_TIME, instant("expires")));
      spec.withField(new AuthentikFieldSpec("expiring", "Expiring", QFieldType.BOOLEAN, bool("expiring")).withFilter(QCriteriaOperator.EQUALS, "expiring"));
      spec.withField(new AuthentikFieldSpec("ownerPk", "Owner Id", QFieldType.INTEGER, intAt("user_obj", "pk")));
      spec.withField(new AuthentikFieldSpec("ownerType", "Owner Type", QFieldType.STRING, at("user_obj", "type")));
      spec.withField(new AuthentikFieldSpec("ownerName", "Owner", QFieldType.STRING, at("user_obj", "name")));
      spec.withField(new AuthentikFieldSpec("managed", "Managed", QFieldType.STRING, string("managed")));
      spec.withField(new AuthentikFieldSpec("lastUsed", "Last Used", QFieldType.DATE_TIME, o -> null));
      spec.withField(new AuthentikFieldSpec("lastUsedNote", "Last Used Note", QFieldType.STRING, o -> null));
      spec.withField(new AuthentikFieldSpec("createdAt", "Created", QFieldType.DATE_TIME, o -> null));
      spec.withField(new AuthentikFieldSpec("scopeSummary", "Scope", QFieldType.STRING, o -> null));
      return (spec);
   }



   /*******************************************************************************
    ** /stages/invitation/invitations/ (uuid). Created by the Invite User action;
    ** cancelled by Cancel Invitation.
    *******************************************************************************/
   static AuthentikTableSpec invitations()
   {
      AuthentikTableSpec spec = new AuthentikTableSpec(INVITATION, "Invitations", "mail", "/stages/invitation/invitations/", "pk")
         .withDefaultOrdering("name")
         .withRecordLabelFields("name");
      spec.withField(new AuthentikFieldSpec("pk", "Id", QFieldType.STRING, string("pk")));
      spec.withField(new AuthentikFieldSpec("name", "Name", QFieldType.STRING, string("name")).withSearchable().withOrdering("name"));
      spec.withField(new AuthentikFieldSpec("email", "Email", QFieldType.STRING, at("fixed_data", "email")));
      spec.withField(new AuthentikFieldSpec("singleUse", "Single Use", QFieldType.BOOLEAN, bool("single_use")));
      spec.withField(new AuthentikFieldSpec("expires", "Expires", QFieldType.DATE_TIME, instant("expires")));
      spec.withField(new AuthentikFieldSpec("flowSlug", "Flow", QFieldType.STRING, at("flow_obj", "slug")));
      spec.withField(new AuthentikFieldSpec("createdBy", "Created By", QFieldType.STRING, at("created_by", "username")));
      return (spec);
   }

}
