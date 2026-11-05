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

package com.kingsrook.qbits.authentik.processes;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.admin.AuthentikAdmin;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.QWidgetData;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;

/*******************************************************************************
 ** Metadata-driven grant checkboxes and server-searched assignment selectors.
 ** These produce ordinary admin requests; the widget never writes to Authentik.
 *******************************************************************************/
public final class AccessEditorWidget
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AccessEditorWidget()
   {
   }

   /*******************************************************************************
    ** Processes with structured access fields.
    *******************************************************************************/
   public static boolean supports(AuthentikProcesses.Def def)
   {
      return (def.fields().stream().anyMatch(f -> List.of("permissions", "appAccess", "parentIds", "groupIds", "userIds").contains(f.getName())));
   }

   /*******************************************************************************
    ** Each process has its own immutable editor configuration.
    *******************************************************************************/
   public static String name(AuthentikQBitConfig config, AuthentikProcesses.Def def)
   {
      return (config.applyPrefix(def.key() + "AccessEditor"));
   }

   /*******************************************************************************
    ** Register a widget with the same permission as its process.
    *******************************************************************************/
   public static QWidgetMetaData metadata(AuthentikQBitConfig config, AuthentikProcesses.Def def)
   {
      return (new QWidgetMetaData().withName(name(config, def)).withLabel("Permissions and assignments")
         .withType("AUTHENTIK_ACCESS_EDITOR").withGridColumns(12).withIsCard(false)
         .withCodeReference(new QCodeReference(Renderer.class)).withPermissionRules(def.action().getPermission().rules())
         .withDefaultValue("backendName", config.getApiBackendName()).withDefaultValue("processKey", def.key()));
   }

   /*******************************************************************************
    ** Load live initial grants. Inherited permissions remain separate from edits.
    *******************************************************************************/
   public static Data load(AuthentikQBitConfig config, AuthentikProcesses.Def def, String pk) throws QException
   {
      AuthentikRuntime runtime = AuthentikRuntime.forBackend(config.getApiBackendName());
      runtime.getGuard().authorize(def.action());
      AuthentikActionUtil util = AuthentikActionUtil.forBackend(config.getApiBackendName());
      GroupGraph graph = util.groupGraph();
      GroupGraph.Node node = null;
      boolean userAccess = def.action() == com.kingsrook.qbits.authentik.admin.AdminAction.EDIT_USER_PERMISSIONS;
      if(userAccess)
      {
         if(pk == null || !pk.matches("[1-9][0-9]*"))
         {
            throw (new QUserFacingException("Select a user and open the editor again."));
         }
         var user = util.getObject(AuthentikTables.get(AuthentikTables.USER), pk);
         if(user == null || !runtime.getGuard().isUserInScope(user))
         {
            throw (new QUserFacingException("That user is unavailable."));
         }
         var group = AuthentikAdmin.forBackend(config.getApiBackendName()).userAccessGroup(pk);
         node = group == null ? null : graph.byPk(group.getString("pk"));
      }
      else if(def.prefill())
      {
         if(pk == null || graph.byPk(pk) == null)
         {
            throw (new QUserFacingException("Select a group or application role and open the editor again."));
         }
         node = graph.byPk(pk);
      }
      List<Map<String, Object>> fields = new ArrayList<>();
      for(var field : def.fields())
      {
         String key = field.getName();
         if(!List.of("permissions", "appAccess", "parentIds", "groupIds", "userIds").contains(key))
         {
            continue;
         }
         Map<String, Object> item = new LinkedHashMap<>();
         item.put("name", key);
         List<Map<String, String>> selected = new ArrayList<>();
         if(key.equals("permissions"))
         {
            item.put("label", "Direct permissions");
            item.put("catalogWidget", name(config, def));
            if(node != null)
            {

               node.permissions().forEach(value -> selected.add(Map.of("id", value, "label", value)));
               var inherited = new EffectivePermissionResolver(graph, runtime.getPermissionCatalog()).resolveGroups(node.parentPks());
               item.put("inherited", inherited.grantedBy());
               item.put("policyPermissions", node.policyPermissions());
            }
            if(userAccess)
            {
               List<String> inheritedGroups = new ArrayList<>(util.groupGraphWithMembers().groupsOfUser(Integer.parseInt(pk)));
               if(node != null)
               {
                  inheritedGroups.remove(node.pk());
               }
               item.put("inherited", new EffectivePermissionResolver(graph, runtime.getPermissionCatalog()).resolveGroups(inheritedGroups).grantedBy());
            }

         }
         else if(key.equals("appAccess"))
         {
            item.put("label", "Application sign-in access");
            TreeSet<String> choices = new TreeSet<>();
            choices.add(config.getAppKey());
            graph.nodes().forEach(group -> choices.addAll(group.appAccess()));
            for(var application : util.getAllPages("/core/applications/?ordering=name", 1000))
            {
               choices.add(application.getString("slug"));
            }
            if(node != null)
            {
               node.appAccess().forEach(value -> selected.add(Map.of("id", value, "label", value)));
            }
            item.put("choices", choices.stream().map(value -> Map.of("id", value, "label", value)).toList());
         }
         else
         {
            boolean users = key.equals("userIds");
            item.put("label", users ? "Users" : key.equals("parentIds") ? "Inherit from groups and application roles" : "Groups and application roles");
            item.put("source", config.applyTablePrefix(users ? AuthentikTables.USER : AuthentikTables.GROUP));
            if(key.equals("parentIds") && node != null)
            {
               for(String parentPk : node.parentPks())
               {
                  GroupGraph.Node parent = graph.byPk(parentPk);
                  selected.add(Map.of("id", parentPk, "label", parent == null ? parentPk : parent.name()));
               }
            }
         }
         item.put("selected", selected);
         fields.add(item);
      }
      return (new Data(fields));
   }

   /*******************************************************************************
    ** Render the configured editor; process values supply only the selected key.
    *******************************************************************************/
   public static class Renderer extends AbstractWidgetRenderer
   {
      /*******************************************************************************
       ** Resolve configuration on the server and enforce the action guard.
       *******************************************************************************/
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         var defaults = ((QWidgetMetaData) input.getWidgetMetaData()).getDefaultValues();
         AuthentikQBitConfig config = AuthentikRuntime.forBackend(String.valueOf(defaults.get("backendName"))).getConfig();
         String key = String.valueOf(defaults.get("processKey"));
         AuthentikProcesses.Def def = AuthentikProcesses.definitions(config).stream().filter(d -> d.key().equals(key)).findFirst()
            .orElseThrow(() -> new QUserFacingException("This access editor is no longer available."));
         if(input.getQueryParams() != null && "true".equals(input.getQueryParams().get("accessCatalog")))
         {
            AuthentikRuntime runtime = AuthentikRuntime.forBackend(config.getApiBackendName());
            runtime.getGuard().authorize(def.action());
            return (new RenderWidgetOutput(new Data(List.of(AccessCatalog.page(runtime.getPermissionCatalog(), runtime.getPolicyCatalog(), input.getQueryParams())))));
         }
         return (new RenderWidgetOutput(load(config, def, input.getQueryParams() == null ? null : input.getQueryParams().get("accessEditorPk"))));
      }
   }

   /*******************************************************************************
    ** Serializable metadata for the frontend; choices are not authorization.
    *******************************************************************************/
   public static class Data extends QWidgetData
   {
      private final List<Map<String, Object>> fields;

      /*******************************************************************************
       ** Frontend renderer type.
       *******************************************************************************/
      @Override
      public String getType()
      {
         return ("AUTHENTIK_ACCESS_EDITOR");
      }

      /*******************************************************************************
       ** Create the editor payload.
       *******************************************************************************/
      public Data(List<Map<String, Object>> fields)
      {
         this.fields = fields;
      }

      /*******************************************************************************
       ** Fields rendered by the access editor.
       *******************************************************************************/
      public List<Map<String, Object>> getFields()
      {
         return (fields);
      }
   }
}
