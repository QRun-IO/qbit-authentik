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


import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import com.kingsrook.qqq.backend.core.actions.permissions.AvailablePermission;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaDataInterface;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppChildMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.MetaDataWithPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.reporting.QReportMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.utils.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;


/*******************************************************************************
 ** What a policy can grant in a QInstance (DESIGN.md section 12.4): every app,
 ** table, process, report and protected widget, with its permission base name
 ** (the policy resource) and the actions QQQ checks for it, grouped by app.
 **
 ** Unlike PermissionsHelper.getAllAvailablePermissions, hidden tables and
 ** processes are included: record actions are hidden from the nav but still
 ** permission-checked. Objects with a custom permission checker or that are
 ** NOT_PROTECTED are left out (a policy cannot grant them).
 *******************************************************************************/
public final class PolicyCatalog
{
   /** Group label of objects that are in no app. */
   public static final String OTHER = "Other";

   /** Kinds of resources. */
   public enum Kind
   {
      APP, TABLE, PROCESS, REPORT, WIDGET
   }



   /*******************************************************************************
    ** One grantable resource.
    **
    ** @param name    the policy resource (permission base name)
    ** @param label   what operators see
    ** @param kind    app, table, process, report or widget
    ** @param actions the actions QQQ checks, in canonical order
    ** @param features explicitly grantable table features, sorted by name
    ** @param note    a plain note (e.g. why an action is missing), or null
    *******************************************************************************/
   public record Resource(String name, String label, Kind kind, List<PolicyAction> actions, List<Feature> features, String note)
   {
      /*******************************************************************************
       ** A resource with only standard actions.
       *******************************************************************************/
      public Resource(String name, String label, Kind kind, List<PolicyAction> actions, String note)
      {
         this(name, label, kind, actions, List.of(), note);
      }
   }



   /*******************************************************************************
    ** A table feature's permission suffix and display label from QQQ.
    *******************************************************************************/
   public record Feature(String name, String label)
   {
   }



   /*******************************************************************************
    ** The resources of one app (or of no app: OTHER).
    *******************************************************************************/
   public record Group(String app, String label, List<Resource> resources)
   {
   }



   private final List<Group>           groups;
   private final Map<String, Resource> byName;



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   private PolicyCatalog(List<Group> groups)
   {
      this.groups = groups;
      this.byName = new LinkedHashMap<>();
      for(Group group : groups)
      {
         for(Resource resource : group.resources())
         {
            byName.putIfAbsent(resource.name(), resource);
         }
      }
   }



   /*******************************************************************************
    ** Build the catalog of an instance.
    *******************************************************************************/
   public static PolicyCatalog of(QInstance qInstance)
   {
      return (of(qInstance, PermissionsHelper.getAllAvailablePermissions(qInstance)));
   }



   /*******************************************************************************
    ** Build using an explicit permission source, including features registered
    ** by core. This needs no dependency on the feature metadata hook itself.
    *******************************************************************************/
   public static PolicyCatalog of(QInstance qInstance, Collection<AvailablePermission> availablePermissions)
   {
      Map<String, String>                     appOfObject = appsOfObjects(qInstance);
      Map<String, Map<String, ResourceDraft>> byApp       = new LinkedHashMap<>();

      List<QAppMetaData> apps = new ArrayList<>(qInstance.getApps().values());
      apps.sort(Comparator.comparing((QAppMetaData a) -> a.getSortOrder() == null ? 500 : a.getSortOrder()).thenComparing(a -> label(a.getLabel(), a.getName())));
      for(QAppMetaData app : apps)
      {
         byApp.put(app.getName(), new LinkedHashMap<>());
      }
      byApp.put(null, new LinkedHashMap<>());

      for(QAppMetaData app : apps)
      {
         add(byApp, app.getName(), qInstance, app, Kind.APP, label(app.getLabel(), app.getName()), EnumSet.of(PolicyAction.HAS_ACCESS), null);
      }

      List<QTableMetaData> tables = new ArrayList<>(qInstance.getTables().values());
      tables.sort(Comparator.comparing(t -> label(t.getLabel(), t.getName())));
      for(QTableMetaData table : tables)
      {
         QPermissionRules rules = PermissionsHelper.getEffectivePermissionRules(table, qInstance);
         Set<PolicyAction> actions = EnumSet.noneOf(PolicyAction.class);
         String            note    = null;
         if(rules.getLevel() == PermissionLevel.HAS_ACCESS_PERMISSION)
         {
            actions.add(PolicyAction.HAS_ACCESS);
         }
         else
         {
            QBackendMetaData backend = qInstance.getBackend(table.getBackendName());
            if(table.isCapabilityEnabled(backend, Capability.TABLE_QUERY) || table.isCapabilityEnabled(backend, Capability.TABLE_GET))
            {
               actions.add(PolicyAction.READ);
            }
            if(rules.getLevel() == PermissionLevel.READ_WRITE_PERMISSIONS)
            {
               note = "This table uses one write permission instead of separate insert, edit and delete actions.";
            }
            else
            {
               if(table.isCapabilityEnabled(backend, Capability.TABLE_INSERT))
               {
                  actions.add(PolicyAction.INSERT);
               }
               if(table.isCapabilityEnabled(backend, Capability.TABLE_UPDATE))
               {
                  actions.add(PolicyAction.EDIT);
               }
               if(table.isCapabilityEnabled(backend, Capability.TABLE_DELETE))
               {
                  actions.add(PolicyAction.DELETE);
               }
            }
         }
         String baseName = StringUtils.hasContent(rules.getPermissionBaseName()) ? rules.getPermissionBaseName() : table.getName();
         Map<String, Feature> features = new TreeMap<>();
         for(AvailablePermission permission : availablePermissions)
         {
            if(permission.getName().startsWith(baseName + "."))
            {
               String suffix = permission.getName().substring(baseName.length() + 1);
               if(!suffix.isEmpty() && PolicyAction.fromJsonName(suffix).isEmpty())
               {
                  features.putIfAbsent(suffix, new Feature(suffix, permission.getPermissionType()));
               }
            }
         }
         add(byApp, appOfObject.get("table:" + table.getName()), qInstance, table, Kind.TABLE, label(table.getLabel(), table.getName()), actions, features, note);
      }

      List<QProcessMetaData> processes = new ArrayList<>(qInstance.getProcesses().values());
      processes.sort(Comparator.comparing(p -> label(p.getLabel(), p.getName())));
      for(QProcessMetaData process : processes)
      {
         String app = appOfObject.get("process:" + process.getName());
         if(app == null && process.getTableName() != null)
         {
            app = appOfObject.get("table:" + process.getTableName());
         }
         String label = label(process.getLabel(), process.getName());
         if(process.getTableName() != null && qInstance.getTable(process.getTableName()) != null)
         {
            label = label + " (" + label(qInstance.getTable(process.getTableName()).getLabel(), process.getTableName()) + " action)";
         }
         add(byApp, app, qInstance, process, Kind.PROCESS, label, EnumSet.of(PolicyAction.HAS_ACCESS), null);
      }

      List<QReportMetaData> reports = new ArrayList<>(qInstance.getReports().values());
      reports.sort(Comparator.comparing(r -> label(r.getLabel(), r.getName())));
      for(QReportMetaData report : reports)
      {
         add(byApp, appOfObject.get("report:" + report.getName()), qInstance, report, Kind.REPORT, label(report.getLabel(), report.getName()), EnumSet.of(PolicyAction.HAS_ACCESS), null);
      }

      List<QWidgetMetaDataInterface> widgets = new ArrayList<>(qInstance.getWidgets().values());
      widgets.sort(Comparator.comparing(w -> label(w.getLabel(), w.getName())));
      for(QWidgetMetaDataInterface widget : widgets)
      {
         add(byApp, appOfObject.get("widget:" + widget.getName()), qInstance, widget, Kind.WIDGET, label(widget.getLabel(), widget.getName()), EnumSet.of(PolicyAction.HAS_ACCESS), null);
      }

      List<Group> groups = new ArrayList<>();
      for(Map.Entry<String, Map<String, ResourceDraft>> entry : byApp.entrySet())
      {
         if(entry.getValue().isEmpty())
         {
            continue;
         }
         String groupLabel = entry.getKey() == null ? OTHER : label(qInstance.getApp(entry.getKey()).getLabel(), entry.getKey());
         List<Resource> resources = new ArrayList<>();
         for(ResourceDraft draft : entry.getValue().values())
         {
            resources.add(new Resource(draft.name, String.join(" / ", draft.labels), draft.kind, new ArrayList<>(draft.actions), List.copyOf(draft.features.values()), draft.note));
         }
         groups.add(new Group(entry.getKey(), groupLabel, resources));
      }
      return (new PolicyCatalog(groups));
   }



   /*******************************************************************************
    ** Accumulates one resource while building (several objects can share a
    ** permission base name).
    *******************************************************************************/
   private static class ResourceDraft
   {
      private final String            name;
      private final Kind              kind;
      private final Set<String>       labels  = new LinkedHashSet<>();
      private final Set<PolicyAction> actions = new TreeSet<>();
      private final Map<String, Feature> features = new TreeMap<>();
      private String                  note;



      /*******************************************************************************
       ** Constructor.
       *******************************************************************************/
      ResourceDraft(String name, Kind kind)
      {
         this.name = name;
         this.kind = kind;
      }
   }



   /*******************************************************************************
    ** Add an object under its app, unless a policy cannot grant it.
    *******************************************************************************/
   private static void add(Map<String, Map<String, ResourceDraft>> byApp, String app, QInstance qInstance, MetaDataWithPermissionRules object, Kind kind, String label,
      Set<PolicyAction> actions, String note)
   {
      add(byApp, app, qInstance, object, kind, label, actions, Map.of(), note);
   }



   /*******************************************************************************
    ** Add standard and feature actions, merging shared permission base names.
    *******************************************************************************/
   private static void add(Map<String, Map<String, ResourceDraft>> byApp, String app, QInstance qInstance, MetaDataWithPermissionRules object, Kind kind, String label,
      Set<PolicyAction> actions, Map<String, Feature> features, String note)
   {
      QPermissionRules rules = PermissionsHelper.getEffectivePermissionRules(object, qInstance);
      if(rules == null || rules.getLevel() == null || rules.getLevel() == PermissionLevel.NOT_PROTECTED || rules.getCustomPermissionChecker() != null || (actions.isEmpty() && features.isEmpty()))
      {
         return;
      }
      String name = StringUtils.hasContent(rules.getPermissionBaseName()) ? rules.getPermissionBaseName() : nameOf(object);
      if(!PolicyParser.RESOURCE_PATTERN.matcher(name).matches())
      {
         return;
      }

      ////////////////////////////////////////////////////////////////////
      // a base name shared with an object already listed (in any app) //
      // joins that entry, so a resource appears once                  //
      ////////////////////////////////////////////////////////////////////
      for(Map<String, ResourceDraft> resources : byApp.values())
      {
         ResourceDraft existing = resources.get(name);
         if(existing != null)
         {
            existing.labels.add(label);
            existing.actions.addAll(actions);
            existing.features.putAll(features);
            return;
         }
      }

      ResourceDraft draft = new ResourceDraft(name, kind);
      draft.labels.add(label);
      draft.actions.addAll(actions);
      draft.features.putAll(features);
      draft.note = note;
      byApp.computeIfAbsent(byApp.containsKey(app) ? app : null, k -> new LinkedHashMap<>()).put(name, draft);
   }



   /*******************************************************************************
    ** Which app directly lists each object ("table:x", "process:y", ...): app
    ** children (sections included) and app widgets. The first app wins.
    *******************************************************************************/
   private static Map<String, String> appsOfObjects(QInstance qInstance)
   {
      Map<String, String> rs = new LinkedHashMap<>();
      for(QAppMetaData app : qInstance.getApps().values())
      {
         if(app.getChildren() != null)
         {
            for(QAppChildMetaData child : app.getChildren())
            {
               String type = child instanceof QTableMetaData ? "table" : child instanceof QProcessMetaData ? "process" : child instanceof QReportMetaData ? "report" : null;
               if(type != null)
               {
                  rs.putIfAbsent(type + ":" + child.getName(), app.getName());
               }
            }
         }
         if(app.getWidgets() != null)
         {
            for(String widget : app.getWidgets())
            {
               rs.putIfAbsent("widget:" + widget, app.getName());
            }
         }
      }
      return (rs);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String nameOf(MetaDataWithPermissionRules object)
   {
      if(object instanceof QTableMetaData t)
      {
         return (t.getName());
      }
      if(object instanceof QProcessMetaData p)
      {
         return (p.getName());
      }
      if(object instanceof QAppMetaData a)
      {
         return (a.getName());
      }
      if(object instanceof QReportMetaData r)
      {
         return (r.getName());
      }
      if(object instanceof QWidgetMetaDataInterface w)
      {
         return (w.getName());
      }
      return ("");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String label(String label, String name)
   {
      return (StringUtils.hasContent(label) ? label : name);
   }



   /*******************************************************************************
    ** The groups, in app order, "Other" last.
    *******************************************************************************/
   public List<Group> getGroups()
   {
      return (groups);
   }



   /*******************************************************************************
    ** A resource by policy name, or null.
    *******************************************************************************/
   public Resource get(String name)
   {
      return (byName.get(name));
   }



   /*******************************************************************************
    ** Every QQQ permission a policy can grant here ({resource}.{action}).
    *******************************************************************************/
   public Set<String> permissionNames()
   {
      Set<String> rs = new TreeSet<>();
      for(Resource resource : byName.values())
      {
         for(PolicyAction action : resource.actions())
         {
            rs.add(action.permission(resource.name()));
         }
         resource.features().forEach(feature -> rs.add(resource.name() + "." + feature.name()));
      }
      return (rs);
   }



   /*******************************************************************************
    ** The resources of a permission set this catalog does not know, or that
    ** grant an action the resource does not have (sorted, as permission names).
    *******************************************************************************/
   public Set<String> unknownPermissions(Set<String> permissions)
   {
      Set<String> known = permissionNames();
      Set<String> rs    = new TreeSet<>();
      for(String permission : permissions)
      {
         if(!known.contains(permission))
         {
            rs.add(permission);
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** Whether this resource has an explicitly registered feature action.
    *******************************************************************************/
   public boolean hasFeature(String resourceName, String actionName)
   {
      Resource resource = get(resourceName);
      return (resource != null && resource.features().stream().anyMatch(feature -> feature.name().equals(actionName)));
   }



   /*******************************************************************************
    ** As JSON for the editor widget.
    *******************************************************************************/
   public JSONArray toJson()
   {
      JSONArray rs = new JSONArray();
      for(Group group : groups)
      {
         JSONArray resources = new JSONArray();
         for(Resource resource : group.resources())
         {
            JSONArray actions = new JSONArray();
            resource.actions().forEach(a -> actions.put(a.getJsonName()));
            JSONObject json = new JSONObject()
               .put("name", resource.name())
               .put("label", resource.label())
               .put("kind", resource.kind().name())
               .put("actions", actions);
            if(resource.kind() == Kind.TABLE || !resource.features().isEmpty())
            {
               JSONArray features = new JSONArray();
               resource.features().forEach(feature -> features.put(new JSONObject().put("name", feature.name()).put("label", feature.label())));
               json.put("features", features);
            }
            if(resource.note() != null)
            {
               json.put("note", resource.note());
            }
            resources.put(json);
         }
         rs.put(new JSONObject().put("app", group.app() == null ? JSONObject.NULL : group.app()).put("label", group.label()).put("resources", resources));
      }
      return (rs);
   }
}
