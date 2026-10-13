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


import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.admin.AuthentikAdmin;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.QWidgetData;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.utils.StringUtils;
import org.json.JSONObject;


/*******************************************************************************
 ** The policy editor widget (type AUTHENTIK_POLICY_EDITOR, DESIGN.md section
 ** 12.4). It is shown on the Edit Policy step; the Next UI widget of the same
 ** type draws the matrix and hands the generated document back to the step as
 ** the process value policyDocument. The data here: the catalog of what a
 ** policy can grant, and the group's current document read live from
 ** Authentik.
 *******************************************************************************/
public final class PolicyEditorWidget
{
   /** The widget type the Next UI renders. */
   public static final String TYPE = "AUTHENTIK_POLICY_EDITOR";

   /** Short widget name (prefixed with the qbit namespace). */
   public static final String NAME = "policyEditor";

   /** Widget default value naming the qbit's API backend. */
   public static final String BACKEND_NAME_KEY = "backendName";

   /** Widget parameter (process value) with the group's pk. */
   public static final String GROUP_PK_PARAM = "groupPk";



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private PolicyEditorWidget()
   {
   }



   /*******************************************************************************
    ** The data for a group (or for none: an empty document).
    *******************************************************************************/
   public static Data load(AuthentikQBitConfig config, String groupPk) throws QException
   {
      AuthentikRuntime runtime = AuthentikRuntime.forBackend(config.getApiBackendName());
      PolicyFormat     format  = config.getPolicyFormat();
      Data             data    = new Data()
         .withSpec(format.spec())
         .withVersion(format.version())
         .withCatalog(runtime.getPolicyCatalog().toJson().toList())
         .withOutputFieldName(AuthentikAdmin.POLICY_DOCUMENT);

      if(!StringUtils.hasContent(groupPk))
      {
         return (data);
      }
      if(!groupPk.matches("[A-Za-z0-9-]+"))
      {
         throw (new QUserFacingException("Not a group id: " + groupPk));
      }

      JSONObject group = AuthentikActionUtil.forBackend(config.getApiBackendName()).getApiJsonOrNull("/core/groups/" + groupPk + "/?include_users=false&include_parents=false&include_children=false");
      if(group == null)
      {
         throw (new QUserFacingException("That group no longer exists."));
      }
      data.withGroupLabel(group.optString("name"));

      Object stored = group.optJSONObject("attributes") == null ? null : group.getJSONObject("attributes").opt(format.attribute());
      if(stored != null && !JSONObject.NULL.equals(stored) && !"".equals(stored))
      {
         try
         {
            /////////////////////////////////////////////////////////////////
            // canonical form of what is stored (unknown resources survive) //
            /////////////////////////////////////////////////////////////////
            data.withDocument(PolicyGenerator.toPretty(PolicyGenerator.canonical(stored, format)));
         }
         catch(PolicyParseException e)
         {
            data.withDocumentProblem(e.getMessage());
         }
      }

      QRecord row = PolicyStore.find(config, groupPk);
      if(row != null)
      {
         data.withChangedInAuthentik(!Objects.equals(row.getValueString("authentikFingerprint"), PolicyStore.fingerprint(stored, format)));
      }
      return (data);
   }



   /*******************************************************************************
    ** Renderer. QQQ checks the widget's permission rules
    ** (authentik.policies.manage) before calling it.
    *******************************************************************************/
   public static class Renderer extends AbstractWidgetRenderer
   {
      /*******************************************************************************
       ** Render.
       *******************************************************************************/
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         String backendName = String.valueOf(((QWidgetMetaData) input.getWidgetMetaData()).getDefaultValues().get(BACKEND_NAME_KEY));
         AuthentikQBitConfig config = AuthentikRuntime.forBackend(backendName).getConfig();
         Map<String, String> params = input.getQueryParams();
         return (new RenderWidgetOutput(load(config, params == null ? null : params.get(GROUP_PK_PARAM))));
      }
   }



   /*******************************************************************************
    ** The widget's data (see the Next UI's PolicyEditorPayload).
    *******************************************************************************/
   public static class Data extends QWidgetData
   {
      private String                    spec;
      private String                    version;
      private String                    groupLabel;
      private List<Object>              catalog;
      private String                    document;
      private String                    documentProblem;
      private Boolean                   changedInAuthentik = false;
      private String                    outputFieldName;



      /*******************************************************************************
       **
       *******************************************************************************/
      @Override
      public String getType()
      {
         return (TYPE);
      }



      /*******************************************************************************
       ** Getter for spec
       *******************************************************************************/
      public String getSpec()
      {
         return (spec);
      }



      /*******************************************************************************
       ** Fluent setter for spec
       *******************************************************************************/
      public Data withSpec(String spec)
      {
         this.spec = spec;
         return (this);
      }



      /*******************************************************************************
       ** Getter for version
       *******************************************************************************/
      public String getVersion()
      {
         return (version);
      }



      /*******************************************************************************
       ** Fluent setter for version
       *******************************************************************************/
      public Data withVersion(String version)
      {
         this.version = version;
         return (this);
      }



      /*******************************************************************************
       ** Getter for groupLabel
       *******************************************************************************/
      public String getGroupLabel()
      {
         return (groupLabel);
      }



      /*******************************************************************************
       ** Fluent setter for groupLabel
       *******************************************************************************/
      public Data withGroupLabel(String groupLabel)
      {
         this.groupLabel = groupLabel;
         return (this);
      }



      /*******************************************************************************
       ** Getter for catalog (groups of resources, as plain JSON values)
       *******************************************************************************/
      public List<Object> getCatalog()
      {
         return (catalog);
      }



      /*******************************************************************************
       ** Fluent setter for catalog
       *******************************************************************************/
      public Data withCatalog(List<Object> catalog)
      {
         this.catalog = catalog;
         return (this);
      }



      /*******************************************************************************
       ** Getter for document (the group's current document, pretty; null for none)
       *******************************************************************************/
      public String getDocument()
      {
         return (document);
      }



      /*******************************************************************************
       ** Fluent setter for document
       *******************************************************************************/
      public Data withDocument(String document)
      {
         this.document = document;
         return (this);
      }



      /*******************************************************************************
       ** Getter for documentProblem (why the stored document is invalid)
       *******************************************************************************/
      public String getDocumentProblem()
      {
         return (documentProblem);
      }



      /*******************************************************************************
       ** Fluent setter for documentProblem
       *******************************************************************************/
      public Data withDocumentProblem(String documentProblem)
      {
         this.documentProblem = documentProblem;
         return (this);
      }



      /*******************************************************************************
       ** Getter for changedInAuthentik (differs from the last save in QQQ)
       *******************************************************************************/
      public Boolean getChangedInAuthentik()
      {
         return (changedInAuthentik);
      }



      /*******************************************************************************
       ** Fluent setter for changedInAuthentik
       *******************************************************************************/
      public Data withChangedInAuthentik(Boolean changedInAuthentik)
      {
         this.changedInAuthentik = changedInAuthentik;
         return (this);
      }



      /*******************************************************************************
       ** Getter for outputFieldName (the process value the editor writes)
       *******************************************************************************/
      public String getOutputFieldName()
      {
         return (outputFieldName);
      }



      /*******************************************************************************
       ** Fluent setter for outputFieldName
       *******************************************************************************/
      public Data withOutputFieldName(String outputFieldName)
      {
         this.outputFieldName = outputFieldName;
         return (this);
      }
   }
}
