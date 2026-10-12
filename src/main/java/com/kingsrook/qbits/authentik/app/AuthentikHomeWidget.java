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

package com.kingsrook.qbits.authentik.app;


import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.metadata.AuthentikHomeWidgetProducer;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.RawHTML;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;


/*******************************************************************************
 ** Holder of the Identity home widget renderer.
 *******************************************************************************/
public final class AuthentikHomeWidget
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikHomeWidget()
   {
   }



   /*******************************************************************************
    ** Renders the home. QQQ checks the widget's permission rules (authentik.users.read);
    ** each card checks the finer permissions it needs itself.
    *******************************************************************************/
   public static class Renderer extends AbstractWidgetRenderer
   {
      /*******************************************************************************
       ** Render.
       *******************************************************************************/
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         String backendName = String.valueOf(((QWidgetMetaData) input.getWidgetMetaData()).getDefaultValues().get(AuthentikHomeWidgetProducer.BACKEND_NAME_KEY));
         AuthentikQBitConfig config = AuthentikRuntime.forBackend(backendName).getConfig();
         try
         {
            return (new RenderWidgetOutput(new RawHTML(null, AuthentikHomeView.render(AuthentikHomeData.load(config)))));
         }
         catch(QException e)
         {
            throw (e);
         }
         catch(Exception e)
         {
            throw (new QException("The Identity home could not be built: " + e.getMessage(), e));
         }
      }
   }

}
