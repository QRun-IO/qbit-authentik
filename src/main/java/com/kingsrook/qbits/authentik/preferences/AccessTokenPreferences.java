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

package com.kingsrook.qbits.authentik.preferences;


import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceActionMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceActionScope;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceListMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferenceSectionMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.preferences.UserPreferencesMetaData;


/*******************************************************************************
 ** Self-service token metadata for core's generic Preferences clients.
 *******************************************************************************/
public final class AccessTokenPreferences
{
   public static final String SECTION = "access-tokens";
   public static final String LIST = "tokens";



   /*******************************************************************************
    ** Register without an app or permission gate: every signed-in user may enter.
    *******************************************************************************/
   public static void register(QInstance instance, AuthentikQBitConfig config)
   {
      UserPreferenceListMetaData tokens = new UserPreferenceListMetaData().withName(LIST).withLabel("Tokens").withRowLabel("Token")
         .withField(readOnly("description", "Description", QFieldType.STRING))
         .withField(readOnly("identifier", "Identifier", QFieldType.STRING))
         .withField(readOnly("intent", "Intent", QFieldType.STRING))
         .withField(readOnly("expires", "Expires", QFieldType.DATE_TIME))
         .withField(readOnly("scope", "Scope", QFieldType.STRING));
      UserPreferenceActionMetaData create = new UserPreferenceActionMetaData().withName("create").withLabel("Create token")
         .withScope(UserPreferenceActionScope.SECTION).withOrder(10)
         .withInputField(new QFieldMetaData("description", QFieldType.STRING).withLabel("Description").withIsRequired(true))
         .withInputField(expiry().withDefaultValue(30));
      if(Boolean.TRUE.equals(config.getTokenScopesEnabled()))
      {
         create.withInputField(new QFieldMetaData("readOnly", QFieldType.BOOLEAN).withLabel("Read only"))
            .withInputField(new QFieldMetaData("apps", QFieldType.TEXT).withLabel("Apps"))
            .withInputField(new QFieldMetaData("tables", QFieldType.TEXT).withLabel("Tables"));
      }
      UserPreferencesMetaData.ofOrWithNew(instance).withSection(new UserPreferenceSectionMetaData()
         .withName(SECTION).withLabel("Access tokens").withIcon(new QIcon("key"))
         .withDescription("Personal access tokens for scripts and integrations. Keys are shown once.")
         .withOrder(30).withShowInUserMenu(true).withProvider(new QCodeReference(AccessTokenPreferencesProvider.class))
         .withList(tokens).withAction(create)
         .withAction(rowAction("rotate", "Rotate token", 20).withIsDestructive(true)
            .withConfirmationText("Rotate this token? The old key stops working now."))
         .withAction(rowAction("extend", "Extend expiry", 30).withInputField(expiry()))
         .withAction(rowAction("revoke", "Revoke token", 40).withIsDestructive(true)
            .withConfirmationText("Revoke this token? Anything using it stops working now.")));
   }



   /*******************************************************************************
    ** Token attributes can only be changed by the audited actions.
    *******************************************************************************/
   private static QFieldMetaData readOnly(String name, String label, QFieldType type)
   {
      return (new QFieldMetaData(name, type).withLabel(label).withIsEditable(false));
   }



   /*******************************************************************************
    ** Both creation and extension require an explicit bounded lifetime.
    *******************************************************************************/
   private static QFieldMetaData expiry()
   {
      return (new QFieldMetaData("expiresInDays", QFieldType.INTEGER).withLabel("Expires in days").withIsRequired(true));
   }



   /*******************************************************************************
    ** All row actions refer to the provider's own-token list.
    *******************************************************************************/
   private static UserPreferenceActionMetaData rowAction(String name, String label, int order)
   {
      return (new UserPreferenceActionMetaData().withName(name).withLabel(label).withOrder(order)
         .withScope(UserPreferenceActionScope.ROW).withListName(LIST));
   }
}
