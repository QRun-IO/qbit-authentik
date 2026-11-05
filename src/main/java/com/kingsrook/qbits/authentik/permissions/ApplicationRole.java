/*
 * Copyright 2026 Kingsrook, LLC
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */
package com.kingsrook.qbits.authentik.permissions;

import org.json.JSONObject;

/*******************************************************************************
 ** Application roles use ordinary Authentik group inheritance and memberships.
 ** The marker is descriptive; it never grants Authentik administrative RBAC.
 *******************************************************************************/
public final class ApplicationRole
{
   public static final String ATTRIBUTE = "qqq.io/application-role";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private ApplicationRole()
   {
   }

   /*******************************************************************************
    ** Recognize only an explicit boolean marker on a group.
    *******************************************************************************/
   public static boolean isRole(JSONObject group)
   {
      JSONObject attributes = group == null ? null : group.optJSONObject("attributes");
      return (attributes != null && Boolean.TRUE.equals(attributes.opt(ATTRIBUTE)));
   }
}
