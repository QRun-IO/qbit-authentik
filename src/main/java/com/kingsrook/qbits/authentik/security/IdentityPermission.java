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

package com.kingsrook.qbits.authentik.security;


import java.util.Optional;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;


/*******************************************************************************
 ** The qbit's own QQQ permissions (DESIGN.md section 5.2).
 **
 ** Operators write the short name (e.g. "authentik.users.read") into a group's
 ** qqq.io/permissions attribute; "authentik.*" means all of them. In a QQQ
 ** session each one is held as its HAS_ACCESS form, the short name plus
 ** ".hasAccess", which is what QQQ's PermissionsHelper checks for metadata
 ** guarded by {@link #rules()}.
 *******************************************************************************/
public enum IdentityPermission
{
   USERS_READ("authentik.users.read"),
   USERS_MANAGE("authentik.users.manage"),
   GROUPS_MANAGE("authentik.groups.manage"),
   MEMBERSHIPS_MANAGE("authentik.memberships.manage"),
   PERMISSIONS_MANAGE("authentik.permissions.manage"),
   ROLES_MANAGE("authentik.roles.manage"),
   CREDENTIALS_RESET("authentik.credentials.reset"),
   SESSIONS_REVOKE("authentik.sessions.revoke"),
   AUDIT_READ("authentik.audit.read"),
   APPROVE("authentik.approve"),
   ADMIN("authentik.admin");

   /** The wildcard operators write for "all identity permissions". */
   public static final String WILDCARD = "authentik.*";

   /** Suffix QQQ uses for HAS_ACCESS permissions. */
   public static final String HAS_ACCESS_SUFFIX = ".hasAccess";

   /** Prefix of the permission names before the owner naming rule (2026-10-12); see UPGRADE.md. */
   @Deprecated
   public static final String LEGACY_PREFIX = "identity.";

   /** Wildcard before the owner naming rule (2026-10-12); no longer granted. */
   @Deprecated
   public static final String LEGACY_WILDCARD = "identity.*";

   private final String shortName;



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   IdentityPermission(String shortName)
   {
      this.shortName = shortName;
   }



   /*******************************************************************************
    ** The name written in qqq.io/permissions, e.g. "authentik.users.read".
    *******************************************************************************/
   public String getShortName()
   {
      return (shortName);
   }



   /*******************************************************************************
    ** The name this permission had before the owner naming rule (2026-10-12),
    ** e.g. "identity.users.read". Only for finding stored grants when upgrading;
    ** legacy names are never granted.
    *******************************************************************************/
   @Deprecated
   public String getLegacyShortName()
   {
      return (LEGACY_PREFIX + shortName.substring(shortName.indexOf('.') + 1));
   }



   /*******************************************************************************
    ** The QQQ session permission, e.g. "authentik.users.read.hasAccess".
    *******************************************************************************/
   public String getSessionPermission()
   {
      return (shortName + HAS_ACCESS_SUFFIX);
   }



   /*******************************************************************************
    ** Permission rules guarding metadata by this permission.
    *******************************************************************************/
   public QPermissionRules rules()
   {
      return (new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION).withPermissionBaseName(shortName));
   }



   /*******************************************************************************
    ** Look up by short name or by session permission name.
    *******************************************************************************/
   public static Optional<IdentityPermission> fromName(String name)
   {
      if(name == null)
      {
         return (Optional.empty());
      }

      for(IdentityPermission permission : values())
      {
         if(permission.shortName.equals(name) || permission.getSessionPermission().equals(name))
         {
            return (Optional.of(permission));
         }
      }
      return (Optional.empty());
   }

}
