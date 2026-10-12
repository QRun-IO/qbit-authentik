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


import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Unit test for IdentityPermission: the authentik.* names (owner naming rule,
 ** 2026-10-12) and the legacy identity.* names.
 *******************************************************************************/
class IdentityPermissionTest
{

   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void namesUseTheQbitPrefix()
   {
      assertThat(IdentityPermission.WILDCARD).isEqualTo("authentik.*");
      for(IdentityPermission permission : IdentityPermission.values())
      {
         assertThat(permission.getShortName()).startsWith("authentik.");
         assertThat(permission.getSessionPermission()).isEqualTo(permission.getShortName() + ".hasAccess");
      }
      assertThat(IdentityPermission.USERS_READ.getShortName()).isEqualTo("authentik.users.read");
      assertThat(IdentityPermission.ADMIN.getShortName()).isEqualTo("authentik.admin");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   @SuppressWarnings("deprecation")
   void legacyNamesAreKnownButNeverGranted()
   {
      assertThat(IdentityPermission.LEGACY_WILDCARD).isEqualTo("identity.*");
      assertThat(IdentityPermission.USERS_READ.getLegacyShortName()).isEqualTo("identity.users.read");
      assertThat(IdentityPermission.MEMBERSHIPS_MANAGE.getLegacyShortName()).isEqualTo("identity.memberships.manage");
      assertThat(IdentityPermission.ADMIN.getLegacyShortName()).isEqualTo("identity.admin");

      assertThat(IdentityPermission.fromName("authentik.users.read")).contains(IdentityPermission.USERS_READ);
      assertThat(IdentityPermission.fromName("authentik.users.read.hasAccess")).contains(IdentityPermission.USERS_READ);
      assertThat(IdentityPermission.fromName("identity.users.read")).isEmpty();
      assertThat(IdentityPermission.fromName("identity.users.read.hasAccess")).isEmpty();
   }

}
