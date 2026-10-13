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

package com.kingsrook.qbits.authentik.permissions;


import java.util.Collection;
import java.util.List;
import java.util.Set;


/*******************************************************************************
 ** SPI: the permissions a host grants TODAY, before Authentik group policies
 ** take over (DESIGN.md section 12.8). Typically a hard-coded grant such as
 ** "members of the admins group get adminPermissions()". The qbit uses it to
 **   - generate a group's policy from current access,
 **   - compare current access with what the mapper would grant, and
 **   - fall back to it while the cut-over guard keeps the mapper inactive.
 *******************************************************************************/
public interface AuthentikHostPermissionSource
{

   /*******************************************************************************
    ** The QQQ session permissions a user gets today.
    **
    ** @param email      the user's email (may be null)
    ** @param groupNames the user's direct Authentik group names
    *******************************************************************************/
   Set<String> userPermissions(String email, Collection<String> groupNames);



   /*******************************************************************************
    ** The permissions members of a group get today because of that group. The
    ** default asks for a user in only that group.
    *******************************************************************************/
   default Set<String> groupPermissions(String groupName)
   {
      return (userPermissions(null, List.of(groupName)));
   }
}
