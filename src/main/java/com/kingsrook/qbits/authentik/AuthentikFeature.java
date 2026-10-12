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

package com.kingsrook.qbits.authentik;


/*******************************************************************************
 ** Features a host can turn on (DESIGN.md section 3.2). A feature that is off
 ** produces no metadata, and the guard refuses its operations.
 *******************************************************************************/
public enum AuthentikFeature
{
   /** Read-only tables: users, groups, memberships, roles, applications, bindings, blueprints, sessions, events. */
   READ,

   /** Create, invite, edit, deactivate users (phase 3). */
   USERS,

   /** Create and edit groups, permissions and app-access attributes (phase 2/3). */
   GROUPS,

   /** Add and remove members (phase 2). */
   MEMBERSHIP,

   /** Recovery email, MFA reset, app-password revoke (phase 3). */
   CREDENTIALS,

   /** Revoke sessions (phase 3). */
   SESSIONS,

   /** Authentik RBAC role management (phase 4). */
   RBAC,

   /** Access matrix widget. */
   ACCESS_MATRIX,

   /** Local mirror tables (phase 1+). */
   MIRROR,

   /** Inbound Authentik webhook (phase 2). */
   WEBHOOK,

   /** Nightly read-only snapshot export (phase 3). */
   SNAPSHOT_EXPORT
}
