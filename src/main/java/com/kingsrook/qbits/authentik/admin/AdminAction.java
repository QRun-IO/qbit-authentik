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

package com.kingsrook.qbits.authentik.admin;


import com.kingsrook.qbits.authentik.AuthentikFeature;
import com.kingsrook.qbits.authentik.security.IdentityPermission;


/*******************************************************************************
 ** Every change the qbit can make to Authentik (DESIGN.md section 6.3), with
 ** the QQQ permission and feature it needs and how strongly it is confirmed.
 *******************************************************************************/
public enum AdminAction
{
   // Null permission means self-service: AuthentikTokens verifies the live owner.
   // Processes add no permission beyond their table; cross-owner actions require TOKENS_MANAGE.
   CREATE_TOKEN("Create token", "token", null, AuthentikFeature.TOKENS, Confirmation.CONFIRM),
   ROTATE_TOKEN("Rotate token", "token", null, AuthentikFeature.TOKENS, Confirmation.CONFIRM),
   REVOKE_TOKEN("Revoke token", "token", null, AuthentikFeature.TOKENS, Confirmation.CONFIRM),
   EXTEND_TOKEN("Extend expiry", "token", null, AuthentikFeature.TOKENS, Confirmation.CONFIRM),
   CREATE_SERVICE_ACCOUNT("Create service account", "user", IdentityPermission.TOKENS_MANAGE, AuthentikFeature.TOKENS, Confirmation.CONFIRM),
   CREATE_USER("Create user", "user", IdentityPermission.USERS_MANAGE, AuthentikFeature.USERS, Confirmation.CONFIRM),
   INVITE_USER("Invite user", "invitation", IdentityPermission.USERS_MANAGE, AuthentikFeature.USERS, Confirmation.CONFIRM),
   EDIT_USER("Edit user", "user", IdentityPermission.USERS_MANAGE, AuthentikFeature.USERS, Confirmation.CONFIRM),
   DEACTIVATE_USER("Deactivate user", "user", IdentityPermission.USERS_MANAGE, AuthentikFeature.USERS, Confirmation.TYPED),
   REACTIVATE_USER("Reactivate user", "user", IdentityPermission.USERS_MANAGE, AuthentikFeature.USERS, Confirmation.CONFIRM),
   CANCEL_INVITATION("Cancel invitation", "invitation", IdentityPermission.USERS_MANAGE, AuthentikFeature.USERS, Confirmation.CONFIRM),
   ADD_MEMBER("Add to group", "membership", IdentityPermission.MEMBERSHIPS_MANAGE, AuthentikFeature.MEMBERSHIP, Confirmation.CONFIRM),
   REMOVE_MEMBER("Remove from group", "membership", IdentityPermission.MEMBERSHIPS_MANAGE, AuthentikFeature.MEMBERSHIP, Confirmation.CONFIRM),
   CREATE_GROUP("Create group", "group", IdentityPermission.GROUPS_MANAGE, AuthentikFeature.GROUPS, Confirmation.CONFIRM),
   EDIT_GROUP("Edit group", "group", IdentityPermission.GROUPS_MANAGE, AuthentikFeature.GROUPS, Confirmation.CONFIRM),
   EDIT_PERMISSIONS("Edit permissions and app access", "group", IdentityPermission.PERMISSIONS_MANAGE, AuthentikFeature.GROUPS, Confirmation.CONFIRM),
   SAVE_POLICY("Save policy", "group", IdentityPermission.POLICIES_MANAGE, AuthentikFeature.POLICIES, Confirmation.CONFIRM),
   DELETE_USER("Delete user", "user", IdentityPermission.USERS_MANAGE, AuthentikFeature.DELETE, Confirmation.TYPED),
   DELETE_GROUP("Delete group", "group", IdentityPermission.GROUPS_MANAGE, AuthentikFeature.DELETE, Confirmation.TYPED),
   SEND_RECOVERY_EMAIL("Send password reset email", "user", IdentityPermission.CREDENTIALS_RESET, AuthentikFeature.CREDENTIALS, Confirmation.CONFIRM),
   RESET_MFA("Reset MFA", "user", IdentityPermission.CREDENTIALS_RESET, AuthentikFeature.CREDENTIALS, Confirmation.TYPED),
   REVOKE_APP_PASSWORDS("Revoke app passwords", "user", IdentityPermission.CREDENTIALS_RESET, AuthentikFeature.CREDENTIALS, Confirmation.TYPED),
   REVOKE_SESSIONS("Revoke sessions", "user", IdentityPermission.SESSIONS_REVOKE, AuthentikFeature.SESSIONS, Confirmation.CONFIRM);

   /** How strongly an action is confirmed (DESIGN.md section 6.3). */
   public enum Confirmation
   {
      /** The Review screen is the confirmation. */
      CONFIRM,
      /** The operator also types the target's name (or the number of targets). */
      TYPED
   }

   private final String         label;
   private final String         targetType;
   private final IdentityPermission permission;
   private final AuthentikFeature feature;
   private final Confirmation   confirmation;



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   AdminAction(String label, String targetType, IdentityPermission permission, AuthentikFeature feature, Confirmation confirmation)
   {
      this.label = label;
      this.targetType = targetType;
      this.permission = permission;
      this.feature = feature;
      this.confirmation = confirmation;
   }



   /*******************************************************************************
    ** Getter for label
    *******************************************************************************/
   public String getLabel()
   {
      return (label);
   }



   /*******************************************************************************
    ** Getter for targetType
    *******************************************************************************/
   public String getTargetType()
   {
      return (targetType);
   }



   /*******************************************************************************
    ** Getter for permission
    *******************************************************************************/
   public IdentityPermission getPermission()
   {
      return (permission);
   }



   /*******************************************************************************
    ** Getter for feature
    *******************************************************************************/
   public AuthentikFeature getFeature()
   {
      return (feature);
   }



   /*******************************************************************************
    ** Getter for confirmation
    *******************************************************************************/
   public Confirmation getConfirmation()
   {
      return (confirmation);
   }

}
