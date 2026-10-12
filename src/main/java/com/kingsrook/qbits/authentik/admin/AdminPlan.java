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


import java.util.ArrayList;
import java.util.List;


/*******************************************************************************
 ** What a request would do, computed by the guard rules before anything is
 ** sent: whether it may run, why not, the target, a before and after, and
 ** whether it needs a second person. The Review screen shows it; the Result
 ** step executes it (after computing it again against live data).
 *******************************************************************************/
public class AdminPlan
{
   /** The outcome of planning. */
   public enum State
   {
      /** Will run. */
      READY,
      /** Already in the wanted state; nothing to do. */
      NO_CHANGE,
      /** Refused by a rule (the message says which). */
      REFUSED,
      /** Allowed, but needs a second person to approve first. */
      NEEDS_APPROVAL
   }

   private final AdminRequest request;
   private State              state       = State.READY;
   private String             message;
   private String             targetType;
   private String             targetLabel;
   private String             before;
   private String             after;
   private final List<String> notes       = new ArrayList<>();



   /*******************************************************************************
    ** Constructor.
    *******************************************************************************/
   public AdminPlan(AdminRequest request)
   {
      this.request = request;
      this.targetType = request.action().getTargetType();
   }



   /*******************************************************************************
    ** Refuse, with the reason shown to the operator.
    *******************************************************************************/
   public AdminPlan refuse(String reason)
   {
      this.state = State.REFUSED;
      this.message = reason;
      return (this);
   }



   /*******************************************************************************
    ** Mark as already done.
    *******************************************************************************/
   public AdminPlan noChange(String why)
   {
      this.state = State.NO_CHANGE;
      this.message = why;
      return (this);
   }



   /*******************************************************************************
    ** Whether the plan will make a change when executed.
    *******************************************************************************/
   public boolean isRunnable()
   {
      return (state == State.READY);
   }



   /*******************************************************************************
    ** Getter for request
    *******************************************************************************/
   public AdminRequest getRequest()
   {
      return (request);
   }



   /*******************************************************************************
    ** Getter for state
    *******************************************************************************/
   public State getState()
   {
      return (state);
   }



   /*******************************************************************************
    ** Setter for state
    *******************************************************************************/
   public AdminPlan withState(State state)
   {
      this.state = state;
      return (this);
   }



   /*******************************************************************************
    ** Getter for message
    *******************************************************************************/
   public String getMessage()
   {
      return (message);
   }



   /*******************************************************************************
    ** Fluent setter for message
    *******************************************************************************/
   public AdminPlan withMessage(String message)
   {
      this.message = message;
      return (this);
   }



   /*******************************************************************************
    ** Getter for targetType
    *******************************************************************************/
   public String getTargetType()
   {
      return (targetType);
   }



   /*******************************************************************************
    ** Getter for targetLabel
    *******************************************************************************/
   public String getTargetLabel()
   {
      return (targetLabel);
   }



   /*******************************************************************************
    ** Fluent setter for targetLabel
    *******************************************************************************/
   public AdminPlan withTargetLabel(String targetLabel)
   {
      this.targetLabel = targetLabel;
      return (this);
   }



   /*******************************************************************************
    ** Getter for before
    *******************************************************************************/
   public String getBefore()
   {
      return (before);
   }



   /*******************************************************************************
    ** Getter for after
    *******************************************************************************/
   public String getAfter()
   {
      return (after);
   }



   /*******************************************************************************
    ** Set the before and after text.
    *******************************************************************************/
   public AdminPlan withChange(String before, String after)
   {
      this.before = before;
      this.after = after;
      return (this);
   }



   /*******************************************************************************
    ** Notes for the operator (warnings and consequences).
    *******************************************************************************/
   public List<String> getNotes()
   {
      return (notes);
   }



   /*******************************************************************************
    ** A one-line description for review lines and audit.
    *******************************************************************************/
   public String describe()
   {
      return (request.action().getLabel() + ": " + (targetLabel == null ? request.targetKey() : targetLabel)
         + (before != null || after != null ? " (" + (before == null ? "" : before) + " -> " + (after == null ? "" : after) + ")" : ""));
   }

}
