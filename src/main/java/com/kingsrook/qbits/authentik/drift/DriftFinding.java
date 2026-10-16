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

package com.kingsrook.qbits.authentik.drift;


/*******************************************************************************
 ** One line of the drift report.
 **
 ** @param severity ERROR (identity management is broken or unsafe), WARNING
 **                 (needs attention), INFO (worth knowing), OK (a check passed)
 ** @param check    the check's short name, e.g. "blueprints"
 ** @param subject  what the finding is about, e.g. a group name
 ** @param message  plain-language explanation and what to do
 ** @param reason   a short, safe summary for health outcomes (no attribute
 **                 values a person typed beyond validated permission names);
 **                 null when the finding has none
 *******************************************************************************/
public record DriftFinding(Severity severity, String check, String subject, String message, String reason)
{

   /*******************************************************************************
    ** A finding without a health reason.
    *******************************************************************************/
   public DriftFinding(Severity severity, String check, String subject, String message)
   {
      this(severity, check, subject, message, null);
   }



   /*******************************************************************************
    ** This finding with a short, safe reason for health outcomes.
    *******************************************************************************/
   public DriftFinding withReason(String reason)
   {
      return (new DriftFinding(severity, check, subject, message, reason));
   }



   /*******************************************************************************
    ** Severity, most severe first.
    *******************************************************************************/
   public enum Severity
   {
      ERROR, WARNING, INFO, OK
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   public static DriftFinding error(String check, String subject, String message)
   {
      return (new DriftFinding(Severity.ERROR, check, subject, message));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   public static DriftFinding warning(String check, String subject, String message)
   {
      return (new DriftFinding(Severity.WARNING, check, subject, message));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   public static DriftFinding info(String check, String subject, String message)
   {
      return (new DriftFinding(Severity.INFO, check, subject, message));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   public static DriftFinding ok(String check, String subject, String message)
   {
      return (new DriftFinding(Severity.OK, check, subject, message));
   }

}
