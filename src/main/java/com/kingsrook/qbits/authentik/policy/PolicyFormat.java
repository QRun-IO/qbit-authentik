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

package com.kingsrook.qbits.authentik.policy;


import java.util.regex.Pattern;


/*******************************************************************************
 ** The names a host uses for its policy documents (docs/POLICY-FORMAT.md): the
 ** PolicySpec it accepts, the one supported PolicyVersion, the Authentik group
 ** attribute that holds a group's document, and the token claim that holds the
 ** merged document.
 **
 ** @param spec      PolicySpec, e.g. "qqq-iam"
 ** @param version   PolicyVersion (semver), e.g. "1.0.0"
 ** @param attribute group attribute key, e.g. "qqq.io/policy"
 ** @param claim     token claim name, e.g. "qqq_policy"
 *******************************************************************************/
public record PolicyFormat(String spec, String version, String attribute, String claim)
{
   /** Default PolicySpec. */
   public static final String DEFAULT_SPEC = "qqq-iam";

   /** Default (and only) PolicyVersion of this qbit's format. */
   public static final String DEFAULT_VERSION = "1.0.0";

   /** Default group attribute. */
   public static final String DEFAULT_ATTRIBUTE = "qqq.io/policy";

   /** Default token claim. */
   public static final String DEFAULT_CLAIM = "qqq_policy";

   /** The generic defaults. */
   public static final PolicyFormat DEFAULT = new PolicyFormat(DEFAULT_SPEC, DEFAULT_VERSION, DEFAULT_ATTRIBUTE, DEFAULT_CLAIM);

   /** A valid spec name: letters, digits, dot, dash and underscore. */
   public static final Pattern SPEC_PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");

   /** Semver MAJOR.MINOR.PATCH. */
   public static final Pattern VERSION_PATTERN = Pattern.compile("(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)");

   /** A valid claim name. */
   public static final Pattern CLAIM_PATTERN = Pattern.compile("[A-Za-z_][A-Za-z0-9_.-]{0,63}");



   /*******************************************************************************
    ** Whether every name is well formed (used by the config's validate()).
    *******************************************************************************/
   public String problem()
   {
      if(spec == null || !SPEC_PATTERN.matcher(spec).matches())
      {
         return ("policySpec must be letters, digits, '.', '-' or '_': " + spec);
      }
      if(version == null || !VERSION_PATTERN.matcher(version).matches())
      {
         return ("policyVersion must be semver MAJOR.MINOR.PATCH: " + version);
      }
      if(attribute == null || attribute.isBlank())
      {
         return ("policyAttribute is required");
      }
      if(claim == null || !CLAIM_PATTERN.matcher(claim).matches())
      {
         return ("policyClaim must be a plain claim name: " + claim);
      }
      return (null);
   }
}
