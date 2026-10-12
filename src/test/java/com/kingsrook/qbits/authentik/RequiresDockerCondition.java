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


import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.testcontainers.DockerClientFactory;


/*******************************************************************************
 ** JUnit condition for integration tests that need Docker.
 **
 ** Without Docker, the tests are skipped on a developer machine, but fail when
 ** CI=true, so a CI build can never pass with its integration tests silently
 ** skipped. Register it ahead of @Testcontainers, so no container is started
 ** when the tests are disabled.
 *******************************************************************************/
public class RequiresDockerCondition implements ExecutionCondition
{

   /*******************************************************************************
    ** Evaluate against the local Docker environment and the CI env var.
    *******************************************************************************/
   @Override
   public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context)
   {
      return (evaluate(DockerClientFactory.instance().isDockerAvailable(), System.getenv("CI")));
   }



   /*******************************************************************************
    ** Decide whether Docker-backed tests run, skip, or fail.
    **
    ** @param dockerAvailable whether a usable Docker environment was found
    ** @param ciValue         value of the CI environment variable (may be null)
    ** @return enabled when Docker is available; disabled when it is not and CI
    **         is not "true"
    ** @throws IllegalStateException when Docker is unavailable and CI is "true"
    *******************************************************************************/
   static ConditionEvaluationResult evaluate(Boolean dockerAvailable, String ciValue)
   {
      if(Boolean.TRUE.equals(dockerAvailable))
      {
         return (ConditionEvaluationResult.enabled("Docker is available"));
      }

      if("true".equalsIgnoreCase(ciValue))
      {
         throw (new IllegalStateException("Docker is required for integration tests when CI=true, but no usable Docker environment was found"));
      }

      return (ConditionEvaluationResult.disabled("Docker is not available; skipping (with CI=true these tests fail instead)"));
   }

}
