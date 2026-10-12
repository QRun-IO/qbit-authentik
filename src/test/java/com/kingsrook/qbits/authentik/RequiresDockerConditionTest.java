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


import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Tests for RequiresDockerCondition.
 *******************************************************************************/
class RequiresDockerConditionTest
{

   /*******************************************************************************
    ** Docker available: integration tests run, whether or not CI is set.
    *******************************************************************************/
   @Test
   void testEvaluate_dockerAvailable_enabled()
   {
      ConditionEvaluationResult local = RequiresDockerCondition.evaluate(true, null);
      ConditionEvaluationResult ci    = RequiresDockerCondition.evaluate(true, "true");

      assertThat(local.isDisabled()).isFalse();
      assertThat(ci.isDisabled()).isFalse();
   }



   /*******************************************************************************
    ** No Docker outside CI: integration tests are skipped.
    *******************************************************************************/
   @Test
   void testEvaluate_noDockerOutsideCi_disabled()
   {
      assertThat(RequiresDockerCondition.evaluate(false, null).isDisabled()).isTrue();
      assertThat(RequiresDockerCondition.evaluate(false, "").isDisabled()).isTrue();
      assertThat(RequiresDockerCondition.evaluate(false, "false").isDisabled()).isTrue();
   }



   /*******************************************************************************
    ** No Docker with CI=true: evaluation throws, so the tests fail instead of
    ** silently skipping.
    *******************************************************************************/
   @Test
   void testEvaluate_noDockerInCi_throws()
   {
      assertThatThrownBy(() -> RequiresDockerCondition.evaluate(false, "true"))
         .isInstanceOf(IllegalStateException.class)
         .hasMessageContaining("CI=true");

      assertThatThrownBy(() -> RequiresDockerCondition.evaluate(false, "TRUE"))
         .isInstanceOf(IllegalStateException.class);
   }

}
