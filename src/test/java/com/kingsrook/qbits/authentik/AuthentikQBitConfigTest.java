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


import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Tests for AuthentikQBitConfig.
 *******************************************************************************/
class AuthentikQBitConfigTest
{

   /*******************************************************************************
    **
    *******************************************************************************/
   private static List<String> errors(AuthentikQBitConfig config)
   {
      List<String> errors = new ArrayList<>();
      config.validate(new QInstance(), errors);
      return (errors);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void validConfigHasNoErrors()
   {
      assertThat(errors(AuthentikTestSupport.unitConfig())).isEmpty();
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void requiredSettings()
   {
      List<String> errors = errors(new AuthentikQBitConfig());
      assertThat(errors).anyMatch(e -> e.contains("baseUrl is required"));
      assertThat(errors).anyMatch(e -> e.contains("apiToken is required"));
      assertThat(errors).anyMatch(e -> e.contains("appKey is required"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void baseUrlMustBeHostRoot()
   {
      assertThat(errors(AuthentikTestSupport.unitConfig().withBaseUrl("ftp://x"))).anyMatch(e -> e.contains("absolute http(s)"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withBaseUrl("https://auth.example.test/api/v3"))).anyMatch(e -> e.contains("host root"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withBaseUrl("not a url at all"))).isNotEmpty();
      assertThat(AuthentikTestSupport.unitConfig().withBaseUrl("https://auth.example.test//").getApiRoot()).isEqualTo("https://auth.example.test/api/v3");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void unavailableFeaturesAndDependencies()
   {
      assertThat(errors(AuthentikTestSupport.unitConfig().withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.MEMBERSHIP))))
         .anyMatch(e -> e.contains("MEMBERSHIP is not available"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withFeatures(EnumSet.of(AuthentikFeature.MIRROR)))).anyMatch(e -> e.contains("READ is required"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.MIRROR)))).anyMatch(e -> e.contains("mirrorBackendName"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.MIRROR)).withMirrorBackendName("nope")))
         .anyMatch(e -> e.contains("backend not found"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS)))).anyMatch(e -> e.contains("recoveryEmailStage"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.WEBHOOK)).withWebhookSecret(null))).anyMatch(e -> e.contains("webhookSecret"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void numericAndNameSettings()
   {
      assertThat(errors(AuthentikTestSupport.unitConfig().withThrottleRequestsPerSecond(0))).anyMatch(e -> e.contains("at least 1"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withListCacheTtlSeconds(-1))).anyMatch(e -> e.contains("non-negative"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withTableNamePrefix("9bad"))).anyMatch(e -> e.contains("tableNamePrefix"));
      assertThat(errors(AuthentikTestSupport.unitConfig().withAppKey("Bad Key"))).anyMatch(e -> e.contains("appKey"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void secretsResolveAndNeverPrint() throws Exception
   {
      AuthentikQBitConfig config = AuthentikTestSupport.unitConfig().withApiToken("${env.QBIT_AUTHENTIK_TEST_UNSET_VARIABLE}");
      assertThat(config.getResolvedApiToken()).isNull();
      assertThat(errors(config)).anyMatch(e -> e.contains("apiToken"));

      AuthentikQBitConfig literal = AuthentikTestSupport.unitConfig();
      assertThat(literal.getResolvedApiToken()).isEqualTo(AuthentikTestSupport.TEST_TOKEN);
      assertThat(literal.toString()).doesNotContain(AuthentikTestSupport.TEST_TOKEN).contains("******");

      String json = new ObjectMapper().writeValueAsString(literal.withWebhookSecret("hook-secret-value"));
      assertThat(json).doesNotContain(AuthentikTestSupport.TEST_TOKEN).doesNotContain("hook-secret-value");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void derivedNames()
   {
      AuthentikQBitConfig config = AuthentikTestSupport.unitConfig();
      assertThat(config.applyPrefix("user")).isEqualTo("authentikUser");
      assertThat(config.getApiBackendName()).isEqualTo("authentikApi");
      assertThat(config.getEffectiveServiceAccountUsername()).isEqualTo("qqq-kof22-admin-idadmin");
      assertThat(config.withServiceAccountUsername("custom-sa").getEffectiveServiceAccountUsername()).isEqualTo("custom-sa");
      assertThat(new AuthentikQBitConfig().withTableNamePrefix("").applyPrefix("user")).isEqualTo("user");
      assertThat(config.withBootstrapOperators(" A@x.test, ,b@x.test ").getResolvedBootstrapOperators()).containsExactly("a@x.test", "b@x.test");
   }

}
