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


import java.util.EnumSet;
import com.kingsrook.qbits.authentik.admin.AdminTestSupport;
import com.kingsrook.qqq.backend.core.model.metadata.help.bundles.HelpBundles;
import com.kingsrook.qqq.backend.core.testing.HelpBundleAssertions;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Coverage of the shipped help with all supported optional metadata present.
 *******************************************************************************/
class AuthentikHelpBundleTest
{
   /*******************************************************************************
    ** New objects and non-trivial fields must ship with valid help.
    *******************************************************************************/
   @Test
   void bundleCoversOwnedMetadata() throws Exception
   {
      var support = AdminTestSupport.create(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.TOKENS,
         AuthentikFeature.POLICIES, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.DELETE,
         AuthentikFeature.MEMBERSHIP, AuthentikFeature.CREDENTIALS, AuthentikFeature.SESSIONS));
      HelpBundleAssertions.forInstance(support.qInstance)
         .bundles("help/qbit-authentik.yaml")
         .owning(target -> target.name().startsWith("authentik"))
         .assertComplete();
      var bundle = HelpBundles.of(support.qInstance).getBundles().get(0);
      assertThat(bundle.getVersion()).isEqualTo(AuthentikQBitProducer.getVersion());
      var keys = bundle.getEntries().stream().map(entry -> entry.getKey()).toList();
      assertThat(keys).doesNotHaveDuplicates();
      // Core's gate currently requires apps, tables, actions and table fields.
      // Also pin coverage for this qbit's widgets and possible-value sources.
      support.qInstance.getWidgets().keySet().stream().filter(name -> name.startsWith("authentik"))
         .forEach(name -> assertThat(keys).contains("widget:" + name + ";slot:label"));
      support.qInstance.getPossibleValueSources().keySet().stream().filter(name -> name.startsWith("authentik"))
         .forEach(name -> assertThat(keys).contains("possibleValueSource:" + name + ";slot:help"));
   }


   /*******************************************************************************
    ** Metadata-only registration is safe without help storage and follows prefixes.
    *******************************************************************************/
   @Test
   void registersWithoutHelpStorage() throws Exception
   {
      var instance = AuthentikTestSupport.produce(AuthentikTestSupport.unitConfig().withTableNamePrefix("idp"));
      assertThat(instance.getTable("helpContent")).isNull();
      HelpBundles.syncOnStartup(instance);
      var bundles = HelpBundles.of(instance).getBundles();
      assertThat(bundles).hasSize(1);
      assertThat(bundles.get(0).getEntries()).anySatisfy(entry ->
      {
         assertThat(entry.getKey()).isEqualTo("table:idp_user;slot:help");
         assertThat(entry.getContent()).contains("{{label:idp_user}}").doesNotContain("{{label:authentik");
      });
   }

}
