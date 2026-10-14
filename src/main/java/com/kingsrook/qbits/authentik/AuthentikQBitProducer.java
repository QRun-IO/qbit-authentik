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


import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import com.kingsrook.qbits.authentik.admin.AuthentikLocalTables;
import com.kingsrook.qbits.authentik.app.AuthentikRelations;
import com.kingsrook.qbits.authentik.client.AuthentikTables;
import com.kingsrook.qbits.authentik.health.AuthentikHealthChecks;
import com.kingsrook.qbits.authentik.metadata.AuthentikAppMetaDataProducer;
import com.kingsrook.qbits.authentik.processes.AuthentikProcesses;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.metadata.MetaDataProducerMultiOutput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValueSource;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitMetaDataProducer;
import com.kingsrook.qqq.backend.core.utils.StringUtils;
import static com.kingsrook.qqq.backend.core.logging.LogUtils.logPair;


/*******************************************************************************
 ** Entry point of the Authentik QBit (QQQ 4.1 QBitMetaDataProducer).
 **
 ** produce() validates the config, registers the AuthentikRuntime for the API
 ** backend, then lets QQQ run the component producers in the metadata package
 ** (API backend, read-only tables, the Identity app).
 **
 ** Host usage:
 **   new AuthentikQBitProducer().withQBitConfig(config).produce(qInstance);
 *******************************************************************************/
public class AuthentikQBitProducer implements QBitMetaDataProducer<AuthentikQBitConfig>
{
   private static final QLogger LOG = QLogger.getLogger(AuthentikQBitProducer.class);

   public static final String GROUP_ID    = "com.kingsrook.qbits";
   public static final String ARTIFACT_ID = "authentik";

   private static final String VERSION = loadVersion();

   private AuthentikQBitConfig qBitConfig;
   private String              namespace;



   /*******************************************************************************
    ** Fluent setter for the config.
    *******************************************************************************/
   public AuthentikQBitProducer withQBitConfig(AuthentikQBitConfig config)
   {
      this.qBitConfig = config;
      return (this);
   }



   /*******************************************************************************
    ** Setter for the config.
    *******************************************************************************/
   public void setQBitConfig(AuthentikQBitConfig config)
   {
      this.qBitConfig = config;
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public AuthentikQBitConfig getQBitConfig()
   {
      return (this.qBitConfig);
   }



   /*******************************************************************************
    ** Namespace for this QBit instance; also the default tableNamePrefix.
    *******************************************************************************/
   public AuthentikQBitProducer withNamespace(String namespace)
   {
      this.namespace = namespace;
      return (this);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public String getNamespace()
   {
      return (this.namespace);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public QBitMetaData getQBitMetaData()
   {
      return (new QBitMetaData()
         .withGroupId(GROUP_ID)
         .withArtifactId(ARTIFACT_ID)
         .withVersion(VERSION)
         .withNamespace(getNamespace())
         .withConfig(getQBitConfig()));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Override
   public String getPackageNameForFindingMetaDataProducers()
   {
      return (AuthentikAppMetaDataProducer.class.getPackageName());
   }



   /*******************************************************************************
    ** A producer found by package scanning has no config; skip it.
    *******************************************************************************/
   @Override
   public boolean isEnabled()
   {
      return (qBitConfig != null);
   }



   /*******************************************************************************
    ** Validate, register the runtime, produce and add everything to the
    ** instance. Returns an empty output so a host that also calls
    ** addSelfToInstance on the result adds nothing twice.
    *******************************************************************************/
   @Override
   public MetaDataProducerMultiOutput produce(QInstance qInstance) throws QException
   {
      if(qBitConfig == null)
      {
         throw (new QException("AuthentikQBit configuration validation failed: no config was supplied (call withQBitConfig)"));
      }

      if(StringUtils.hasContent(namespace) && !StringUtils.hasContent(qBitConfig.getTableNamePrefix()))
      {
         qBitConfig.setTableNamePrefix(namespace);
      }

      List<String> errors = new ArrayList<>();
      qBitConfig.validate(qInstance, errors);
      if(!errors.isEmpty())
      {
         throw (new QException("AuthentikQBit configuration validation failed: " + String.join("; ", errors)));
      }

      AuthentikRuntime.register(new AuthentikRuntime(qBitConfig));

      MetaDataProducerMultiOutput output = QBitMetaDataProducer.super.produce(qInstance);
      output.addSelfToInstance(qInstance);

      AuthentikHealthChecks.register(qInstance, qBitConfig);
      addPossibleValueSources(qInstance);
      AuthentikRelations.apply(qInstance, qBitConfig);
      for(QProcessMetaData process : AuthentikProcesses.processes(qBitConfig))
      {
         qInstance.addProcess(process);
      }

      LOG.info("Authentik QBit produced", logPair("version", VERSION), logPair("appKey", qBitConfig.getAppKey()),
         logPair("features", qBitConfig.getEffectiveFeatures()), logPair("readOnly", qBitConfig.getReadOnly()));
      return (new MetaDataProducerMultiOutput());
   }



   /*******************************************************************************
    ** Possible-value sources: the user and group tables (for the group pickers
    ** on the actions) and the local tables' status enums.
    *******************************************************************************/
   private void addPossibleValueSources(QInstance qInstance)
   {
      for(String spec : List.of(AuthentikTables.USER, AuthentikTables.GROUP))
      {
         String name = qBitConfig.applyTablePrefix(spec);
         if(qInstance.getPossibleValueSource(name) == null)
         {
            qInstance.addPossibleValueSource(QPossibleValueSource.newForTable(name));
         }
      }
      if(qBitConfig.getLocalBackendName() != null)
      {
         for(QPossibleValueSource source : AuthentikLocalTables.possibleValueSources())
         {
            qInstance.addPossibleValueSource(source);
         }
      }
   }



   /*******************************************************************************
    ** The artifact version, from the Maven-filtered qbit-authentik.properties.
    *******************************************************************************/
   static String loadVersion()
   {
      try(InputStream inputStream = AuthentikQBitProducer.class.getClassLoader().getResourceAsStream("qbit-authentik.properties"))
      {
         if(inputStream != null)
         {
            Properties properties = new Properties();
            properties.load(inputStream);
            String version = properties.getProperty("version");
            if(StringUtils.hasContent(version) && !version.contains("${"))
            {
               return (version);
            }
         }
      }
      catch(Exception e)
      {
         LOG.debug("Could not read qbit-authentik.properties", e);
      }
      return ("unknown");
   }



   /*******************************************************************************
    ** Getter for the artifact version.
    *******************************************************************************/
   public static String getVersion()
   {
      return (VERSION);
   }

}
