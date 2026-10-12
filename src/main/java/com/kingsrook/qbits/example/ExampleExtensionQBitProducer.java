/*******************************************************************************
 ** Producer for the Example Extension QBit.
 *******************************************************************************/
package com.kingsrook.qbits.example;

import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitProducer;


/*******************************************************************************
 ** Producer class for the Example Extension QBit.
 *******************************************************************************/
public class ExampleExtensionQBitProducer implements QBitProducer
{
   public static final String GROUP_ID    = "com.kingsrook.qbits";
   public static final String ARTIFACT_ID = "qbit-example-extension";
   public static final String VERSION     = "0.1.0";

   private ExampleExtensionQBitConfig config;



   /*******************************************************************************
    ** Produce this QBit into the given QInstance.
    *******************************************************************************/
   @Override
   public void produce(QInstance qInstance, String namespace) throws QException
   {
      QBitMetaData qBitMetaData = new QBitMetaData()
         .withGroupId(GROUP_ID)
         .withArtifactId(ARTIFACT_ID)
         .withVersion(VERSION)
         .withNamespace(namespace)
         .withConfig(config);

      qInstance.addQBit(qBitMetaData);

      if(config != null && config.getTargetTableName() != null)
      {
         applyTableCustomizations(qInstance, config.getTargetTableName());
      }
   }



   /*******************************************************************************
    ** Apply customizations to the target table.
    *******************************************************************************/
   private void applyTableCustomizations(QInstance qInstance, String tableName)
   {
      // Implement your extension logic here
   }



   /*******************************************************************************
    ** Fluent setter for config
    *******************************************************************************/
   public ExampleExtensionQBitProducer withConfig(ExampleExtensionQBitConfig config)
   {
      this.config = config;
      return this;
   }
}
