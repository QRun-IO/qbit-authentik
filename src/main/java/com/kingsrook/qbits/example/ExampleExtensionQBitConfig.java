/*******************************************************************************
 ** Configuration for the Example Extension QBit.
 *******************************************************************************/
package com.kingsrook.qbits.example;

import java.util.List;

import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitConfig;


/*******************************************************************************
 ** Configuration class for the Example Extension QBit.
 *******************************************************************************/
public class ExampleExtensionQBitConfig implements QBitConfig
{
   private String  targetTableName;
   private Boolean enableFeatureX = true;



   /*******************************************************************************
    ** Validate configuration before QBit is produced.
    *******************************************************************************/
   @Override
   public void validate(QInstance qInstance, List<String> errors)
   {
      if(targetTableName != null && qInstance.getTable(targetTableName) == null)
      {
         errors.add("Target table not found: " + targetTableName);
      }
   }



   /*******************************************************************************
    ** Getter for targetTableName
    *******************************************************************************/
   public String getTargetTableName()
   {
      return targetTableName;
   }



   /*******************************************************************************
    ** Fluent setter for targetTableName
    *******************************************************************************/
   public ExampleExtensionQBitConfig withTargetTableName(String targetTableName)
   {
      this.targetTableName = targetTableName;
      return this;
   }



   /*******************************************************************************
    ** Getter for enableFeatureX
    *******************************************************************************/
   public Boolean getEnableFeatureX()
   {
      return enableFeatureX;
   }



   /*******************************************************************************
    ** Fluent setter for enableFeatureX
    *******************************************************************************/
   public ExampleExtensionQBitConfig withEnableFeatureX(Boolean enableFeatureX)
   {
      this.enableFeatureX = enableFeatureX;
      return this;
   }
}
