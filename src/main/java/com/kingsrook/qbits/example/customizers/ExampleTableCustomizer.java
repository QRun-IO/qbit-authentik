/*******************************************************************************
 ** Example table customizer.
 *******************************************************************************/
package com.kingsrook.qbits.example.customizers;

import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** Example table customizer that adds behavior to existing tables.
 *******************************************************************************/
public class ExampleTableCustomizer
{

   /*******************************************************************************
    ** Apply customizations to the given table.
    *******************************************************************************/
   public void customize(QTableMetaData table)
   {
      // Example: Add audit tracking fields
      // table.withField(new QFieldMetaData("createdAt", QFieldType.DATE_TIME));
   }
}
