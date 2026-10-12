# Extension Patterns

[ExampleExtensionQBitProducer](../src/main/java/com/kingsrook/qbits/example/ExampleExtensionQBitProducer.java) registers the QBit identity and calls `applyTableCustomizations` for the configured target. That method is the extension point: look up the table, validate that it exists, and call your customized [ExampleTableCustomizer](../src/main/java/com/kingsrook/qbits/example/customizers/ExampleTableCustomizer.java).

```java
QTableMetaData table = qInstance.getTable(tableName);
if(table == null)
{
   throw new QException("Target table not found: " + tableName);
}
new ExampleTableCustomizer().customize(table);
```

When implementing this method, add `throws QException` to its declaration. Run the config's `validate(QInstance, List<String>)` before registering metadata, and report validation errors rather than silently ignoring a missing target. The uncustomized template contains placeholders for this behavior.

For record hooks, use QQQ's existing table customizer interfaces or `AbstractPreInsertCustomizer`. Its `apply(List<QRecord>)` method returns the records for the next stage; register the customizer through the table's `TableCustomizers.PRE_INSERT_RECORD` role. Check the actual QQQ interface before adding another hook. Add tests proving that the intended table changes and invalid configurations are handled.
