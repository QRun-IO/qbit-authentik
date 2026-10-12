# QBit Template: Extension

Template repository for creating QQQ Extension QBits - infrastructure extensions, customizers, and action handlers.

## What is an Extension QBit?

Extension QBits extend or enhance how QQQ operates at the infrastructure/framework level. They provide:
- New backend implementations
- Authentication mechanisms
- Audit capabilities
- Table customizers
- Action handlers

## Quick Start

Requires **Java 21**, **Maven 3.8+**, and QQQ **4.0.0**. Create your repository, customize its Maven coordinates and Java package/classes, implement the table customizer, then run `mvn clean verify`. See [Getting Started](docs/00-getting-started.md).

## Structure

```
src/main/java/com/kingsrook/qbits/example/
├── ExampleExtensionQBitConfig.java    # Configuration
├── ExampleExtensionQBitProducer.java  # Entry point
└── customizers/
    └── ExampleTableCustomizer.java    # Table customization
```

## Key Characteristics

- **No QAppSection** - Pure infrastructure
- **No user-facing tables** (or minimal operational)
- **Wraps existing tables/processes** with new behavior
- **Validates dependencies** on other QQQ components

## Documentation

- [Getting Started](docs/00-getting-started.md)
- [Extension Patterns](docs/01-extension-patterns.md)

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
