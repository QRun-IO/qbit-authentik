# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Phase 0 foundations: `AuthentikQBitConfig`, `AuthentikQBitProducer`, `AuthentikActionUtil` (bearer auth, page/page_size paging, filter mapping that rejects unsupported filters, 10 rps token-bucket throttle, log redaction), read-only Users and Groups tables, Identity app.
- Pinned Authentik 2026.8.3 OpenAPI schema and schema drift tests.
- Testcontainers contract tests against Authentik 2026.8.3 (bootstrap on an empty instance, superuser floor, blueprint re-apply safety, access-check behaviour) and a fixture recorder.
