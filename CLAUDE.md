# qbit-template-extension

GitHub template repository for scaffolding QQQ "Extension QBits" (infrastructure-level plugins: table customizers, auth, audit, action wrappers). Not a shipping library — consumers click "Use this template" and rename the `com.kingsrook.qbits.example` package.

## QQQ 4.0 baseline — 2026-09-24

The historical review below predates the 4.0 migration. This template targets Java 21 and the public QQQ 4.0.0 release from Maven Central. The corrected APIs, license references and actual template commands are in README.md and docs/00-getting-started.md. Preserve the documented multi-instance and scaffold limitations.

## Knowledge base

Reviewed dossiers for this repo and the wider QQQ platform live in the second-brain vault:

- Hub / entry point: `R:/Git.Local/KofTwentyTwo/second-brain/knowledge/qqq/qqq-hub.md`
- This repo's dossier: `R:/Git.Local/KofTwentyTwo/second-brain/knowledge/qqq/repos/qbit-template-extension.md`
- QBit mechanics refresher: `R:/Git.Local/KofTwentyTwo/second-brain/knowledge/qqq/architecture/metadata-model.md`

Reviewed at commit `e7d4b4d672cc` (branch `main`, 2026-05-21). Known drift as of that review: no `qbit-build-parent` parent pom (org convention), qqq pinned at 0.35.0 on main (0.40.0-SNAPSHOT on develop), README still claims AGPL-3.0 while LICENSE/NOTICE are Apache-2.0, and README references `scripts/customize_template.py` / `actions/ExampleActionCustomizer.java` which do not exist. See the dossier's "Maturity & risks" and "v4.0 impact" sections before modifying the scaffold.
