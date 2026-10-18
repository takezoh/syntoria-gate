# Gate development guidance

Write all documentation, code comments, schema descriptions and example annotations in English. Respond to the user in their requested language.

Read [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/development.md](docs/development.md). Confirm behavioral claims against implementation and tests. Keep current behavior in product and technical documentation, and change history under `docs/changes/`.

Keep actual domains, redirect registrations, local settings and credentials out of tracked files and generated release artifacts. Use synthetic examples. Preserve deployed resource identities, data, secret versions and access boundaries during operational changes.

Documentation-only changes require language, local-link and content checks. Do not claim runtime or hosted acceptance from document validation. Use the existing dev-docs configuration for structured development records.
