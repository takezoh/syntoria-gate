# Gate development guidance

Write all documentation, code comments, schema descriptions and example annotations in English. Respond to the user in their requested language.

Read [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/development.md](docs/development.md). Confirm behavioral claims against implementation and tests. Keep current behavior in product and technical documentation, and change history under `docs/changes/`.

Keep actual domains, redirect registrations, local settings and credentials out of tracked files and generated release artifacts, as described in [Deployment identifiers](#deployment-identifiers). Use synthetic examples. Preserve deployed resource identities, data, secret versions and access boundaries during operational changes.

Documentation-only changes require language, local-link and content checks. Do not claim runtime or hosted acceptance from document validation. Use the existing dev-docs configuration for structured development records.

## Deployment identifiers

Never commit actual deployment identifiers: not in tracked files, commit messages, test fixtures, examples, documentation, evidence and release records, or generated artifacts. They include GCP project IDs and numbers, service account emails, Cloud Run and other service URLs (`*.run.app`), Artifact Registry paths, Cloud Storage bucket names, production and personal domains and hostnames, redirect registrations, private site URLs, and provider account or endpoint identifiers such as Neon or Cloudflare. They are not secrets, but they map the production environment and the repositories can be public.

- Keep real values in ignored local files (`.local/gate-runtime.json` for the project, issuer, cookie parent, GitHub account and browser apps; `.local/terraform.tfvars` for Terraform) and inject them when rendering or running. Do not hard-code them in scripts, templates or tests.
- In tracked files use only synthetic placeholders: project `example-project`, project number `123456789012` and domains under `example.com` or `example.test`.
- Before committing, check the staged diff, new files and the commit message for such values, including values copied from command output, cloud readbacks or hosted verification.
- If one has been committed, do not push. Report it instead: removing it requires rewriting history and a force push.
