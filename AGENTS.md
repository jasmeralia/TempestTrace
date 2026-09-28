# TempestTrace project instructions

Read [docs/DESIGN.md](docs/DESIGN.md) before changing collection, redaction,
packaging, or the user flow. This is a design-stage repository; do not describe it as
a working OBS backup utility until the acceptance checks are implemented and tested.

The original OBS configuration must remain read-only. Keep collection and redaction
independent of Qt, and test them with synthetic fixtures. Never commit real OBS
profiles, scenes, logs, Dropbox metadata, tokens, or credentials.

Use test-driven development for behavior changes: add a failing synthetic test,
implement the behavior, then refactor with the tests green. Cover Windows and Linux
path adapters, including native and Flatpak OBS locations. Add a regression test
before fixing a discovered bug.

Before a code PR, run `make lint` and `make test`. On Windows, also smoke-test the
one-file executable when the packaging target exists. Keep README and design docs
current with user-facing changes.

Successful master builds publish beta prereleases. Morgan promotes a validated
prerelease to a full release manually using the same tag and assets. CI must never
promote a release or downgrade one back to prerelease on rerun. CI must build and
smoke-test the Windows portable executable, NSIS installer, and all required Linux
packages before tagging or publishing. Do not add
`build/release-ready` until that multi-platform workflow is complete.

PRs require `Lint & Test`, `codecov/project`, and `codecov/patch`. Keep pytest-cov's
`coverage.xml` and pytest's `junit.xml` uploads working. Dependabot auto-merge uses
the dedicated `DEPENDABOT_MERGE_TOKEN` Dependabot secret so its master merge triggers
release CI. Configure it in Settings → Secrets and variables → Dependabot; an Actions
secret is not exposed to Dependabot-triggered workflows.
