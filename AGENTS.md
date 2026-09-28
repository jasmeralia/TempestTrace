# TempestTrace project instructions

Read [docs/DESIGN.md](docs/DESIGN.md) before changing collection, redaction,
packaging, or the user flow. This is a design-stage repository; do not describe it as
a working OBS backup utility until the acceptance checks are implemented and tested.

The original OBS configuration must remain read-only. Keep collection and redaction
independent of Qt, and test them with synthetic fixtures. Never commit real OBS
profiles, scenes, logs, Dropbox metadata, tokens, or credentials.

Before a code PR, run `make lint` and `make test`. On Windows, also smoke-test the
one-file executable when the packaging target exists. Keep README and design docs
current with user-facing changes.

Releases are prereleases until Rin has validated a real diagnostic backup. CI must
build and smoke-test the Windows executable before tagging or publishing a release.
