# TempestTrace design and implementation plan

Status: implementation in progress. The path adapters, collector, redaction, PyQt
window, verified updater, Linux package definitions, and cross-platform CI workflows
are implemented with synthetic fixtures. The full package workflows have not yet run
in GitHub Actions. Each successful master build will publish a beta prerelease after
the Windows and Linux CI package builds and smoke tests pass; hands-on installation,
collection, update, sandbox, and streaming checks validate that beta before Morgan
promotes it to stable.
Source task: Odoo project.task 583,
"Build TempestTrace: Safe OBS Diagnostic Backup."

## Goal and boundaries

Give Rin a Windows NSIS installer for an app that creates an OBS diagnostic backup
Morgan can inspect. Provide the same collection and redaction behavior on native
Linux desktops. The result is a single timestamped ZIP file
under `Dropbox/Jasmeralia and Rin/obs logs/`, produced by the app with no
command-line step or manual archiving. Collect OBS profiles, scene collections, and
relevant logs. Keep diagnostic settings and Streamlabs source settings intact in the
output, except for values that match a known credential pattern (such as stream
keys), which are redacted in place. Never modify OBS's own files or interrupt an
active stream.

The first release targets Windows 10/11 x64 and native Linux amd64/arm64. Support
standard OBS Studio installations on both systems and OBS Flatpak on Linux. Portable
OBS installations and additional data sources can be added only after an explicit
selection and a test fixture for their path layout. Recordings, caches,
browser profile data, arbitrary plugin directories, and system-wide diagnostics are
outside the first release.

## User flow

1. The window explains what will be copied, where it will go, and that OBS can remain
   open. It never offers to stop or restart OBS.
2. On Windows, the app resolves OBS from `%APPDATA%\obs-studio` and Dropbox from
   `%APPDATA%\Dropbox\info.json` or `%LOCALAPPDATA%\Dropbox\info.json`. On Linux,
   it checks `$XDG_CONFIG_HOME/obs-studio` (falling back to `~/.config/obs-studio`)
   and `~/.var/app/com.obsproject.Studio/config/obs-studio` for OBS Flatpak, and
   resolves Dropbox from
   `~/.dropbox/info.json`. If multiple OBS trees are found, the user chooses one.
   When TempestTrace itself runs as a Flatpak, its `$XDG_CONFIG_HOME` points to
   TempestTrace's sandbox, not the host OBS directory. Resolve native OBS from the
   host XDG config path (`$HOST_XDG_CONFIG_HOME` when present, otherwise the host
   default), and resolve OBS Flatpak from its separate app data path. Do not mistake
   TempestTrace's own configuration for OBS. A folder picker handles nonstandard OBS
   locations after the sandbox grants access.
   It proposes `Jasmeralia and Rin/obs logs` beneath the selected Dropbox root.
   If either path cannot be resolved or the destination is not writable, show a
   clear error and a folder picker; never silently choose a different destination.
   The destination preview remains visible before Run.
3. Run creates `TempestTrace-YYYY-MM-DD_HH-MM-SS.zip` (with a numeric collision
   suffix) and shows progress by phase: scanning, copying, redacting, verifying,
   packaging, finishing. The worker thread keeps the interface responsive. Cancel is
   supported between files; an incomplete run is visibly marked and never reported as
   successful.
4. The result screen shows the full ZIP file path, counts of copied and skipped
   files, redaction counts by category, warnings, and buttons to open the containing
   folder, open the ZIP, or copy its path. A plain-text `README.txt` and
   machine-readable `manifest.json` repeat those details inside the ZIP, without
   recording secret values.

## Collection contract

Use an explicit allowlist rooted in the chosen OBS configuration directory:

| Source | Output | Rule |
| --- | --- | --- |
| `basic/profiles/**` | same relative path | Copy profile configuration files, including `basic.ini` and `service.json`; sanitize credentials. |
| `basic/scenes/*.json` and `*.json.bak` | same relative path | Copy scene collections and backups; preserve source configuration and ordering. |
| `global.ini` | same relative path | Copy non-secret global OBS settings; sanitize if necessary. |
| `logs/*.txt` | same relative path | Copy the current log plus a bounded set of recent logs relevant to the flicker investigation; sanitize each. |

Discovery must not follow symlinks or Windows reparse points out of the OBS root.
Apply a per-file and total-size ceiling, record any skipped item with a reason, and
never copy unknown file types without a deliberate rule. If a file changes while being
read, retry a bounded number of times and mark it inconsistent in the manifest if it
still changes. The app reads files directly; it does not use OBS WebSocket, process
termination, or a restart. An active stream may cause the current log to change; this
is a warning, not a reason to stop OBS.

[OBS documentation](https://obsproject.com/kb/profiles) describes profiles as output
settings, while scene collections contain sources. [OBS's support forum](https://obsproject.com/forum/threads/what-files-hold-the-obs-configuration.74280/)
identifies `%APPDATA%\obs-studio` as the settings folder, and [its log guidance](https://obsproject.com/forum/threads/please-post-a-log-with-your-issue-heres-how.23074/)
identifies the `logs` subfolder. [Dropbox documents](https://help.dropbox.com/installs/locate-dropbox-folder)
the `info.json` discovery paths above. [OBS's Linux config handling](https://github.com/obsproject/obs-studio/issues/10450)
uses `XDG_CONFIG_HOME`, and [OBS's Flatpak example](https://github.com/obsproject/obs-studio/issues/13635)
shows the separate Flatpak scene directory.
[Flatpak's XDG conventions](https://docs.flatpak.org/en/latest/conventions.html)
explain the app-specific sandbox path and host XDG variables. Confirm all candidate
paths on real Windows and Linux installations before shipping.

## Redaction contract

Redact only the staged copies. Parse JSON structurally and INI files by section/key;
do not apply broad string replacements to scene or profile files. Preserve every
non-secret value, key order where practical, scene/source object, and diagnostic
setting. Start with explicit sensitive fields such as OBS service `key`,
`bearer_token`, `password`, authentication tokens, and client secrets. Scan logs for
known credential patterns and redact matching values while keeping the surrounding
diagnostic line. Maintain a versioned field/path rule list and fixtures taken from
synthetic OBS data; never commit Rin's real configuration or log samples.

Streamlabs source settings must remain equivalent to the original at the parsed JSON
subtree level, with one exception: values matching a known credential pattern (stream
keys, tokens, passwords, etc.) are redacted in place, the same as any other detected
secret. Preserve every other value, key, and structure in the subtree exactly. Never
silently include a detected credential in the output, and never strip or alter
Streamlabs settings beyond the specific redacted values.

Before success, re-read every staged file and scan for known credential signatures,
including original test fixture secrets. Files that cannot be parsed or sanitized are
omitted with a warning, or fail the run when required for diagnosis. `README.txt`,
`manifest.json`, application logs, error messages, and exception traces must also be
free of secret values. Report counts and file paths, never removed values.

## Output safety and layout

Copy each source file into a private OS temporary directory outside the selected
backup destination, then redact and verify it there. Only verified sanitized bytes
may be copied into a uniquely named incomplete staging folder within the target
parent; a Dropbox sync must never see raw OBS bytes. Include a completion marker in
the manifest before compressing the verified staging tree into the final
timestamped ZIP file, then remove the staging folder. Write the ZIP under an
incomplete name first and rename it to its final name only once it is fully written;
a failed or cancelled run leaves an explicitly named incomplete ZIP (or sanitized
staging folder, if compression never started) that the UI offers to remove, and it
must never masquerade as a complete backup. Do not overwrite an existing run.
Record source relative path, output relative path, size, checksum, redaction
categories/counts, read consistency, and warning state for each file. Avoid storing
the Windows user name or raw absolute OBS path in the manifest unless required to
explain a failure.

## Updates and release channels

- Check GitHub Releases for a newer version on startup by default, without blocking
  the GUI. Persist settings for automatic checks and **Include beta updates**;
  provide **Help > Check for Updates** for an explicit check. A failed or offline
  check leaves collection usable. Do not contact any service during collection.
- Ignore drafts and select the highest compatible release with a matching asset for
  the current OS and architecture. Offer stable releases by default for every install;
  include prereleases only when the user opts into beta updates in Preferences. Show
  current and offered versions, stable/beta label, release notes, download size, and
  an explicit **Download and Update** action. Do not install silently.
- Embed the CI-created version tag in each binary and compare versions with a
  semantic-version parser. Do not treat the source-tree `0.0.0` placeholder as an
  installed release version.
- Download to a temporary file, check size and the release's SHA-256 manifest, and
  reject missing, mismatched, or wrong-platform assets before launch. Keep the
  current version usable if download or application fails. Never put OBS data or
  credentials in update requests or update logs.
- On Windows, download and verify the NSIS setup asset after user confirmation,
  wait for TempestTrace to exit, then launch the installer detached. Keep the
  installed version usable if the new install fails. Updating TempestTrace never
  closes or restarts OBS.
- On Linux, check automatically on the same schedule. Offer the matching GitHub
  package for DEB/RPM/Flatpak/Snap and hand off installation to that package system;
  an AppImage may use a verified replace-after-exit flow with rollback. Detect the
  installed package type rather than offering a different format as an in-place
  update. These are GitHub-sideloaded packages, so no distribution repository,
  Flatpak remote, or Snap Store channel supplies updates in the first release.
  Automatic **checks** therefore use GitHub Releases for every format. Show the
  verified local package and the appropriate user-approved package-manager action;
  do not claim that `apt`, `dnf`, `flatpak update`, or Snap refresh will discover a
  future GitHub asset on its own. For Flatpak, update the installed app from a new
  local bundle and retain the app data; for Snap, document the required local-install
  trust mode and confinement. Never overwrite a managed package from inside the app
  or invoke a privileged package command silently.
  [Flatpak's single-file bundle guide](https://docs.flatpak.org/en/latest/single-file-bundles.html)
  distinguishes bundles from updateable remotes, and
  [Snap's install-mode guide](https://snapcraft.io/docs/explanation/snap-development/install-modes/)
  documents the trust and confinement flags for local snaps.
- After lint and tests pass on an untagged master commit, CI allocates and creates the
  next patch tag in the `v0.1.x` beta series, beginning at `v0.1.0`, then builds the
  Windows installer and every Linux format/architecture from that same tag. Serialize
  release builds. Retry an actual build failure with GitHub's **Re-run failed jobs**;
  it reuses the workflow's tag and successful platform artifacts. A rerun after success
  must not rebuild packages or consume a version. The next master merge gets the next
  patch version.
- After every successful master build, publish a beta prerelease once Windows and every
  Linux package/architecture job pass and the complete asset/checksum validation
  succeeds. PR updates run lint and synthetic tests; package builds run only after a
  master merge. A tag may exist without a release if a package build fails; retry only
  an actual Windows or Linux package build failure and reuse that tag. A rerun after
  success does not rebuild packages or consume a version. Existing release assets are
  immutable to CI: retry publication by
  verifying same-name assets and adding only missing files. Changing a release from
  prerelease to stable does not control this behavior. CI never changes release status
  or replaces existing assets. Morgan promotes the validated release manually without
  changing its tag or assets.

## Architecture and toolchain

- Python 3 with PyQt6, following GaleFling's dark palette and component styling plus
  StormFuse's small desktop UI and worker-thread pattern. Use the shared GaleFling
  color and typography tokens throughout the interface. Keep pure collection and
  redaction code separate from Qt so it runs in Linux CI and can be tested with fixture
  trees. Use `pathlib` and separate Windows and Linux path adapters; the GUI only
  coordinates the plan and displays results.
- Suggested modules: `paths` (OBS/Dropbox discovery), `inventory` (allowlist and size
  checks), `snapshot` (read-only copies and consistency), `redaction` (JSON, INI, log
  rules), `verify` (output scan and manifest), `package` (compress the verified
  staging tree into the final ZIP), `ui` (one-window flow), and `jobs` (Qt worker
  and cancellation).
- Use the shared Winds of Storm brand icon (`resources/icons/tempesttrace.ico` and
  `.png`, the same asset used by StormFuse and GaleFling) as the app icon. The NSIS
  installer references it via `MUI_ICON`/`MUI_UNICON`; the GUI's About dialog must
  use the same asset once the GUI stage begins. Before installing or uninstalling,
  the NSIS script terminates any running `TempestTrace.exe` first (same pattern as
  StormFuse/GaleFling), so an in-place upgrade never leaves a stale process holding
  the old executable open.
- Use PyInstaller `--onefile --windowed` to build the executable bundled in a
  per-user NSIS installer with Start Menu and uninstall entries. Publish the
  installer as the Windows release asset; keep the bare executable as an internal
  build input. NSIS must leave OBS, Dropbox, and diagnostic output untouched on
  uninstall. Build sideloadable DEB, RPM, AppImage, Flatpak, and Snap assets for Linux
  amd64 and arm64, following the sibling repos' packaging conventions. Use
  `tempesttrace` as the DEB/RPM/Snap package name and `io.github.jasmeralia.TempestTrace`
  as the Flatpak and desktop app ID; all formats need a launcher, icon, version, and
  architecture. Installed formats need clean uninstall behavior; the AppImage must
  launch without installation. Pin each format's runtime/base and state its tested
  distribution and glibc floor in release notes. The Linux
  packages must grant or request access to OBS's config tree and the chosen Dropbox
  folder; test Flatpak portals and Snap filesystem access rather than assuming sandbox
  access. Flatpak must keep the user's home read-only and grant OBS config and Dropbox
  metadata paths read-only; write access to the chosen backup folder must come from a
  user-approved file chooser portal grant. No FFmpeg dependency is needed.
- Run a Windows smoke test of the built `.exe`, including launch from Explorer and
  a synthetic OBS/Dropbox fixture. Silently install the NSIS asset in CI, smoke-test
  the installed executable, uninstall, and verify removal of installed files.
  Smoke-test install, launch, fixture collection, and uninstall or replacement of
  each Linux package on native Linux for both architectures. Test native and Flatpak
  OBS path discovery, a relocated Dropbox folder, sandbox permissions, and an update
  from an older GitHub-sideloaded package of the same format. Include a matrix for
  native TempestTrace with native/Flatpak OBS and Flatpak TempestTrace with
  native/Flatpak OBS, since the app sandbox changes XDG path resolution.
- Use `ruff check`, `ruff format --check`, `mypy --strict`, and `pytest` as the lint
  and test gate. Follow the Makefile entry points and GitHub Actions conventions from
  StormFuse and GaleFling. Add targeted redaction and no-source-write tests before
  shipping any collector implementation.

## Test-driven implementation

For each behavior, first add a failing test based on the contract in this document,
then implement the smallest change that passes it, then refactor with the tests
green. Keep fixtures synthetic and never use Rin's live OBS or Dropbox data in CI.
Use unit tests for path selection, allowlisting, JSON/INI/log redaction, version and
update-channel selection, manifest generation, and refusal of unsafe output. Use
temporary directory integration tests to prove the OBS source tree is byte-for-byte
unchanged, incomplete runs are not presented as complete, and a failed update
preserves the installed version. Test both OS path adapters through injected paths;
run real Windows and native Linux smoke tests before a release. Add a regression
test before fixing any bug found during implementation.

PR CI must run lint and the complete synthetic test suite. Packaging jobs must run
their platform smoke tests before publication. Manual release testing still covers
the active-stream case and nontechnical GUI flow, which fixture tests cannot prove.
`make test` must emit `coverage.xml` with pytest-cov and `junit.xml` with pytest;
CI uploads both to Codecov using GitHub OIDC for trusted runs and tokenless uploads
for public fork PRs, then stores the reports as an Actions artifact. Codecov enforces
80% project and patch targets; master requires both
Codecov checks alongside `Lint & Test`. Synthetic release-script tests establish
the initial baseline, and collector tests must maintain those targets.

## Delivery stages

The current implementation covers the initial synthetic path discovery, allowlisted
snapshot, redaction, ZIP and manifest workflow, and the basic desktop collection flow.
It does not yet satisfy the complete acceptance list below. Keep this status current as
the remaining updater and packaging stages are implemented and tested.

1. **Repository foundation:** README, this design, license and contributor guidance,
   Dependabot for pip and GitHub Actions, CODEOWNERS, PR CI, branch protection,
   automatic Copilot review, and required conversation resolution. Configure
   vulnerability alerts and verify `git-activity-monitor` covers the new repo.
   Enable Dependabot squash auto-merge with a dedicated token that triggers master
   CI, and require `codecov/project` and `codecov/patch` in branch protection.
2. **Pure collector:** test-first path discovery for Windows, native Linux, and OBS
   Flatpak; allowlist, bounded file inventory, copy and manifest logic. Test on
   synthetic trees, including missing/relocated Dropbox, symlinks/reparse points,
   locked/changing files, and filename collisions.
3. **Redaction:** structural JSON/INI rules and log scanner. Test exact preservation
   of non-secret settings, including Streamlabs subtrees, plus redaction of known
   credential patterns within those subtrees, rejection of unhandled secrets, parse
   failures, and secrets in all user-visible reports.
4. **GUI and packaging:** a single clear window, accessible progress/cancellation,
   completion actions, a Windows one-file build bundled into an NSIS installer,
   and native Linux packages. Include an About dialog using the shared
   `resources/icons/tempesttrace` asset already wired into the NSIS installer.
   Test while OBS is running and streaming; confirm no source writes, restarts, or
   stream interruption on both platforms.
5. **Updates and beta channel:** write failing tests for release selection, channel
   preference, checksum validation, interrupted downloads, update rollback, and
   platform-specific application before implementing the updater and UI.
6. **Release:** build and smoke-test the Windows installer and all required Linux
   assets after each master merge. A final release job depends on successful Windows
   and every Linux package/architecture job, verifies the complete asset matrix and
   checksums, then publishes the Windows NSIS setup installer and Linux assets as a
   GitHub beta prerelease with generated notes and SHA-256 checksums. A failed or
   missing package job leaves no partial release. Serialize builds and retry actual
   failed jobs against the same tag without replacing existing assets. Morgan validates
   a prerelease and promotes that same release to stable without changing its tag or
   assets.

## Acceptance checks

- Rin can install the NSIS package, launch the app, choose/confirm
  the Dropbox location, and finish without opening a terminal or manually creating
  or extracting an archive; the app produces the ZIP itself.
- The Windows installer supports a clean per-user install, launches the installed app,
  uninstalls only its own files, and never changes OBS, Dropbox, or backup outputs.
- A completed output is a single ZIP file containing profiles, scene collections,
  relevant logs, `README.txt`, and `manifest.json`.
- Synthetic stream keys, bearer tokens, and passwords are absent from every output
  file and from UI/application messages, including within Streamlabs source subtrees;
  every other OBS and Streamlabs setting is unchanged after parsing.
- The original OBS tree is byte-for-byte unchanged; the app never terminates OBS.
- Native Linux and Windows produce equivalent sanitized output; Linux packages work
  on both architectures and with native or Flatpak OBS configuration locations.
- Every Linux format launches from a desktop entry or AppImage entry point, accesses
  the chosen OBS and Dropbox folders, and supports a verified, user-approved update
  from a prior GitHub-sideloaded release of the same format.
- Startup and manual update checks honor stable/beta preferences, verify downloads,
  and leave the installed version usable after an update failure.
- Each testable behavior has a test written before its implementation; PR CI and all required
  platform smoke tests pass before a beta release is published.
- PRs require green lint/test checks and resolved review threads; Copilot reviews
  new PRs and new pushes; master rejects direct pushes and force pushes. Codecov
  project and patch checks must pass; Dependabot PRs auto-merge after all gates pass.

## Decisions to validate during implementation

- Confirm Rin's OBS is a standard installation, and confirm the Dropbox account and
  actual folder location on their PC before the first real diagnostic run.
- Choose the recent-log count/age limit after seeing how long the flicker issue takes
  to reproduce; retain a user-selectable option for a specific log if needed.
- Run a synthetic fixture from Rin's OBS version before finalizing the field/path
  redaction list, including the Streamlabs-specific fields that need redaction.
