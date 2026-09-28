# TempestTrace design and implementation plan

Status: design; implementation has not started. Source task: Odoo project.task 583,
"Build TempestTrace: Safe OBS Diagnostic Backup."

## Goal and boundaries

Give Rin a single Windows `.exe` they can launch by double-clicking to create an OBS
diagnostic backup that Morgan can inspect. Provide the same collection and redaction
behavior on native Linux desktops. The result is a normal timestamped folder
under `Dropbox/Jasmeralia and Rin/obs logs/`, with no ZIP and no command-line step.
Collect OBS profiles, scene collections, and relevant logs. Keep diagnostic settings
and Streamlabs source settings intact in the output. Remove credentials such as stream
keys from the output. Never modify OBS's own files or interrupt an active stream.

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
   It proposes `Jasmeralia and Rin/obs logs` beneath the selected Dropbox root.
   If either path cannot be resolved or the destination is not writable, show a
   clear error and a folder picker; never silently choose a different destination.
   The destination preview remains visible before Run.
3. Run creates `TempestTrace-YYYY-MM-DD_HH-MM-SS` (with a numeric collision suffix)
   and shows progress by phase: scanning, copying, redacting, verifying, finishing.
   The worker thread keeps the interface responsive. Cancel is supported between
   files; an incomplete run is visibly marked and never reported as successful.
4. The result screen shows the full folder path, counts of copied and skipped files,
   redaction counts by category, warnings, and buttons to open the folder or copy its
   path. A plain-text `README.txt` and machine-readable `manifest.json` repeat those
   details inside the folder, without recording secret values.

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
shows the separate Flatpak scene directory. Confirm all candidate paths on real
Windows and Linux installations before shipping.

## Redaction contract

Redact only the staged copies. Parse JSON structurally and INI files by section/key;
do not apply broad string replacements to scene or profile files. Preserve every
non-secret value, key order where practical, scene/source object, and diagnostic
setting. Start with explicit sensitive fields such as OBS service `key`,
`bearer_token`, `password`, authentication tokens, and client secrets. Scan logs for
known credential patterns and redact matching values while keeping the surrounding
diagnostic line. Maintain a versioned field/path rule list and fixtures taken from
synthetic OBS data; never commit Rin's real configuration or log samples.

Streamlabs source settings must remain byte-for-byte equivalent at the parsed JSON
subtree level. A credential detected inside that subtree is a conflict between the
preservation and redaction requirements: block a successful backup, explain the
specific source/file and ask Morgan to decide a narrow rule before release. Never
quietly strip Streamlabs settings or silently include a detected credential.

Before success, re-read every staged file and scan for known credential signatures,
including original test fixture secrets. Files that cannot be parsed or sanitized are
omitted with a warning, or fail the run when required for diagnosis. `README.txt`,
`manifest.json`, application logs, error messages, and exception traces must also be
free of secret values. Report counts and file paths, never removed values.

## Output safety and layout

Stage in a uniquely named incomplete folder within the target parent, then rename
to the final timestamped name only after verification. Include a completion marker
in the manifest. A failed or cancelled run leaves an explicitly named incomplete
folder that the UI offers to remove; it must never masquerade as a complete backup.
Do not overwrite an existing run. Record source relative path, output relative path,
size, checksum, redaction categories/counts, read consistency, and warning state for
each file. Avoid storing the Windows user name or raw absolute OBS path in the
manifest unless required to explain a failure.

## Updates and release channels

- Check GitHub Releases for a newer version on startup by default, without blocking
  the GUI. Persist settings for automatic checks and **Include beta updates**;
  provide **Help > Check for Updates** for an explicit check. A failed or offline
  check leaves collection usable. Do not contact any service during collection.
- Ignore drafts and select the highest compatible release with a matching asset for
  the current OS and architecture. Stable installations default to stable releases;
  beta installations keep receiving beta updates unless the user opts out. Show
  current and offered versions, stable/beta label, release notes, download size, and
  an explicit **Download and Update** action. Do not install silently.
- Embed the CI-created version tag in each binary and compare versions with a
  semantic-version parser. Do not treat the source-tree `0.0.0` placeholder as an
  installed release version.
- Download to a temporary file, check size and the release's SHA-256 manifest, and
  reject missing, mismatched, or wrong-platform assets before launch. Keep the
  current version usable if download or application fails. Never put OBS data or
  credentials in update requests or update logs.
- On Windows, the one-file executable cannot replace itself while running. After
  user confirmation, a detached updater waits for TempestTrace to exit, replaces the
  old executable in a writable location with rollback available, and launches the
  new version. If the original location is not writable, offer the verified new
  executable in Downloads with clear instructions. Updating TempestTrace never
  closes or restarts OBS.
- On Linux, check automatically on the same schedule. Offer the matching GitHub
  package for DEB/RPM/Flatpak/Snap and hand off installation to that package system;
  an AppImage may use a verified replace-after-exit flow. Never overwrite a managed
  package from inside the app or invoke a privileged package command silently.
- Publish beta releases as GitHub prereleases. Stable publication is a separate,
  explicit decision after Rin validates a real backup; the release workflow must
  not silently promote a prerelease to stable. Keep the current `v0.1.N` tag
  strategy, with `N` based on master commit position, during beta development and
  revise it deliberately when defining the first stable version.

## Architecture and toolchain

- Python 3 with PyQt6, following StormFuse's small dark desktop UI and worker-thread
  pattern. Keep pure collection/redaction code separate from Qt, so it runs in
  Linux CI and can be tested with fixture trees. Use `pathlib` and separate Windows
  and Linux path adapters; the GUI only coordinates the plan and displays results.
- Suggested modules: `paths` (OBS/Dropbox discovery), `inventory` (allowlist and size
  checks), `snapshot` (read-only copies and consistency), `redaction` (JSON, INI, log
  rules), `verify` (output scan and manifest), `ui` (one-window flow), and `jobs`
  (Qt worker and cancellation).
- Use PyInstaller `--onefile --windowed` to produce one directly launchable Windows
  `.exe`; no archive or installer step for Rin. Build sideloadable DEB, RPM, AppImage,
  Flatpak, and Snap assets for Linux amd64 and arm64, following the sibling repos'
  packaging conventions. The Linux packages must grant or request access to OBS's
  config tree and the chosen Dropbox folder; test Flatpak portals and Snap filesystem
  access rather than assuming sandbox access. State each package's glibc/runtime
  floor and architecture in release notes. No FFmpeg dependency is needed.
- Run a Windows smoke test of the built `.exe`, including launch from Explorer and
  a synthetic OBS/Dropbox fixture. Smoke-test each Linux package on native Linux;
  test native and Flatpak OBS path discovery and a relocated Dropbox folder.
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
CI uploads both to Codecov using GitHub OIDC and stores the reports as an Actions
artifact. Codecov enforces 80% project and patch targets; master requires both
Codecov checks alongside `Lint & Test`. Synthetic release-script tests establish
the initial baseline, and collector tests must maintain those targets.

## Delivery stages

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
   of non-secret settings and Streamlabs subtrees, plus rejection of unhandled
   secrets, parse failures, and secrets in all user-visible reports.
4. **GUI and packaging:** a single clear window, accessible progress/cancellation,
   completion actions, a Windows one-file build, and native Linux packages. Test
   while OBS is running and streaming; confirm no source writes, restarts, or stream
   interruption on both platforms.
5. **Updates and beta channel:** write failing tests for release selection, channel
   preference, checksum validation, interrupted downloads, update rollback, and
   platform-specific application before implementing the updater and UI.
6. **Release:** expand the current Windows-only workflow to build and smoke-test all
   required Linux assets before adding the `build/release-ready` marker and enabling
   publication. After CI passes on a master
   merge, derive a stable version tag from
   that commit's first-parent position on master, create the tag in CI, and serialize
   retries by commit SHA without replacing builds for other master commits;
   publish the Windows `.exe` and Linux assets as a GitHub beta prerelease with
   generated notes and SHA-256 checksums. Never publish a release from the
   design-only foundation or without Windows and Linux smoke tests.

## Acceptance checks

- Rin can double-click the `.exe`, choose/confirm the Dropbox location, and finish
  without extracting a ZIP or opening a terminal.
- A completed output has profiles, scene collections, relevant logs, `README.txt`,
  and `manifest.json` in an ordinary folder.
- Synthetic stream keys, bearer tokens, and passwords are absent from every output
  file and from UI/application messages; normal OBS settings and Streamlabs source
  subtrees are unchanged after parsing.
- The original OBS tree is byte-for-byte unchanged; the app never terminates OBS.
- Native Linux and Windows produce equivalent sanitized output; Linux packages work
  on both architectures and with native or Flatpak OBS configuration locations.
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
  redaction list. The first real backup remains blocked if preservation conflicts
  with a credential found in Streamlabs settings.
