# TempestTrace design and implementation plan

Status: design; implementation has not started. Source task: Odoo project.task 583,
"Build TempestTrace: Safe OBS Diagnostic Backup."

## Goal and boundaries

Give Rin a single Windows `.exe` they can launch by double-clicking to create an OBS
diagnostic backup that Morgan can inspect. The result is a normal timestamped folder
under `Dropbox/Jasmeralia and Rin/obs logs/`, with no ZIP and no command-line step.
Collect OBS profiles, scene collections, and relevant logs. Keep diagnostic settings
and Streamlabs source settings intact in the output. Remove credentials such as stream
keys from the output. Never modify OBS's own files or interrupt an active stream.

The first release targets Windows 10/11 x64 and the default OBS Studio installation.
Portable OBS installations and additional data sources can be added only after an
explicit selection and a test fixture for their path layout. Recordings, caches,
browser profile data, arbitrary plugin directories, and system-wide diagnostics are
outside the first release.

## User flow

1. The window explains what will be copied, where it will go, and that OBS can remain
   open. It never offers to stop or restart OBS.
2. The app resolves OBS from `%APPDATA%\obs-studio`. It resolves the Dropbox root from
   `%APPDATA%\Dropbox\info.json` or `%LOCALAPPDATA%\Dropbox\info.json`, then proposes
   `Jasmeralia and Rin\obs logs` beneath it. If either cannot be resolved or the
   destination is not writable, show a clear error and a folder picker; never silently
   choose a different destination. The destination preview remains visible before Run.
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
the `info.json` discovery paths above.

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

## Architecture and toolchain

- Python 3 with PyQt6, following StormFuse's small dark desktop UI and worker-thread
  pattern. Keep pure collection/redaction code separate from Qt, so it runs in Linux
  CI and can be tested with fixture trees. Use `pathlib` and explicit Windows path
  adapters; the GUI only coordinates the plan and displays results.
- Suggested modules: `paths` (OBS/Dropbox discovery), `inventory` (allowlist and size
  checks), `snapshot` (read-only copies and consistency), `redaction` (JSON, INI, log
  rules), `verify` (output scan and manifest), `ui` (one-window flow), and `jobs`
  (Qt worker and cancellation).
- Use PyInstaller `--onefile --windowed` to produce one directly launchable `.exe`;
  no archive or installer step for Rin. Run a Windows smoke test of the built file,
  including launch from Explorer and a synthetic OBS/Dropbox fixture.
- Use `ruff check`, `ruff format --check`, `mypy --strict`, and `pytest` as the lint
  and test gate. Follow the Makefile entry points and GitHub Actions conventions from
  StormFuse and GaleFling. Add targeted redaction and no-source-write tests before
  shipping any collector implementation.

## Delivery stages

1. **Repository foundation:** README, this design, license and contributor guidance,
   Dependabot for pip and GitHub Actions, CODEOWNERS, PR CI, branch protection,
   automatic Copilot review, and required conversation resolution. Configure
   vulnerability alerts and verify `git-activity-monitor` covers the new repo.
2. **Pure collector:** path discovery, allowlist, bounded file inventory, copy and
   manifest logic. Test on synthetic trees, including missing/relocated Dropbox,
   symlinks/reparse points, locked/changing files, and filename collisions.
3. **Redaction:** structural JSON/INI rules and log scanner. Test exact preservation
   of non-secret settings and Streamlabs subtrees, plus rejection of unhandled
   secrets, parse failures, and secrets in all user-visible reports.
4. **GUI and packaging:** a single clear window, accessible progress/cancellation,
   completion actions, and a Windows one-file build. Test while OBS is running and
   streaming; confirm no source writes, restarts, or stream interruption.
5. **Release:** after CI passes on a master merge, derive a stable version tag from
   that commit's first-parent position on master, create the tag in CI, and serialize
   retries by commit SHA without replacing builds for other master commits;
   build the Windows `.exe`, verify its launch and required asset, and publish a
   GitHub prerelease with generated notes and SHA-256 checksum. Never publish a
   release from the design-only foundation or without a Windows smoke test.

## Acceptance checks

- Rin can double-click the `.exe`, choose/confirm the Dropbox location, and finish
  without extracting a ZIP or opening a terminal.
- A completed output has profiles, scene collections, relevant logs, `README.txt`,
  and `manifest.json` in an ordinary folder.
- Synthetic stream keys, bearer tokens, and passwords are absent from every output
  file and from UI/application messages; normal OBS settings and Streamlabs source
  subtrees are unchanged after parsing.
- The original OBS tree is byte-for-byte unchanged; the app never terminates OBS.
- PRs require green lint/test checks and resolved review threads; Copilot reviews
  new PRs and new pushes; master rejects direct pushes and force pushes.

## Decisions to validate during implementation

- Confirm Rin's OBS is a standard installation, and confirm the Dropbox account and
  actual folder location on their PC before the first real diagnostic run.
- Choose the recent-log count/age limit after seeing how long the flicker issue takes
  to reproduce; retain a user-selectable option for a specific log if needed.
- Run a synthetic fixture from Rin's OBS version before finalizing the field/path
  redaction list. The first real backup remains blocked if preservation conflicts
  with a credential found in Streamlabs settings.
