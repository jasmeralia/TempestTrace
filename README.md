# TempestTrace

TempestTrace is a planned Windows desktop utility for collecting a safe OBS Studio
diagnostic backup for troubleshooting Rin's screen flicker issue.

The [design and implementation plan](docs/DESIGN.md) defines the collection scope,
redaction rules, user flow, tests, and release criteria. The collector and executable
have not been implemented yet; this repository currently contains the plan and
project setup. CI runs lint and tests on PRs and master; after a future implementation
adds `build/TempestTrace.spec` and a `--smoke-test` entry point, master merges will
build and publish a one-file Windows prerelease. Prerelease tags use the master
commit position (`v0.1.<position minus one>`), so every merge has a stable tag even
when builds overlap or are retried; version numbers can have gaps before the first
executable is ready.

## Intended use

Rin will double-click a standalone Windows executable, review the proposed output
location, and start a read-only collection. A successful run will leave a normal,
timestamped folder under `Dropbox/Jasmeralia and Rin/obs logs/` with sanitized OBS
profiles, scene collections, recent logs, and a readable manifest. The utility will
never stop OBS or change its source files.

## Source references

- [OBS Studio profiles](https://obsproject.com/kb/profiles)
- [OBS Studio configuration folder](https://obsproject.com/forum/threads/what-files-hold-the-obs-configuration.74280/)
- [OBS Studio log location](https://obsproject.com/forum/threads/please-post-a-log-with-your-issue-heres-how.23074/)
- [Dropbox folder discovery](https://help.dropbox.com/installs/locate-dropbox-folder)
