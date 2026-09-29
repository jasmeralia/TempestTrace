# Linux package build scaffold

`build-packages.sh` creates local-installable DEB and RPM packages, an AppImage,
a Flatpak single-file bundle, and a locally installable Snap for the machine's
native architecture. Files use the release asset pattern
`TempestTrace-v{version}-linux-{amd64|arm64}.{deb|rpm|AppImage|flatpak|snap}`.
It expects a Linux host with Python 3.14, PyInstaller, and
the format-specific tools listed below. `APP_VERSION` must be a package-safe
version (the workflow uses the current commit SHA for non-release builds).

The reusable GitHub Actions workflow builds and checks amd64 and arm64 artifacts
as part of the main CI/release run. After a master merge, the release job verifies
the complete package matrix and checksums, then publishes a beta prerelease.

## Host tools

- DEB: `dpkg-deb` (Ubuntu runner package `dpkg`).
- RPM: `rpmbuild` (Ubuntu runner package `rpm`; the workflow install-smokes the
  RPM in the Fedora 42 container).
- AppImage: `appimagetool` 13 from the AppImageKit GitHub release.
- Flatpak: Flatpak 1.14 or newer, Flathub's pinned Freedesktop 26.08 runtime
  and SDK for the host architecture.
- Snap: Snapcraft's `8.x/stable` channel and the core24 base. Local installation
  requires `snap install --dangerous`; strict confinement requests the `obs-config`
  personal-files interface for standard hidden OBS and Dropbox metadata paths.
  Connect it once with `sudo snap connect tempesttrace:obs-config` if snapd does
  not connect it automatically.

The binary is frozen with PyInstaller on Ubuntu 22.04, so its glibc
floor is glibc 2.35. DEB, RPM, and AppImage builds depend on Qt platform plugins
and system libraries supplied by the target machine; the package metadata is a
starting point and still needs testing on each promised distribution. Fedora
42 is the RPM install smoke-test container. The Flatpak and Snap assets
use their core24/Freedesktop 26.08 runtimes rather than the host glibc.

## Access and validation limits

DEB, RPM, and AppImage run outside a filesystem sandbox. The Flatpak requests
network access for GitHub update checks and read/write access to the user's home
directory so it can read native OBS settings and Dropbox metadata and write the
selected backup; this is broader than a single-folder portal grant. Flatpak's
`home` permission excludes `~/.var/app/<app-id>`; TempestTrace separately
requests read-only access to
`~/.var/app/com.obsproject.Studio/config/obs-studio` so it can discover OBS's
Flatpak data. CI tests collection from both native and OBS Flatpak fixture paths.
Relocated Dropbox folders outside the home directory may require a file chooser
portal grant; portal behavior remains unverified with this PyQt6 UI. The strict
Snap declares `home` plus an `obs-config`
personal-files plug for standard hidden OBS and Dropbox metadata paths. The user
or administrator must connect that plug after installation. Relocated data
outside the home directory needs additional access and has not been validated.

Linux CI installs and launches each package and removes installed packages. It
also collects synthetic native and OBS Flatpak fixtures with the strict Flatpak,
then checks redaction and confirms the source fixtures were unchanged. The strict
Snap collection check explicitly connects `obs-config`. These checks do not test
real OBS installations, streaming, file chooser portal access, relocated Dropbox
folders, or same-format updates. The Snap is a sideloaded package; users
connect its `obs-config` plug after installation, as the CI smoke test does. The
updater is implemented, including AppImage replacement with rollback and
package-manager handoff, but those update paths still need platform smoke tests.
Published beta artifacts therefore still require hands-on validation before manual
promotion to stable.
