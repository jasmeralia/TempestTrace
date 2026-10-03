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
- AppImage: `appimagetool` 1.9.1 from the `AppImage/appimagetool` release, verified by SHA-256.
- AppImage runtime: `AppImage/type2-runtime` release `20251108`, downloaded for the
  target architecture and verified by SHA-256 before use. `APPIMAGE_RUNTIME_FILE`
  must point to this verified regular file when running `build-packages.sh`.
- Flatpak: Flatpak 1.14 or newer, Flathub's pinned Freedesktop 26.08 runtime
  and SDK for the host architecture.
- Snap: Snapcraft's `8.x/stable` channel and the core24 base. Local installation
  requires `snap install --dangerous`; strict confinement requests the `obs-config`
  personal-files interface for standard hidden OBS and Dropbox metadata paths.
  Connect it once with `sudo snap connect tempesttrace:obs-config` if snapd does
  not connect it automatically.

The binary is frozen with PyInstaller on Ubuntu 24.04, so its glibc
floor is glibc 2.39. DEB and RPM declare their Qt graphics libraries as package
dependencies, including EGL and OpenGL. Their Wayland libraries are recommended
because the CI smoke tests use X11 and offscreen Qt. The strict Snap stages its Qt
graphics and Wayland support libraries; its `opengl` plug grants GPU access but does
not supply `libEGL.so.1` or `libGL.so.1` by itself. The Flatpak uses the pinned
Freedesktop 26.08 runtime, which supplies those libraries. Fedora 42 is the RPM
install smoke-test container. Release notes identify Windows 10/11 x64, Ubuntu
24.04 amd64/arm64, the glibc floor for DEB/RPM/AppImage, and Fedora 42 RPM smoke
coverage. Flatpak and Snap are sideloaded without a configured remote or store channel.

The AppImage uses graphics and display libraries from the host rather than bundling
copies that could conflict with the host's display server or GPU driver. Install the
following packages if they are absent (a normal desktop may already have them):

| Distribution | AppImage host packages |
| --- | --- |
| Ubuntu 24.04 and Debian 13 | `libxcb1 libgl1 libegl1` |
| Fedora 42 | `libxcb libglvnd-glx libglvnd-egl` |
| Arch Linux | `libxcb libglvnd` |
| openSUSE Tumbleweed | `libxcb1 libglvnd` |

A graphical desktop session is also needed for normal use. `QT_QPA_PLATFORM=offscreen`
is for CI smoke tests. Wayland support may need its Wayland cursor and EGL libraries
from the distribution; those libraries are common on Wayland desktops. The AppImage
library inventory was checked on x86_64 clean containers for these distributions;
the CI package workflow remains the acceptance check for the release-built binary
on both architectures.

## Access and validation limits

DEB, RPM, and AppImage run outside a filesystem sandbox. The Flatpak requests
network access for GitHub update checks and read-only access to the user's home
for config discovery. It also grants read-only access to the host native OBS config,
OBS Flatpak config, and Dropbox metadata. It grants read/write access to `~/Dropbox`
so the default `~/Dropbox/Jasmeralia and Rin/obs logs` destination works. A Dropbox
folder relocated outside `~/Dropbox`, or another custom destination, needs an
additional sandbox grant and is not yet validated for Flatpak. CI tests collection
from both native and OBS Flatpak fixture paths. The strict
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
