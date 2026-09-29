#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 OUTPUT_DIR" >&2
    exit 2
fi

output_dir=$(mkdir -p "$1" && cd "$1" && pwd)
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
version=${APP_VERSION:-0.0.0}
version_bare=${version#v}
arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$arch" in
    x86_64|amd64) arch=amd64; flatpak_arch=x86_64; rpm_arch=x86_64 ;;
    aarch64|arm64) arch=arm64; flatpak_arch=aarch64; rpm_arch=aarch64 ;;
    *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
app=$work/app
mkdir -p "$app/usr/bin" "$app/usr/share/applications" \
    "$app/usr/share/icons/hicolor/256x256/apps" "$app/usr/share/doc/tempesttrace"

python -m PyInstaller "$repo_root/build/TempestTrace.spec" \
    --noconfirm --clean --distpath "$work/dist" --workpath "$work/pyinstaller"
install -m 0755 "$work/dist/TempestTrace" "$app/usr/bin/tempesttrace"
install -m 0644 "$repo_root/packaging/linux/tempesttrace.desktop" \
    "$app/usr/share/applications/io.github.jasmeralia.TempestTrace.desktop"
install -m 0644 "$repo_root/resources/icons/tempesttrace.png" \
    "$app/usr/share/icons/hicolor/256x256/apps/io.github.jasmeralia.TempestTrace.png"
install -m 0644 "$repo_root/LICENSE" "$app/usr/share/doc/tempesttrace/copyright"

build_deb() {
    local root=$work/deb
    mkdir -p "$root/DEBIAN"
    cp -a "$app/." "$root/"
    cat > "$root/DEBIAN/control" <<EOF
Package: tempesttrace
Version: ${version#v}
Section: utils
Priority: optional
Architecture: $arch
Maintainer: TempestTrace contributors
Depends: libc6 (>= 2.35), libx11-6, libxcb1, libxkbcommon-x11-0, libxcb-cursor0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-render-util0, libxcb-xinerama0, libxcb-xkb1
Description: Safe OBS diagnostic backup utility
 Creates a redacted diagnostic archive without modifying OBS configuration.
EOF
    dpkg-deb --root-owner-group --build "$root" \
        "$output_dir/TempestTrace-v${version_bare}-linux-${arch}.deb"
}

build_rpm() {
    local top=$work/rpmbuild
    mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    mkdir -p "$top/SOURCES/tempesttrace-rootfs"
    cp -a "$app/." "$top/SOURCES/tempesttrace-rootfs/"
    cat > "$top/SPECS/tempesttrace.spec" <<EOF
Name:           tempesttrace
Version:        ${version#v}
Release:        1
Summary:        Safe OBS diagnostic backup utility
License:        GPL-3.0-or-later
BuildArch:      $rpm_arch
Requires:       glibc >= 2.35
Requires:       libX11
Requires:       libxcb
Requires:       libxkbcommon-x11
Requires:       xcb-util-wm
Requires:       xcb-util-image
Requires:       xcb-util-keysyms
Requires:       xcb-util-renderutil
%description
Creates a redacted diagnostic archive without modifying OBS configuration.
%install
mkdir -p %{buildroot}
cp -a "$top/SOURCES/tempesttrace-rootfs/." %{buildroot}/
%files
/usr/bin/tempesttrace
/usr/share/applications/io.github.jasmeralia.TempestTrace.desktop
/usr/share/icons/hicolor/256x256/apps/io.github.jasmeralia.TempestTrace.png
/usr/share/doc/tempesttrace/copyright
EOF
    rpmbuild --define "_topdir $top" -bb "$top/SPECS/tempesttrace.spec"
    cp "$top/RPMS/$rpm_arch/"*.rpm \
        "$output_dir/TempestTrace-v${version_bare}-linux-${arch}.rpm"
}

build_appimage() {
    local dir=$work/AppDir
    mkdir -p "$dir/usr/bin" "$dir/usr/share/applications" \
        "$dir/usr/share/icons/hicolor/256x256/apps"
    cp -a "$app/usr/bin/tempesttrace" "$dir/usr/bin/"
    sed 's/^Exec=tempesttrace$/Exec=AppRun/' \
        "$app/usr/share/applications/io.github.jasmeralia.TempestTrace.desktop" \
        > "$dir/usr/share/applications/io.github.jasmeralia.TempestTrace.desktop"
    cp -a "$app/usr/share/icons/hicolor/256x256/apps/"* \
        "$dir/usr/share/icons/hicolor/256x256/apps/"
    ln -s usr/share/applications/io.github.jasmeralia.TempestTrace.desktop "$dir/tempesttrace.desktop"
    ln -s usr/share/icons/hicolor/256x256/apps/io.github.jasmeralia.TempestTrace.png \
        "$dir/io.github.jasmeralia.TempestTrace.png"
    cat > "$dir/AppRun" <<'EOF'
#!/bin/sh
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$HERE/usr/bin/tempesttrace" "$@"
EOF
    chmod 0755 "$dir/AppRun"
    local appimage_arch=x86_64
    [[ "$arch" == arm64 ]] && appimage_arch=aarch64
    APPIMAGE_EXTRACT_AND_RUN=1 VERSION="$version" ARCH="$appimage_arch" appimagetool "$dir" \
        "$output_dir/TempestTrace-v${version_bare}-linux-${arch}.AppImage"
    chmod 0755 "$output_dir/TempestTrace-v${version_bare}-linux-${arch}.AppImage"
}

build_flatpak() {
    command -v flatpak >/dev/null
    flatpak remote-add --if-not-exists --user flathub https://dl.flathub.org/repo/flathub.flatpakrepo
    flatpak install --user --noninteractive --assumeyes flathub \
        "org.freedesktop.Platform/$flatpak_arch/26.08" \
        "org.freedesktop.Sdk/$flatpak_arch/26.08"
    local dir=$work/flatpak-build
    local repo=$work/flatpak-repo
    flatpak build-init --arch="$flatpak_arch" "$dir" \
        io.github.jasmeralia.TempestTrace org.freedesktop.Platform 26.08 \
        org.freedesktop.Sdk 26.08
    install -D -m 0755 "$app/usr/bin/tempesttrace" "$dir/files/bin/tempesttrace"
    install -D -m 0644 "$app/usr/share/applications/io.github.jasmeralia.TempestTrace.desktop" \
        "$dir/files/share/applications/io.github.jasmeralia.TempestTrace.desktop"
    install -D -m 0644 "$app/usr/share/icons/hicolor/256x256/apps/io.github.jasmeralia.TempestTrace.png" \
        "$dir/files/share/icons/hicolor/256x256/apps/io.github.jasmeralia.TempestTrace.png"
    # Keep OBS/config files read-only and limit writes to the default Dropbox destination.
    flatpak build-finish --command=tempesttrace --socket=wayland --socket=fallback-x11 \
        --share=ipc --share=network --device=dri --filesystem=home:ro \
        --filesystem=xdg-config/obs-studio:ro \
        --filesystem='~/.var/app/com.obsproject.Studio/config/obs-studio:ro' \
        --filesystem='~/.dropbox:ro' --filesystem='~/Dropbox:rw' "$dir"
    flatpak build-export --arch="$flatpak_arch" "$repo" "$dir" stable
    flatpak build-bundle --arch="$flatpak_arch" "$repo" \
        "$output_dir/TempestTrace-v${version_bare}-linux-${arch}.flatpak" \
        io.github.jasmeralia.TempestTrace stable
}

build_snap() {
    local dir=$work/snap
    mkdir -p "$dir/app"
    cp -a "$app/." "$dir/app/"
    cat > "$dir/snapcraft.yaml" <<EOF
name: tempesttrace
base: core24
version: '${version#v}'
summary: Safe OBS diagnostic backup utility
description: Creates a redacted diagnostic archive without modifying OBS configuration.
grade: devel
confinement: strict
platforms:
  $arch:
    build-on: [$arch]
    build-for: [$arch]
apps:
  tempesttrace:
    command: usr/bin/tempesttrace
    desktop: usr/share/applications/io.github.jasmeralia.TempestTrace.desktop
    plugs: [desktop, desktop-legacy, wayland, x11, opengl, home, network, obs-config]
plugs:
  obs-config:
    interface: personal-files
    read:
      - \$HOME/.config/obs-studio
      - \$HOME/.var/app/com.obsproject.Studio/config/obs-studio
      - \$HOME/.dropbox/info.json
parts:
  app:
    plugin: dump
    source: app
    stage-packages:
      - libx11-6
      - libxcb1
      - libxkbcommon-x11-0
      - libxcb-cursor0
      - libxcb-icccm4
      - libxcb-image0
      - libxcb-keysyms1
      - libxcb-randr0
      - libxcb-render-util0
      - libxcb-xinerama0
      - libxcb-xkb1
EOF
    (cd "$dir" && snapcraft pack --destructive-mode --output \
        "$output_dir/TempestTrace-v${version_bare}-linux-${arch}.snap")
}

build_deb
build_rpm
build_appimage
build_flatpak
build_snap

for package in "$output_dir"/*; do
    case "$package" in
        *.deb) dpkg-deb --info "$package" >/dev/null ;;
        *.rpm) rpm -qp --info "$package" >/dev/null ;;
        *.AppImage) test -x "$package" ;;
        *.flatpak) flatpak build-bundle --help >/dev/null ;;
        *.snap) unsquashfs -s "$package" >/dev/null ;;
    esac
done
