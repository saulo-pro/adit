#!/bin/sh
# Installs adit on a Mac. https://adit.saulo.pro
#
#   curl -fsSL https://adit.saulo.pro/install.sh | sh
#
# It downloads adit's latest release from GitHub (github.com/saulo-pro/adit/releases), checks it
# against the release's SHA256SUMS, puts adit, aditd and adit-tray in /usr/local/bin, and runs
# `sudo adit install`, which starts aditd now and at every boot and the menu bar icon at every login.
# sudo asks for your password once. Running it again upgrades adit. It downloads nothing else and
# sends nothing anywhere.
#
#   ADIT_VERSION=0.1.1   installs that version instead of the latest
#   ADIT_BIN=/opt/adit   puts the three binaries there instead of /usr/local/bin
#
# To remove adit: sudo adit uninstall, then delete adit, aditd and adit-tray from /usr/local/bin.
set -eu

repo=https://github.com/saulo-pro/adit
bin=${ADIT_BIN:-/usr/local/bin}

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'adit install: %s\n' "$*" >&2
  exit 1
}

# Everything runs from here, at the end of the file, so a download cut short runs nothing.
main() {
  [ "$(uname -s)" = Darwin ] || fail "adit runs on macOS only."
  release=$(sw_vers -productVersion)
  [ "${release%%.*}" -ge 13 ] || fail "adit needs macOS 13 or later; this Mac runs $release."
  if command -v brew > /dev/null 2>&1 && [ -d "$(brew --prefix)/Cellar/adit" ]; then
    fail "Homebrew installed adit here. Upgrade it with: brew upgrade adit. Or remove it first with: sudo adit uninstall; brew uninstall adit"
  fi

  # ADIT_DOWNLOAD, a folder holding a release, is for adit's own tests.
  if [ -n "${ADIT_DOWNLOAD:-}" ]; then
    url=$ADIT_DOWNLOAD
  elif [ -n "${ADIT_VERSION:-}" ]; then
    url="$repo/releases/download/v${ADIT_VERSION#v}"
  else
    url="$repo/releases/latest/download"
  fi

  tmp=$(mktemp -d -t adit-install)
  trap 'rm -rf "$tmp"' EXIT
  say "Downloading adit from $url"
  for file in adit-macos.tar.gz SHA256SUMS; do
    curl -fsSL --proto '=https,file' -o "$tmp/$file" "$url/$file" || fail "could not download $url/$file"
  done
  (cd "$tmp" && grep ' adit-macos.tar.gz$' SHA256SUMS > expected && shasum -a 256 -c expected > /dev/null 2>&1) ||
    fail "the download does not match the release's SHA256SUMS, so nothing was installed."
  mkdir "$tmp/adit"
  tar -xzf "$tmp/adit-macos.tar.gz" -C "$tmp/adit"
  version=$("$tmp/adit/adit" version | head -n 1)

  say "Installing $version in $bin. sudo asks for your password."
  sudo mkdir -p "$bin"
  sudo install -m 755 -o root -g wheel "$tmp/adit/adit" "$tmp/adit/aditd" "$tmp/adit/adit-tray" "$bin/"
  sudo "$bin/adit" install

  say ""
  say "$version is installed in $bin."
  case ":$PATH:" in
    *":$bin:"*) ;;
    *) say "$bin is not on your PATH: add it, or run $bin/adit." ;;
  esac
  say "Add a tunnel:   sudo adit import ~/Downloads/office.conf"
  say "Bring it up:    adit up office"
  say "Upgrade:        run this installer again"
  say "Remove:         sudo adit uninstall && sudo rm $bin/adit $bin/aditd $bin/adit-tray"
}

main "$@"
