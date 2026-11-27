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
# What root installs, root checks: the archive is copied into a folder only root can enter, its
# checksum is verified there, and the binaries are installed from there.
#
#   ADIT_VERSION=0.1.3   installs that version instead of the latest
#   ADIT_BIN=/opt/adit   puts the three binaries there instead of /usr/local/bin
#
# To remove adit: sudo adit uninstall, then delete adit, aditd and adit-tray from /usr/local/bin.
set -eu

repo=https://github.com/saulo-pro/adit
bin=${ADIT_BIN:-/usr/local/bin}
sudo=/usr/bin/sudo

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'adit install: %s\n' "$*" >&2
  exit 1
}

# Everything runs from here, at the end of the file, so a download cut short runs nothing.
main() {
  [ "$(/usr/bin/uname -s)" = Darwin ] || fail "adit runs on macOS only."
  release=$(/usr/bin/sw_vers -productVersion)
  [ "${release%%.*}" -ge 13 ] || fail "adit needs macOS 13 or later; this Mac runs $release."
  if command -v brew > /dev/null 2>&1 && [ -d "$(brew --prefix)/Cellar/adit" ]; then
    fail "Homebrew installed adit here. Upgrade it with: brew upgrade adit. Or remove it first with: sudo adit uninstall; brew uninstall adit"
  fi
  case $bin in
    /*) ;;
    *) fail "ADIT_BIN must be an absolute path." ;;
  esac

  if [ -n "${ADIT_VERSION:-}" ]; then
    version=${ADIT_VERSION#v}
    case $version in
      '' | *[!0-9A-Za-z.+-]*) fail "ADIT_VERSION must be a version, such as 0.1.3." ;;
    esac
    url="$repo/releases/download/v$version"
  else
    url="$repo/releases/latest/download"
  fi

  tmp=$(/usr/bin/mktemp -d -t adit-install)
  root=""
  trap '/bin/rm -rf "$tmp"; [ -z "$root" ] || $sudo /bin/rm -rf "$root"' EXIT
  say "Downloading adit from $url"
  for file in adit-macos.tar.gz SHA256SUMS; do
    /usr/bin/curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 -o "$tmp/$file" "$url/$file" ||
      fail "could not download $url/$file"
  done
  expected=$(/usr/bin/awk '$2 == "adit-macos.tar.gz" { print $1 }' "$tmp/SHA256SUMS")
  case $expected in
    '' | *[!0-9a-f]*) fail "the release's SHA256SUMS has no checksum for adit-macos.tar.gz, so nothing was installed." ;;
  esac
  [ ${#expected} -eq 64 ] || fail "the release's SHA256SUMS has no checksum for adit-macos.tar.gz, so nothing was installed."

  say "Installing adit in $bin. sudo asks for your password."
  root=$($sudo /usr/bin/mktemp -d /private/var/tmp/adit-install.XXXXXX)
  $sudo /bin/chmod 700 "$root"
  $sudo /bin/cp "$tmp/adit-macos.tar.gz" "$root/adit-macos.tar.gz"
  actual=$($sudo /usr/bin/shasum -a 256 "$root/adit-macos.tar.gz" | /usr/bin/awk '{ print $1 }')
  [ "$actual" = "$expected" ] || fail "the download does not match the release's SHA256SUMS, so nothing was installed."
  $sudo /usr/bin/tar -xzf "$root/adit-macos.tar.gz" -C "$root" adit aditd adit-tray
  version=$($sudo "$root/adit" version | /usr/bin/head -n 1)
  $sudo /bin/mkdir -p "$bin"
  $sudo /usr/bin/install -m 755 -o root -g wheel "$root/adit" "$root/aditd" "$root/adit-tray" "$bin/"
  $sudo "$bin/adit" install

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
