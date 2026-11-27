# Helpers the test scripts share; source it.

step() { printf '\n== %s\n' "$*"; }

# expect EXIT COMMAND...: runs the command and stops unless it exits with EXIT.
expect() {
  local want=$1
  shift
  set +e
  "$@"
  local got=$?
  set -e
  if [[ $got != "$want" ]]; then
    echo "FAIL: $* exited $got, want $want" >&2
    exit 1
  fi
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# adit_interfaces ADIT: the interfaces of adit's own tunnels that are up, not other software's. It
# reads the JSON with JavaScript for Automation, which every Mac has; python3 needs Apple's developer
# tools.
adit_interfaces() {
  osascript -l JavaScript -e 'function run(a) { return JSON.parse(a[0]).tunnels.map(t => t.interface).filter(i => i).join(" ") }' "$("$1" list --json)"
}

# local_installer RELEASE OUT writes to OUT a copy of docs/install.sh (path given as $3, default
# docs/install.sh) that downloads from the folder RELEASE (holding adit-macos.tar.gz and SHA256SUMS)
# instead of GitHub: the published script has no switch for that, so tests rewrite where it looks.
local_installer() {
  local release=$1 out=$2 script=${3:-docs/install.sh} site
  site=$(mktemp -d -t adit-site)
  mkdir -p "$site/releases/latest/download"
  cp "$release"/adit-macos.tar.gz "$release"/SHA256SUMS "$site/releases/latest/download/"
  sed -e "s|^repo=.*|repo=file://$site|" -e "s|--proto '=https' --proto-redir '=https' --tlsv1.2|--proto '=file'|" "$script" > "$out"
  if ! grep -q "^repo=file://" "$out" || ! grep -q -- "--proto '=file'" "$out"; then
    fail "could not point the installer at $release"
  fi
}
