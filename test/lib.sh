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
