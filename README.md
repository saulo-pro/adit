# adit

A client for WireGuard® tunnels on macOS that keeps several of them up at once, with a menu bar
icon and a command line that do the same things.

> **Status:** 0.1.2. Full tunnels (`AllowedIPs = 0.0.0.0/0`) come in the
> next version: adit refuses them for now, saying so.

## What it is for

The official WireGuard app for macOS keeps one tunnel up at a time and has no command line;
`wg-quick` runs several, but asks for the administrator password on every use and does not come
back after a reboot. adit covers both:

- **Several tunnels at the same time**, each routing only its own networks. A tunnel whose networks
  or DNS domain overlap a tunnel that is up, adit's or another program's, is refused before it
  connects, with the reason.
- **A menu bar icon and a command line** over one privileged service, `aditd`: a tunnel switched in
  one flips in the other at once. Every command answers in plain words, or in JSON with `--json`,
  for scripts and AI agents, with meaningful exit codes.
- **Back after a reboot, before anyone logs in**, for the tunnels you choose, and through network
  changes.
- **No password for daily use.** The administrator password is asked once, at install; switching
  tunnels needs none.
- **DNS per tunnel.** `DNS = 10.99.1.1, corp.example` sends names under `corp.example` to
  `10.99.1.1` and leaves every other name alone.
- **Honest status**: the last handshake and the bytes each way, not just "connected".
- **Plain WireGuard `.conf` files** in and out, the same ones `wg-quick` and the official apps read.
- **Other software's tunnels shown read-only**: the WireGuard app's and `wg-quick`'s, with
  `wg-quick`'s handshakes and counters. adit never changes them.

## Install

With Homebrew:

```sh
brew install saulo-pro/tap/adit
sudo adit install
```

Or with one line, without Homebrew:

```sh
curl -fsSL https://adit.saulo.pro/install.sh | sh
```

It downloads the latest release from GitHub, checks it against the release's `SHA256SUMS`, puts
`adit`, `aditd` and `adit-tray` in `/usr/local/bin` and runs `sudo adit install`; sudo asks for your
password once. Read it first if you like: `curl -fsSL https://adit.saulo.pro/install.sh | less`.
Run it again to upgrade. It stops on a Mac where Homebrew installed adit, since the two copies would
replace each other. To remove what it installed: `sudo adit uninstall`, then delete the three
binaries from `/usr/local/bin`.

`sudo adit install` copies `aditd` to `/Library/PrivilegedHelperTools/pro.saulo.adit`, where only
root can change it, and starts it now and at every boot. It also sets the menu bar icon to start at
every login (from its own root-owned copy, `/Library/PrivilegedHelperTools/pro.saulo.adit.tray`), and
creates the `adit` group with you in it. Run it again after every `brew upgrade adit`:
`adit version` says when `aditd` is older than `adit`. To remove adit, run `sudo adit uninstall`
before `brew uninstall adit`, or `aditd` keeps running.

## Use

```sh
sudo adit import work.conf     # add a tunnel; PostUp and other hook lines are kept but never run
adit up work                   # no password
adit status                    # every tunnel, adit's and other software's
adit status work --json
adit autostart work on         # bring it up at boot
adit down work
sudo adit export work --output work.conf   # a new file, readable only by you
sudo adit remove work
sudo adit allow caroline         # let another account switch tunnels
sudo adit uninstall            # removes aditd, the group and every tunnel with its keys
```

Exit codes: 0 done; 1 failed, with the reason; 2 wrong usage; 3 `aditd` not reachable; 4 not
allowed; 5 no such tunnel; 6 refused because of a conflict.

## Security

- `aditd` runs as root and only does tunnel work. It answers on a Unix socket that belongs to
  `root:adit` with mode `0660`, and it also asks the kernel who each caller is. Members of the
  `adit` group may list, switch and watch tunnels. Adding, removing and exporting tunnels needs
  `sudo`, so a program running as you cannot slip in a tunnel or read the keys through adit. One
  limit: with Homebrew, the `adit` that `sudo adit` runs lives in a folder your account can write,
  so a program running as you could replace it before you next type `sudo`. `sudo adit install`
  says so, and installs only root-owned copies of what it checked.
- `aditd` never runs a command or opens a path it was sent. Hook lines (`PreUp`, `PostUp`,
  `PreDown`, `PostDown`) are kept, so an export gives the file back unchanged, and never run.
- Private keys stay in `/var/db/adit`, which only root can read, and never appear in output, logs
  or the menu. The store is left out of Time Machine. Export writes a new file only, readable only
  by you, and never through a link. `aditd`'s log is readable by root alone.
- No telemetry, and no network traffic but the tunnels' own.

## How it works

`aditd` runs each tunnel with [wireguard-go](https://git.zx2c4.com/wireguard-go) on its own `utun`
interface, and sets addresses and routes the way `wg-quick` does. A LaunchDaemon starts it at boot.
The command line and the menu bar icon are clients of the same socket. The
[brief](docs/brief.md) says what adit must do, and the [decisions](docs/decisions.md) say why it is
built this way.

## Developing

Go, managed with [mise](https://mise.jdx.dev): `mise install`, then `go test ./...`. Tests that
need root and real tunnels run against two WireGuard servers that run in user space
(`test/servers/up`, built from `test/wgserver`), so they need no Docker:

- `test/integration`: the tunnel manager through its socket.
- `test/e2e`: `aditd` as root and `adit` as you, including DNS, conflicts and other software's
  tunnels.
- `test/install`: installs adit on the Mac for real, checks it, and uninstalls it.
- `test/installer`: installs adit with `docs/install.sh` from a release built on the spot, checks
  that it refuses a bad checksum and a Mac where Homebrew installed adit, and removes it.

Continuous integration runs on GitHub-hosted runners only, and runs these four too: GitHub's
macOS machines give passwordless `sudo`. Locally they ask for your password.

A tag `v<version>` makes a release: `.github/workflows/release.yml` runs `scripts/release-archive`,
which builds `adit`, `aditd` and `adit-tray` as universal binaries (Apple silicon and Intel, macOS 13
and later), and attaches `adit-macos.tar.gz` and `SHA256SUMS` to the GitHub release, where
`install.sh` downloads them. Its notes are that version's section of `CHANGELOG.md`, and a tag without
one fails: before tagging, move what `Unreleased` gathered into a `## [X.Y.Z] - YYYY-MM-DD` section
and add its comparison link at the bottom.

`test/vm` runs the first version's definition of done in a macOS virtual machine
([tart](https://tart.run), which mise installs), where nothing asks for a password: install with
`install.sh`, two adit tunnels beside one of wg-quick's, PostUp kept but not run, a reboot to the
login window with the tunnels back before anyone logs in, and uninstall. `test/vm --release` installs
with the published one-line installer instead of a release built on the spot. The first run downloads
a 25 GB macOS image.
What it cannot do, clicking the menu bar icon and a tunnel of the WireGuard app, `test/done` checks
on a real Mac.

## License

[MIT](LICENSE).

---

"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. adit is an
independent project, not affiliated with or endorsed by the WireGuard project.
