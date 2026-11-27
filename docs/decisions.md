# Decisions

The choices the [brief](brief.md) left open, with the reason for each. Newest last; a decision that
changes gets a new entry rather than an edit, so the reasoning stays readable.

## 2026-11-15 — Build it rather than join an existing client

Five clients that run several WireGuard tunnels at once appeared in 2026 — SimpleVPN, WGMenu,
WireTunnels, wg-client, multiguard — and Defguard's client has existed since 2023. None meets the
brief: all but Defguard are macOS-only; none brings tunnels up at boot before login; the closest
(SimpleVPN) asks for `sudo` again whenever its supervisor restarts and converts `.conf` files into a
format of its own; WGMenu runs `wg-quick`, so imported hook lines still run as root; Defguard's
client is built around its own server and is partly under a commercial license, and its command line
is not available on macOS. WGMenu's README is worth rereading for its route-priority and
root-owned-tools notes.

## 2026-11-15 — Name: adit

An adit is a mine's horizontal entrance tunnel. The command is `adit`. "WireGuard" stays out of the
name: it is a registered trademark, and its policy does not allow names that suggest affiliation.
`warren` was the other strong candidate but is already a command-line tool for running coding
agents — the audience adit's command line is meant for.

## 2026-11-15 — Go for the service, the command line and the tray

Mostly for technical reasons specific to WireGuard:

- **macOS** — the service embeds `wireguard-go` (MIT), the WireGuard author's own userspace
  implementation, as a library. The official macOS app and `wg-quick` run the same code.
- **Windows** — `wireguard-windows` (MIT), which the brief says to study first, is Go: its tunnel
  service, route, DNS and firewall code can be imported or reused, not ported.
- **Linux** — kernel WireGuard over netlink with `wgctrl-go` (MIT). A tie with Rust.
- **Builds** — the service and the command line cross-compile to static binaries for all three
  systems from one machine; only the tray needs cgo on macOS.
- **Tray** — `fyne.io/systray` (Apache-2.0) on all three systems. Rust's `tray-icon` is equivalent;
  neither matches a native SwiftUI menu bar app, which stays possible later because the tray is only
  a client of the service.

Also, less technically: the author already maintains a Go daemon and command line of the same shape.
Rust would bring no garbage collector and a stricter compiler, but the brief needs neither, and the
author is new to it.

Go 1.27.4, managed with mise (`mise.toml`). Module `github.com/saulo-pro/adit`.

## 2026-11-15 — macOS first

It is where the one-tunnel limit hurts today. Linux follows (kernel WireGuard; the work is the
service and the tray), then Windows.

## 2026-11-15 — Distribution: a Homebrew tap built from source, first

A formula in our own tap builds from source, so Gatekeeper does not quarantine it and no Apple
Developer membership is needed. Homebrew's main cask repository stopped accepting unsigned apps on
2026-09-01, so a signed and notarized installer waits until it is worth the yearly fee. Linux
packages and a signed Windows installer come with those systems.

## 2026-11-15 — Tunnels adit did not start are shown read-only

Tunnels brought up by the official app or `wg-quick` appear in the list, marked as not adit's, and
are never changed. Adopting them is not in the first version.

## 2026-11-15 — Repository: github.com/saulo-pro/adit, public

Continuous integration runs on GitHub-hosted runners only: a public repository lets pull requests
from forks run code on the runner, so it must never reach a self-hosted machine.

## 2026-11-16 — License: MIT

The license of the WireGuard code adit builds on — `wireguard-go`, `wgctrl-go` and
`wireguard-windows` — so code can move between those projects and adit without a license question,
and anyone may package or embed adit. `fyne.io/systray` (Apache-2.0) is compatible with it. On
Windows, `wireguard-nt` is GPL-2 as source, but its prebuilt binaries come under a separate license
that allows shipping them with other software; using those keeps adit MIT.

## 2026-11-23 — Who may talk to aditd: members of the `adit` group

`aditd` runs as root because creating interfaces, routes and resolver files needs it; the command
line and the tray never do, they ask `aditd` over a Unix socket. Its socket file belongs to
`root:adit` with mode `0660`, so the kernel refuses a connection from anyone outside the group
before `aditd` reads a byte, and `aditd` checks again: it asks the kernel for the caller's user
(`LOCAL_PEERCRED`) and looks up that user's groups. `sudo adit install` creates the group and adds
the installing user; `sudo adit allow USER` adds another; uninstall deletes the group.

A group rather than a list of names in a file of adit's own: it is the operating system's mechanism
(Docker's socket works the same way), the kernel enforces it even if `aditd`'s own check had a bug,
membership shows in System Settings and `dseditgroup`, and Linux and Windows have the same thing.
The cost: a newly added member may need a new login session before macOS lets them in.

## 2026-11-23 — Daily commands for the group, the rest for root

Members of `adit` may `list`, `status`, `up`, `down`, set `autostart` and `watch`, with no password.
`import`, `remove` and `export` need root (`sudo adit …`), as do `allow`, `install` and `uninstall`.

Every program running as a member passes the group check, so without the split any of them — a
malicious package, a script, an agent — could import a tunnel that routes chosen destinations
through someone else's server, or export the private keys. Daily use stays password-free, as the
brief asks, and adding a tunnel costs a password, as macOS asks before it adds a VPN configuration.
The cost: an agent cannot import a tunnel without the person typing their password.

## 2026-11-24 — Installed as pro.saulo.adit, the way other helpers are

The LaunchDaemon's label is `pro.saulo.adit`, from the author's domain. The binary root runs is
named after it, `/Library/PrivilegedHelperTools/pro.saulo.adit`, as Docker's and Zoom's helpers are
there. The menu bar icon's LaunchAgent is `pro.saulo.adit.tray`. The tunnels live in
`/var/db/adit`, and the log in `/var/log/aditd.log`, rotated by newsyslog.

The icon runs as the person, so its LaunchAgent may start it from Homebrew's `bin`, whose link
survives upgrades. `aditd` runs as root, so it is copied to a place only root can change.

## 2026-11-24 — Other software's tunnels: the WireGuard app's and wg-quick's

adit shows them beside its own, read-only. The app's come from `scutil`, with name, state and
interface: the app shares no handshakes or byte counts. wg-quick's come from its control sockets in
`/var/run/wireguard`, with handshakes and counters, so their state means what adit's does. Other
VPNs are not listed, but their routes still count when adit checks a tunnel for overlaps.

## 2026-11-24 — The Homebrew tap is generated by Homebrew

`saulo-pro/homebrew-tap` started from `brew tap-new`, with its test-bot, pr-pull and autobump
workflows. The formula builds adit from the release's source and needs no bottles: building takes
twenty seconds, and nothing needs signing.

## 2026-11-25 — Root tests run in CI, against WireGuard servers in user space

The tests that need root (real tunnels, routes, resolver files, the LaunchDaemon) run on every push,
on GitHub's macOS machines, where `sudo` needs no password. Run on a laptop, they stopped at a
password prompt until someone came back to type it: once for 43 minutes.

The WireGuard servers they talk to are `test/wgserver`, a small program in its own module whose IP
stack runs inside the process (wireguard-go's netstack, which is gVisor's). It answers ping and DNS
only through the tunnel, needs neither root nor Docker, and works on CI machines, which have no
Docker. It replaced two Docker containers.

## 2026-11-26 — The definition of done runs in a virtual machine

`test/vm` runs it in a macOS virtual machine made with tart from Cirrus Labs' image, whose `sudo`
asks for no password and which reboots to a real login window. Run on a laptop, `test/done` stopped
at password prompts for hours while nobody was there, and with FileVault on a Mac logs its owner in
as soon as the disk is unlocked, so "before login" could only be shown by logging out.

Only what needs a person stays on a real Mac: clicking the menu bar icon, and a tunnel of the
WireGuard app, which comes from the App Store. In the virtual machine, a tunnel of wg-quick's stands
for other software's.

## 2026-11-26 — A one-line installer beside Homebrew

`curl -fsSL https://adit.saulo.pro/install.sh | sh` installs adit without Homebrew. Every tag
`v<version>` now makes a GitHub release with `adit-macos.tar.gz`, holding `adit`, `aditd` and
`adit-tray` as universal binaries for macOS 13 and later, and its `SHA256SUMS`. The script downloads
the latest release, checks the checksum, puts the binaries in `/usr/local/bin` as root's, and runs
`sudo adit install`.

It needs no Apple Developer ID: files `curl` downloads carry no quarantine flag, so Gatekeeper does
not stop unsigned binaries, and Apple silicon needs only the ad-hoc signature Go's linker adds.

The script is short enough to read before running, does all its work from a function called on its
last line, so a download cut short runs nothing, and refuses a Mac where Homebrew installed adit:
both would put their own `aditd` in the same place. It has no upgrade check, as adit has none;
running it again upgrades. The checksum shows the download is whole, not who made it: a release
signed or attested in a way the script can check is left for later.

## 2026-11-26 — Release notes come from CHANGELOG.md

`CHANGELOG.md`, in the Keep a Changelog style, says what each version changed for the people who use
adit: an `Unreleased` section on top, then one section per version with its date, grouped into
Added, Changed, Fixed and Removed. A release's notes are its version's section, which
`scripts/release-notes` prints for the release workflow; a tag without one fails before anything is
built, and CI checks every `v*` tag on each push. GitHub's generated notes listed commits, not what
changed. Nuncio keeps its changelog the same way.

## 2026-11-26 — The history starts over at 0.1.2

The repository was replaced by a new one holding a single commit, to drop personal details that had
found their way into test fixtures. 0.1.0 and 0.1.1 are no longer on GitHub. Their source stays in
the Go module proxy, which keeps every version it has seen, so those tag names are never reused and
the new repository's first release is 0.1.2. Fixtures and examples use fictional names and made-up
addresses.

## 2026-11-27 — Security review and what it changed

A review of the whole repository, its dependencies and its release path (17 reviewers, every finding
traced, challenged and scored with CVSS v3.1) found 70 issues: 2 High, 10 Medium, 40 Low and 18
hardening notes, none critical and none giving root from outside the adit group. 0.1.3 fixes the
High and Medium ones and most of the rest. Decisions it led to:

- Releases are built without the shared Go cache, with `go mod verify`, in a job that cannot publish;
  a second job publishes from the built artifact in the `release` environment. Actions are pinned to
  commits. Each archive has a build provenance attestation. Releases are immutable: drafted, filled,
  then published.
- `main` takes no force push or deletion and needs signed commits; `v*` tags cannot be moved or
  deleted (repository rulesets, the tap too).
- The tray's LaunchAgent runs a root-owned copy, so no account's file runs in another's session.
  With Homebrew, `adit` itself still lives in a folder its owner's programs can change: inside a
  command run through `sudo` that cannot be closed, so `sudo adit install` says so and installs only
  copies of what it checked.
- Limits a configuration file may not exceed (DNS servers and domains, peers, AllowedIPs,
  addresses, size), and address ranges and domains it may not take, are enforced at import.
- The landing page keeps its analytics, under a Content-Security-Policy that allows only that script
  and its endpoint.
- `v0.1.2` stays: it was published, the Go module proxy keeps its source anyway, and the rule is
  that a published tag is never deleted. 0.1.3, from the single clean commit's line, is the Latest.

Left for later, by choice: an Apple Developer ID with notarisation (the attestation covers
provenance meanwhile), signing SHA256SUMS with a key install.sh pins, and a packet filter per tunnel.


## 2026-11-27 — Full tunnels: routes, servers kept outside, default DNS

A full tunnel (`AllowedIPs = 0.0.0.0/0`, or pieces that add up to it) comes up beside split tunnels.
How it works was settled by comparing sixteen other clients and by three experiments in a virtual
machine, before building:

- **Routes.** `0.0.0.0/0` goes in as `0.0.0.0/1` and `128.0.0.0/1` (`::/0` as `::/1` and
  `8000::/1`), as wg-quick does. They win over the default route without replacing it, so taking the
  tunnel down, or aditd dying, leaves the Mac's own route as it was. Split tunnels' networks and the
  local network are more specific and keep winning.
- **Every tunnel's server stays outside it.** Without a route of its own, the full tunnel captures
  the packets to its own server and nothing gets through. aditd adds a host route through the Mac's
  real gateway for the server of every adit tunnel that is up, before the full tunnel's routes go in
  (none for a server on the local network; one to nowhere when there is no gateway, so packets never
  go round inside the tunnel). A network change removes host routes through the old gateway, so they
  are checked and put back after every change and every minute. Routes adit adds outside a tunnel's
  own interface are recorded in `/var/run/adit/routes.json` and removed by aditd at its next start
  if it died.
- **DNS.** The full tunnel's servers become the default resolver through the System Configuration
  dynamic store: a key of adit's own, `State:/Network/Service/adit-NAME/DNS`, whose supplemental
  match domain is the empty domain. macOS puts it ahead of the network's resolver; `/etc/resolver`
  files still win for their domains, so split tunnels keep their DNS; `/etc/resolv.conf` follows;
  removing the key restores the network's DNS at once. Three other ways did nothing, and changing the
  network service's own keys broke resolution until the network was joined again, so adit never
  touches keys that are not its own. wg-quick's way, rewriting every network service with
  `networksetup`, leaves DNS overridden when it is killed.
- **A DNS line is required.** A full tunnel without one would leave every name to the network's
  resolver, outside the tunnel.
- **IPv6.** A full tunnel that carries only IPv4 sends all IPv6 nowhere while it is up (`::/1` and
  `8000::/1` to a blackhole), so it cannot leave around the tunnel.
- **One full tunnel at a time.** A second one, adit's or another program's, is refused, naming it.
  A split tunnel whose networks would take the full tunnel's DNS server is refused too.
- **Not quite full is refused.** A tunnel routing a large part of the internet without all of it
  (`0.0.0.0/1` alone, `10.0.0.0/7`, `::/0` without IPv4) is refused, saying how to write a full
  tunnel.

For now a full tunnel fails open: if it drops or aditd dies, traffic goes out directly, as with the
WireGuard app. A kill switch comes next, as a pf anchor of aditd's: the experiments showed that
anchors outlive the process that loaded them, that only root's packets can be let through to the
tunnels' servers, that starting to block cuts connections already open, and that another program's
anchor evaluated earlier can let traffic through adit's block.
