# Changelog

What changed in each version of adit, for the people who use it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each version's section here is the
notes of its GitHub release.

## [Unreleased]

### Security

- Releases are built with no cache from earlier CI runs, with every module checked against `go.sum`,
  in a job that cannot publish; each archive carries a build provenance attestation, which
  `gh attestation verify adit-macos.tar.gz --repo saulo-pro/adit` checks.
- `golang.org/x/crypto`, `x/net` and `x/sys` are up to date, and CI checks for known
  vulnerabilities on every push.
- A malformed key line no longer puts the key into the error, which reached the terminal and
  aditd's log. Lines with control characters, which a terminal can hide, are refused at import.
- aditd's log is readable by root alone, rotation now really starts a new file, and repeated
  WireGuard errors are logged once a minute with a count.
- Status reads no longer pass the tunnels' private keys around, the tunnel store is excluded from
  Time Machine, and a crash while saving no longer leaves a copy of a configuration behind.
- The menu bar icon starts from a root-owned copy instead of Homebrew's folder, which another
  account's programs could change; `sudo adit install` checks and installs root-owned copies of
  `aditd` and the icon, and says when their source folder is writable by other accounts.
- `sudo adit export` hands the new file over before writing the key and never writes through a
  link; `sudo adit import` reads only a regular file. Under `sudo`, adit talks only to an `aditd`
  running as root.
- `sudo adit install` refuses a group named adit it did not create unless `--reuse-group`, gives
  the group it creates an unused id below 500, and `uninstall` deletes only a group adit created.
- `adit version` says when `aditd` is older than `adit`.
- Bringing a tunnel up reads the routing table back: if a route did not go in (another
  interface already holds that network), the tunnel fails instead of sending that traffic in the
  clear. A local-network route as specific as an AllowedIPs network, a DNS domain above or below
  another resolver's, a tunnel address inside another tunnel's networks, and an endpoint name
  under another tunnel's DNS domain are refused. While a tunnel is up, adit notes routes that
  other software adds later inside its networks.
- The full-tunnel refusal judges what AllowedIPs cover together: four /2 networks, 2000::/3 or
  any network wider than /8 (IPv6: /16) count too.
- A file may list at most 3 DNS servers, 32 DNS domains, 16 addresses, 64 peers and 1,024
  AllowedIPs, in at most 64 KiB; repeated entries count once. Whole top-level domains, `.local`,
  link-local, multicast and unroutable AllowedIPs, link-local addresses and reserved ListenPorts
  are refused. Table, SaveConfig and FwMark lines draw a warning: adit ignores them.
- A peer's endpoint no longer moves to wherever one of its packets came from.
- `aditd` holds up under load: at most 64 connections and 8 watchers per account, small requests
  from anyone but root, nothing read from callers outside the adit group, unknown commands refused
  before they are logged, and a temporary accept error no longer stops it answering. A watch ends
  when its account leaves the adit group.
- After a network change, a tunnel's UDP socket comes back even if its port was taken meanwhile;
  taking a tunnel down while it is coming up waits for it to let go of its device, and DNS for a
  tunnel stops before its device does. Tunnel names match with ASCII case folding only.

### Changed

- An `Address` or `AllowedIPs` entry that is not an IP address is now explained with the example
  `10.99.1.2/24`.

## [0.1.2] - 2026-11-26

adit itself is unchanged since 0.1.0. Its repository starts over at this version, with a single
commit.

### Removed

- The 0.1.0 and 0.1.1 releases and their downloads are no longer on GitHub. Install 0.1.2 or later,
  with Homebrew or the one-line installer.

## 0.1.1 - 2026-11-26

adit itself is unchanged since 0.1.0; what is new is how you install it.

### Added

- A one-line installer: `curl -fsSL https://adit.saulo.pro/install.sh | sh`. It downloads the
  latest release, checks it against the release's `SHA256SUMS`, puts `adit`, `aditd` and
  `adit-tray` in `/usr/local/bin` and runs `sudo adit install`. Run it again to upgrade. It refuses
  a Mac where Homebrew installed adit.
- Every release carries `adit-macos.tar.gz`, with `adit`, `aditd` and `adit-tray` as universal
  binaries for Apple silicon and Intel Macs on macOS 13 and later, and its `SHA256SUMS`.

### Changed

- adit's home page is now https://adit.saulo.pro.

## 0.1.0 - 2026-11-25

The first version, for macOS.

### Added

- Several WireGuard tunnels up at the same time, each routing only its own networks. A tunnel whose
  networks or DNS domain overlap a tunnel that is up, adit's or another program's, is refused
  before it connects, with the reason.
- A menu bar icon and the `adit` command line over one privileged service, `aditd`: a tunnel
  switched in one flips in the other at once.
- Plain-word answers from every command, or JSON with `--json`, with meaningful exit codes.
- Tunnels set to start automatically come up at boot, before anyone logs in, and follow network
  changes.
- No password for daily use: the administrator password is asked once, at install, and members of
  the `adit` group switch tunnels without one. Importing, exporting and removing tunnels need
  `sudo`.
- Import and export of plain WireGuard `.conf` files. `PreUp`, `PostUp`, `PreDown` and `PostDown`
  lines are kept, with a warning, and never run.
- DNS per tunnel: `DNS = 10.99.1.1, corp.example` sends names under `corp.example` to `10.99.1.1`
  and leaves every other name alone.
- Status with the last handshake and the bytes each way.
- The WireGuard app's and `wg-quick`'s tunnels shown read-only, with `wg-quick`'s handshakes and
  counters.
- `sudo adit install` and `sudo adit uninstall`; uninstall removes the service, the interfaces and
  the stored keys.
- Homebrew: `brew install saulo-pro/tap/adit`.
- Full tunnels (`AllowedIPs = 0.0.0.0/0`) are refused for now, saying so.

[Unreleased]: https://github.com/saulo-pro/adit/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/saulo-pro/adit/releases/tag/v0.1.2
