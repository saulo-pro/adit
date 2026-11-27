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
