# AGENTS.md

Guidance for coding agents working in this repository.

## Releases

These are Saulo's conventions for every saulo-pro project. Follow them, and change them only when he
asks.

- **Tags.** Each release is a tag `vX.Y.Z`. A pushed tag is never moved or deleted: a fix is a new
  version.
- **GitHub releases.** Every tag gets a GitHub release, made by `.github/workflows/release.yml`.
  Anything not stable (`v0.2.0-rc.1`: any version with a suffix) is published as a prerelease, so
  it never becomes GitHub's "Latest release".
- **The standard install gets GitHub's Latest release.** Never the tip of `main`, and never a version
  written into the installer. `docs/install.sh` downloads from `releases/latest/download/…`, and
  `ADIT_VERSION=` installs a given version instead. The Homebrew formula in `saulo-pro/homebrew-tap`
  names a version by nature, since it carries the archive's checksum: that is its stable, and `head`
  is `main`.
- **No moving tags.** No `stable` or `latest` git tag: `git pull` does not move a tag a clone already
  has, and git's manual advises against re-tagging. GitHub's Latest release is the moving pointer.
- **The version comes from the tag.** `scripts/release-archive` stamps it from the tag, and the
  release checks the binaries report it. Never type a version into the source.
- **A changelog per version.** `CHANGELOG.md` at the root, in the Keep a Changelog style:
  `## [Unreleased]` on top, then one `## [X.Y.Z] - YYYY-MM-DD` section per version, grouped into
  Added / Changed / Fixed / Removed, with comparison links at the bottom. Add to Unreleased with
  each change a user would notice. Before tagging, move what Unreleased gathered into the version's
  dated section, leave Unreleased empty, and add the version's comparison link. The GitHub release's
  notes are that version's section: `scripts/release-notes` prints it for `release.yml`, which stops
  before building when the tag has none, and CI's `changelog` job checks every `v*` tag on push.
- **A one-line installer runs nothing until it has fully arrived.** All of `docs/install.sh`'s work is
  in `main()`, called on its last line, so a download cut short by `curl … | sh` runs nothing.
  `test/installer` checks it.

## Examples and test data

This repository is public. Names, accounts, hosts and addresses in tests, fixtures, docs and examples
are made up, never real ones: not Saulo's or anyone's real name or username, and never output
captured from a real machine without replacing every name, address and identifier in it.

- **People, places and things come from the TV show "2 Broke Girls".** Accounts and people: `max`,
  `caroline`, `earl`, `oleg`, `han`, `sophie`. Tunnels, hosts and places: `williamsburg`, `diner`,
  `cupcakes`, `brooklyn`, `manhattan`, `chestnut`.
- **Addresses** come from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`, `example.com`) or are plainly made-up private ones such as
  `10.99.1.0/24`.
- **Keys** are generated for the test and say so in a comment.
