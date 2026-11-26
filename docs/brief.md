# A WireGuard client with several tunnels at once, a tray icon and a command line

Brief for a new project. It says what the application must do and why; it does not choose the
technology. Open source, for macOS, Linux and Windows.

## Why it exists

I use several WireGuard networks from one laptop (a home lab, an employer's, a product's), and
need more than one connected at the same time. I also work with AI coding agents that drive
tools from the command line. No client I found covers all of this:

- The official WireGuard app for macOS is visual and reconnects by itself, but allows only one
  active tunnel at a time and has no command line.
- `wg-quick` runs several tunnels at once and is scriptable, but has no visual part, asks for
  the administrator password on every use, and does not come back after a reboot.
- The menu bar wrappers around `wg-quick` are unmaintained, and the one that supported several
  tunnels dropped it in its rewrite.
- A paid client may do it all, but I could not confirm its WireGuard support and it is closed.

## What it must do

1. **Several tunnels active at the same time**, each independent of the others.
2. **A tray icon** (menu bar on macOS, system tray on Windows and Linux): shows which tunnels
   are up at a glance; one click switches a tunnel on or off; no main window needed for daily
   use.
3. **A command line with the same abilities as the tray**: list tunnels, bring one up or down,
   show status, import and remove a tunnel. Output readable by a person and, with a flag, as
   JSON for scripts and agents. Exit codes that mean something.
4. **Reconnect after a reboot**: a tunnel marked "start automatically" comes up at system
   start, before anyone logs in, and stays up through sleep, wake and network changes.
5. **No password for daily use**: installing the application asks for administrator rights
   once; after that, the tray and the command line switch tunnels without asking.
6. **Standard configuration files**: imports and exports plain WireGuard `.conf` files, the
   same ones `wg-quick` and the official apps read. Nobody should be locked in.

## How it should behave

- **Tray and command line are two faces of one thing.** A tunnel switched on from the command
  line shows as on in the tray immediately, and the other way round. Neither keeps state of its
  own.
- **Split tunnels are the normal case.** Each tunnel routes only its own address ranges. When
  two tunnels claim overlapping ranges, or two claim all traffic, the application says so
  before connecting rather than letting one silently win.
- **DNS per tunnel**, applied only to that tunnel's names where the system allows it, and
  restored exactly when the tunnel goes down.
- **It coexists with other WireGuard software.** Tunnels brought up by the official app or by
  `wg-quick` are left alone. Showing them read-only in the list would be welcome.
- **Honest status.** "Up" means the last handshake is recent, not merely that the interface
  exists. Show last handshake time and traffic counters per tunnel.
- **Failures are explained.** If a tunnel cannot come up, the command line and the tray both
  say why, in one sentence a person can act on.

## Security

- Private keys never appear in command output, logs or the tray. They are stored where the
  system protects secrets (Keychain, Credential Manager, a root-only file on Linux), not in a
  world-readable configuration file.
- The part running with administrator rights is as small as possible and does only tunnel
  work. It accepts requests only from the local machine, and only from the user who installed
  it or users explicitly allowed.
- It never accepts a path or a command from a request and runs it. In particular, `PreUp`,
  `PostUp`, `PreDown` and `PostDown` lines from imported files are not run by default: they
  would let any configuration file run commands as administrator. If supported at all, they
  need an explicit, per-tunnel opt-in.
- No telemetry and no network calls other than the tunnels themselves and, if added later, an
  update check the user can switch off.

## Things already learned

- On macOS, the one-tunnel limit comes from the system's VPN framework that the official app
  uses. Running several tunnels means the route `wg-quick` takes: a userspace WireGuard
  (`wireguard-go` or an equivalent library) on `utun` interfaces, started by a privileged
  background service.
- On Linux, WireGuard is in the kernel; several interfaces at once is ordinary. The work is
  mostly the service, permissions and the tray, which differs between desktops.
- On Windows, the official implementation already runs each tunnel as its own service and
  supports several at once; study it before writing anything new.
- The natural shape on all three is a small privileged service that owns the tunnels, with the
  tray and the command line as unprivileged clients talking to it over a local socket or pipe.
  That one design answers points 2 to 5 above.

## Out of scope for the first version

- Being a WireGuard server or managing peers on a server.
- Generating configurations for other devices, QR codes, mobile apps.
- Other VPN protocols.
- Accounts, sync between machines, or any hosted service.
- A kill switch. Worth considering later; easy to get wrong.

## To decide in the new session

- **Name** of the project and of the command.
- **Language and tray toolkit.** One codebase for three systems is the goal; the privileged
  service and the command line could share a language even if the tray needs something native.
  I am new to Rust, so if Rust is chosen the code should stay simple and be explained.
- **License.** WireGuard's own userspace code is MIT or GPL depending on the piece; the choice
  of library limits the choice of license.
- **Which system comes first.** macOS is where the problem hurts today.
- **Distribution**: Homebrew, a signed installer on macOS and Windows (signing costs money and
  needs developer accounts), packages on Linux.
- **How it handles tunnels it did not start** (ignore, show read-only, or adopt).

## Definition of done for a first usable version, on macOS

- Two tunnels with different address ranges are up at once, alongside one tunnel in the
  official app, and all three pass traffic.
- Both come back by themselves after a reboot, before login.
- The tray shows both and toggles each with one click and no password.
- The command line does the same, and `status --json` gives handshake age and counters.
- Importing a `.conf` with a `PostUp` line warns and does not run it.
- Uninstalling removes the service, the interfaces and the stored keys.

## Working rules I use in my projects

- Tools and language versions are managed with mise wherever mise can.
- A new project starts from the standard generator of its stack, not from hand-made files.
- Commit or push only when I say so.
