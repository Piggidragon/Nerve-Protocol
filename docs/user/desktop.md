# The desktop app

`nerve-node-desktop` is the node with a window, for a machine with a desktop:
Linux x86_64 with GNOME or KDE Plasma (Wayland or X11), and Windows x86_64.
It is one program: it holds the node, its CLI and the app. It installs
itself like any other program, runs the node as a service, and does
everything `nerve-node` does in a terminal (pairing, modes, folders, rules,
sudo, the proxy, the relay, the audit log, backups) without one. The window
runs the CLI for every action, so it has the CLI's checks and audit records.

## Download

From [Releases](https://github.com/Piggidragon/Nerve-Protocol/releases):

| System | File |
|---|---|
| Linux, x86_64 | `nerve-node-desktop-x86_64-linux` (needs glibc 2.35 or newer: Ubuntu 22.04, Debian 12, Fedora 36 and later) |
| Windows, x86_64 | `nerve-node-desktop-x86_64-windows.exe` |

Check it against `SHA256SUMS` ([install](install.md#download)).

## Install

### Let the file run (Linux)

A downloaded file may not run as a program yet.

- **GNOME Files**: right-click the file, **Properties**, switch on
  **Executable as Program**, close the window, then double-click the file.
- **KDE Dolphin**: right-click the file, **Properties**, **Permissions**, tick
  **Is executable**, **OK**, then click the file.

### Windows

Double-click the file. It is not signed, so Windows may show "Windows
protected your PC": **More info**, then **Run anyway**.

### The installer

The first start shows the app's installer. It says what it installs, and
**Install** does it:

- the node, as a service under a user of its own, `nerve`, that starts with
  the machine (what `nerve-node install` does, [service](service.md));
- the app, with **Nerve** in the application menu (the Start menu on
  Windows);
- `nerve://` links, so a pairing link from a center's web UI opens in Nerve.

Installing changes the system, so the system asks for an administrator's
password next: polkit's dialog on Linux, the UAC prompt on Windows. On
Windows the installer first asks for your own Windows password: commands
from your centers run as you, and the service needs your password to start
them ([Windows](service.md#the-account-commands-run-as-on-windows)). On Linux
they run as the user who installed.

When it is done, **Open Nerve** opens the app. Its first-run steps name the
machine, choose where the keys live, pair the first center and choose its
mode. The downloaded file is no longer needed.

| What | Linux | Windows |
|---|---|---|
| The program, which the service runs too | `/usr/local/bin/nerve-node-desktop` | `C:\Program Files\Nerve\nerve-node-desktop.exe` |
| The menu entry | `/usr/local/share/applications/nerve-node-desktop.desktop`, its icon in `/usr/local/share/icons/hicolor` | `Nerve` in the Start menu of all users |
| `nerve://` links | the entry's `x-scheme-handler/nerve`, the default in `/etc/xdg/mimeapps.list` | `HKEY_LOCAL_MACHINE\Software\Classes\nerve` |
| The node's files, the service | as `nerve-node install` puts them ([service](service.md#install)) | as on Windows ([service](service.md#windows)) |

A node installed before with `nerve-node install` keeps its settings, pairings
and keys: the installer adds the app, and the service runs the app's program
from then on.

## Administrator rights

The node's settings and logs belong to the system, so the app asks for
administrator rights once each time it opens, with the same system dialog,
and says why first. It keeps them while it is open. Every change still runs as
a `nerve-node` command.

## Start and stop

The **Overview** shows the service: whether it runs and starts with the
machine. **Stop** ends the node's links and runs nothing until **Start**;
**Restart** stops and starts it. A stopped service starts again with the
machine. In a terminal this is `nerve-node service stop|start|restart`
([service](service.md#start-and-stop)).

## Pairing links

A `nerve://` link opens in Nerve and goes straight to what the pairing would
be. Nothing is paired until you confirm. Nerve has one window: opening it
again, or a link while it is open, goes to the window that is open.

## Update

**Settings**, **Nerve on this machine**, **Update…**: from the latest release
on GitHub (checked against its `SHA256SUMS`), or from a file you downloaded.
The update replaces the program, puts the menu entry back and restarts the
service; the node's settings, keys and audit log stay. **Restart Nerve**
opens the new version. Opening a newer downloaded file offers **Update** too.

## Uninstall

**Settings**, **Nerve on this machine**, **Uninstall…**. Choose whether the
node's data (settings, pairings, keys, audit log) stays or goes. The service,
its user, the program, the menu entry and the link handler go; the window
closes. Opening the downloaded file again offers **Uninstall…** too. Kept
data comes back with the next install ([uninstall](service.md#uninstall)).

## In a terminal

On Linux, `nerve-node-desktop <command>` is `nerve-node <command>`, with
`sudo` on the installed node. On Windows the app has no console, so a terminal
does not wait for it: use `nerve-node.exe` there ([commands](commands.md)).

## The app's own settings

The appearance (system, light or dark) is kept in
`~/.config/nerve-node-desktop/settings.json` on Linux and
`%APPDATA%\nerve-node-desktop\settings.json` on Windows, apart from the
node's settings.
