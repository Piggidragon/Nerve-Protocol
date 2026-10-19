# The desktop app

`nerve-node-desktop` is the node with a window, for a machine with a desktop:
Linux x86_64 with GNOME or KDE Plasma (Wayland or X11), and Windows x86_64.
It is one program: it holds the node, its CLI and the app. It installs
itself like any other program, runs the node as a service, and does what
`nerve-node` does in a terminal (pairing, modes, folders, rules, sudo, the
proxy, the relay, the audit log, backups, the account commands run as)
without one; two things stay with the terminal ([settings](#settings)). The
window runs the CLI for every action, so it has the CLI's checks and audit
records.

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
them ([Windows](service.md#the-account-commands-run-as-on-windows)). That
holds when you are a standard user and an administrator types their name and
password into the UAC prompt: the commands still run as you, not as the
administrator. If your password was mistyped, enter it again under
**Settings**, **Account for commands**. On Linux they run as the user who
installed.

When it is done, **Open Nerve** opens the app. Its first-run steps name the
machine, choose where the keys live, pair the first center and choose its
mode. The downloaded file is no longer needed.

| What | Linux | Windows |
|---|---|---|
| The program, which the service runs too | `/usr/local/bin/nerve-node-desktop` | `C:\Program Files\Nerve\nerve-node-desktop.exe` |
| The menu entry | `/usr/local/share/applications/nerve-node-desktop.desktop`, its icon in `/usr/local/share/icons/hicolor` | `Nerve` in the Start menu of all users |
| `nerve://` links | the entry's `x-scheme-handler/nerve`, the default in `/etc/xdg/mimeapps.list` | `HKEY_LOCAL_MACHINE\Software\Classes\nerve` |
| Apps & features | | `Nerve`, in `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Nerve` |
| The node's files, the service | as `nerve-node install` puts them ([service](service.md#install)) | as on Windows ([service](service.md#windows)) |

A node installed before with `nerve-node install` keeps its settings, pairings
and keys: the installer adds the app, and the service runs the app's program
from then on, so there is one program to update. On Linux the old program,
`/usr/local/bin/nerve-node`, becomes a link to the app's, so the command
`nerve-node` keeps working. On Windows the old
`C:\Program Files\Nerve\nerve-node.exe` is removed: the app replaces it, and
for a terminal you download the CLI edition on its own
([in a terminal](#in-a-terminal)). A plain `nerve-node uninstall` later hands
over to the app's uninstall, so it removes the app too
([uninstall](service.md#uninstall)).

## Administrator rights

The node's settings and logs belong to the system, so the app asks for
administrator rights once each time it opens, with the same system dialog,
and says why first. It keeps them while it is open. Every change still runs as
a `nerve-node` command.

The app's link to the rights is its own: on Linux the app closes itself to
the other processes of your user once it asks (they can neither open that
link nor trace the app), and its file dialogs then run in a process of
their own, which the desktop portal answers; on Windows the link is open
to the app's process alone. On Windows the app also loads the system's
DLLs from System32 only, never from the folder it was downloaded to.

What this does not cover, while the app is open with the rights:

- On Windows, any program that runs as you may reach into the app's
  process and act through it: Windows does not keep a user's programs
  apart.
- On X11 every program in your desktop session can send key presses and
  clicks to any window, this one too. Wayland does not let it.
- A program that runs as you can change how the app starts, for example
  through your session's environment or a menu entry of its own in your
  home folder, and run in its place.
- A file you pick in the app, such as a backup to restore or a program to
  update from, lies in your folders, which any program that runs as you
  may change before the node reads it.

So the rights are as safe as your desktop session. Close the app when you
are done; that gives them back.

## Start and stop

The **Overview** shows the service: whether it runs and starts with the
machine. **Stop** ends the node's links and runs nothing until **Start**;
**Restart** stops and starts it. A stopped service starts again with the
machine. In a terminal this is `nerve-node service stop|start|restart`
([service](service.md#start-and-stop)).

On Windows the running service takes folder changes at once and every other
change only when it starts again, a pairing too. So after such a change the
app restarts the service itself, two seconds after the last one, and says
so; closed before then, the app restarts it as it closes. The first-run
steps restart it once, at their end, also when you close them early. The node's links come
back at once, but a command a center runs at that moment ends. If the
restart fails, the Overview says that changes wait and offers **Restart**.

## Settings

- **Account for commands**: the account commands from your centers run as.
  On Linux, name another one to use it; one that is not there is made, as
  `setup --create-user` makes it. On Windows, enter its new password there
  when it changed, or your own when no account is chosen yet: the service
  needs it to start commands.
- **Keys**: in files, or in the system keyring where one can hold them. Where
  it cannot (the installed node on Windows, Linux below 7.1, no keyring
  answering for the account the node runs as), the app says why and keeps
  them in files.
- **Backup…** and **Restore…** write and read the file as you, in your own
  folders. A restore never goes under a running node: the app stops the
  service for it and starts it again after. **Keep its keys in files here**
  restores the backup of a machine that kept them in a keyring onto one
  without.
- **Any setting**: shows and sets any setting, and **Add** and **Remove**
  change a list, such as `policy.protected.allow`. On **Permissions**, a
  pattern for files (`fs.read:~/notes/*`) goes on the allow or deny list as
  it is.

What stays with the terminal: restoring the keys straight into the keyring
(`restore --secret-storage keyring`; restore, then switch **Keys** to the
keyring), and the keyring `setup` installs for the node's account on a
Linux without a desktop session for it.

## Pairing links

A `nerve://` link opens in Nerve and goes straight to what the pairing would
be. Nothing is paired until you confirm. Nerve has one window: opening it
again, or a link while it is open, goes to the window that is open. A link
carries the pairing's code and pin, so it goes only to a window of your
own: where the app cannot make sure of that (on Windows, when a program
that is not your Nerve holds the name the window listens by; on Linux,
when `$XDG_RUNTIME_DIR` is not a folder only you may open), each start
opens a window of its own and says so.

## Update

**Settings**, **Nerve on this machine**, **Update…**: from the latest release
on GitHub (checked against its `SHA256SUMS`), or from a file you downloaded.
The update replaces the program, puts the menu entry back and restarts the
service; the node's settings, keys and audit log stay. **Restart Nerve**
opens the new version. Opening a newer downloaded file offers **Update** too.

## Uninstall

**Settings**, **Nerve on this machine**, **Uninstall…**. Choose whether the
node's data (settings, pairings, keys, audit log) stays or goes. The service,
its user, the program, the menu entry, the link handler and, on Linux, the
`nerve-node` link go, and the window says "Nerve is removed" until you close
it. Opening
the downloaded file again offers **Uninstall…** too, and on Windows so does
**Uninstall** at Nerve in **Settings**, **Apps** (Apps & features): it opens
the same in the app. Kept data comes back with the next install
([uninstall](service.md#uninstall)).

## What the app needs

On Linux the window uses parts of the desktop. GNOME and KDE Plasma bring all
of them; on another desktop, install what is missing.

| Part | What it is for | GNOME | KDE Plasma | Other desktops |
|---|---|---|---|---|
| A display, Wayland or X11 | The window | yes | yes | yes |
| OpenGL (Mesa's libEGL, libGL) | Drawing with the GPU; without it the app draws in software | yes | yes | usually |
| `pkexec` and a polkit authentication agent | Asking for administrator rights | built into GNOME Shell | `polkit-kde-agent-1`, part of Plasma | `polkit` and an agent, for example `polkit-gnome`, `lxpolkit`, `mate-polkit` |
| `xdg-desktop-portal` with a file chooser | The file and folder dialogs | `xdg-desktop-portal-gnome` | `xdg-desktop-portal-kde` | `xdg-desktop-portal` and `-gtk` or `-wlr` |
| `update-desktop-database` (desktop-file-utils) | Telling the desktop at once that Nerve opens `nerve://` links | yes | yes | install it, or log out and in after installing |

When a part is missing, the app says so:

| Missing | What happens |
|---|---|
| A display | The app does not start. It prints `no display: …` and shows it as a desktop notification where it can |
| OpenGL | The app starts once more drawing in software, and prints that it does. If that fails too, it prints `the window did not open …` |
| `pkexec` | Instead of the system's question: "There is no pkexec on this machine …", with the package to install |
| The polkit agent | pkexec says that no authentication agent answered, and the app shows instead: "No polkit authentication agent is running …", with agents to install |
| The portal | The button that opens a file or folder dialog says "No file dialog: …" and names the portal packages |
| `update-desktop-database` | Installing goes on, and its last step warns that the desktop may not know about the `nerve://` handler yet |

Windows needs nothing besides the app.

## In a terminal

On Linux, `nerve-node-desktop <command>` is `nerve-node <command>`, with
`sudo` on the installed node; where the app took over a node installed with
`nerve-node`, the command `nerve-node` runs the app's program, which says
`nerve-node-desktop` for `--version`.

On Windows the app is the node's program, and it has no console, so a
terminal does not wait for it. For a terminal, download the CLI edition
`nerve-node-x86_64-windows.exe` from the release: it is a console program,
and run from an administrator's terminal it works on the node the app
installed ([commands](commands.md)). The app's program in a terminal needs a
pipe to be waited for: `"C:\Program Files\Nerve\nerve-node-desktop.exe" status | more`
in cmd, `& "C:\Program Files\Nerve\nerve-node-desktop.exe" status | Out-Default`
in PowerShell. A batch file waits for it as it is.

## The app's own settings

The appearance (system, light or dark) is kept in
`~/.config/nerve-node-desktop/settings.json` on Linux and
`%APPDATA%\nerve-node-desktop\settings.json` on Windows, apart from the
node's settings.
