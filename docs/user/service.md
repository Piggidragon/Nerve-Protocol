# Run the node as a service

On Linux with systemd and on Windows, `nerve-node` installs itself as a
service. The service starts with the machine and runs under a user of its own,
`nerve`, which owns the node's config and state folders. `install`, `update`
and `uninstall` need root, on Windows an administrator. On Linux without
systemd, run `nerve-node run` under your own service manager
([pairing](pairing.md#keep-it-running)). A node you start yourself as root, or
elevated on Windows, is refused unless `machine.allow_root` is set, and warns
at start when it runs
([root and administrator](platforms.md#root-and-administrator)). Windows
differs in a few places; see [Windows](#windows). The center installs
itself the same way on Linux ([center](center.md#run-it-as-a-service)).

## Install

Download the program for your machine (`nerve-node-x86_64-linux` or
`nerve-node-aarch64-linux`, [install](install.md)) and run it once as root:

```sh
curl -LO https://github.com/Piggidragon/Nerve-Protocol/releases/latest/download/nerve-node-x86_64-linux
chmod +x nerve-node-x86_64-linux
sudo ./nerve-node-x86_64-linux install
sudo nerve-node setup
```

Whatever the downloaded file is called, `install` puts it in place as
`/usr/local/bin/nerve-node`.

`install` does this, and says each step:

1. Makes the system user `nerve`, with its own group, no login and the home
   `/var/lib/nerve`. A `nerve` user that `install` did not make is refused.
2. Makes the folders, private to `nerve` (mode 0700). Folders an earlier
   install left behind are given to the new user.
3. Sets the account that [commands run as](#the-account-commands-run-as):
   the account that ran `sudo`. An account chosen before stays. When you
   are logged in as root without `sudo`, it is root, and `install` warns
   that commands from a center then run as root. It warns about the account
   that ran `sudo` as well, since a person logs in as it, and about any
   account that gets root without a password (below), and suggests
   `sudo nerve-node setup --create-user nerve-work`. The warning does not
   stop the install.
4. Copies the program to `/usr/local/bin/nerve-node`.
5. Writes the unit `/etc/systemd/system/nerve-node.service`, enables it and
   starts it. It waits until the node answers. The unit hands the node its
   cgroup (`Delegate=cpu memory pids`), so each command runs held to its
   [limits](limits.md), and keeps the node running when one of them is
   killed for its memory (`OOMPolicy=continue`).

When the settings of an earlier install keep the keys in the system keyring
([keys](config.md#where-the-node-keeps-its-keys)), `install` first checks
that a keyring answers for `nerve`. In a terminal it offers to install one;
otherwise, and on a no, it stops before it starts the service. It then leaves
the account of the commands to `setup`.

Running `install` again repairs what is missing and restarts the service.

| What | Where |
|---|---|
| `node.toml`, one key per center | `/etc/nerve` |
| Audit log, [log](logs.md), control socket and its token, config key, the last version of `node.toml` | `/var/lib/nerve/state` |
| The keys, with `machine.secret_storage = "keyring"` | the keyring of `nerve`, `/var/lib/nerve/.local/share/keyrings` |
| Home of `nerve` | `/var/lib/nerve` |
| The program | `/usr/local/bin/nerve-node` |
| The unit | `/etc/systemd/system/nerve-node.service` |

Nothing else is written. `journalctl -u nerve-node` shows the node's output.

## Use the commands

When the node is installed, `nerve-node` without `--config-dir` and
`--state-dir` works on the installed node. Run the commands with `sudo`:

```sh
sudo nerve-node status
sudo nerve-node rule add allow 'git status'
```

A command that root runs on these folders runs as `nerve`, so every file it
writes stays the node's. Another user gets a message that says to use `sudo`.

## The account commands run as

`nerve` only holds the node's config, keys and state. The commands a center
runs on the node, in every mode, run as an ordinary account: the one
`install` took or `setup` chose (`machine.user` in the [config](config.md)).
They get that account's groups, its home as `HOME` and, when the call names
no folder, as their working folder. A [sudo](sudo.md) command starts as that
account too, and `sudo on` takes that account's password. The node reads and
writes files for a center (`fs`) as that account as well: it sees what the
account sees, and the files it makes belong to the account. `~` in
[rules](rules.md) and the [protected paths](protected-paths.md) is that
account's home.

- In `user` mode a command may do what that account may do.
- In `folder` mode it is that account as well, held by Landlock to the
  folders you gave the center ([modes](modes.md)). That is the only
  difference to `user` mode.
- In `allowlist` mode it runs what an allow rule names, as that account.

No command can read the node's keys: they are private to `nerve`. Before a
command starts, the node checks that its account cannot open the node's
folders, and refuses to run it if it can. That holds as long as the account
cannot become root. Root itself can, and so can an account in a group that
gets root without a password: `docker`, `lxd`, `incus-admin`, `libvirt` or
`disk`. So can an account that may use `sudo` without a password:
`install` and `setup` read its sudo rules (`sudo -l -U <account>`) and, when
they may give root a command without a password (`NOPASSWD` for anything but
plain command paths, `authenticate` turned off, an `exempt_group`), run
`sudo -n -k true` as the account. If that succeeds, they warn. The rules
decide whether that is tried at all: an account whose rules surely need a
password for root, `NOPASSWD` for plain commands such as `apt` or for
another user to run as included, is not run as, so sudo logs no failed
login. One whose rules may grant it but a later rule asks for the password
is run as, and sudo logs it. Only sudo 1.9 without `noninteractive_auth` is
known to stay out of PAM with `-n`. Elsewhere (sudo-rs, an unknown sudo) a
probe would count as a failed login, which can lock the account
(pam_faillock), so none is made and the rules alone decide the warning. The account that ran `sudo`, the one its owner
logs in as, is such an account too (see [platforms](platforms.md#linux)).
`install` and `setup` warn about such an account, whether they take it or it
is chosen already, and suggest an account made for the node, also for root.
`NOPASSWD` for a single command can be root as well (`apt`, `systemctl`, a
shell, an editor), and they do not see that: check `sudo -l -U <account>`
yourself. Choose one outside these groups and without such rules, or a
command can read the keys after all.

- No account chosen: the node runs no command, and says that
  `sudo nerve-node setup` chooses one.
- `nerve` itself is refused, and so is an account that could open the
  node's folders.
- Root is allowed, with a warning: commands from a center then run as root,
  with every right on the machine, the node's keys included; in `folder`
  mode only Landlock still holds them. You are responsible for what they do.
  The node's own file work for a center (`fs`, and the checks of a call's
  paths and working folder) is not a command, though: it is done as root
  without root's right to override permissions, which the service does not
  have. It reaches only what root owns or what is open to everyone, so a
  call into another user's home (often mode 0750) fails with "permission
  denied". Choose that user's account instead, or let a command do the
  work.

### The one privilege the service keeps

To start a command as that account, the service keeps two capabilities,
`CAP_SETUID` and `CAP_SETGID` (`AmbientCapabilities=` in the unit). This is
the one privilege it has beyond what `nerve` may do, chosen so that commands
run as a real account and not as the user that owns the keys.
The node uses it only to switch to the account. Every command it starts
drops both capabilities before it runs, in every mode, so no command keeps
them.

## Setup

`sudo nerve-node setup` asks these things, one at a time. Enter keeps what is
in brackets.

1. The node's name, as centers show it. The host name by default.
2. The account that [commands run as](#the-account-commands-run-as), on an
   installed node. It must exist, or setup offers to make it: an ordinary
   account with a group and a home (`/home/<name>`) of its own, no login,
   and the comment `Nerve user mode`. Choosing root shows the warning above.
3. Where the node keeps its keys: `file` or `keyring`
   ([keys](config.md#where-the-node-keeps-its-keys)). With `keyring` and no
   keyring that answers, it offers to install one where `nerve` has no
   desktop, and then restarts the node if it had found none before. Not
   asked on the installed node on Windows, which keeps them in files
   ([Windows](#windows)), nor on a kernel with a Landlock ABI below 9
   ([keys](config.md#an-older-linux-kernel)); setup warns instead.
4. A pairing link from the center's web UI. Enter skips it. The node shows
   the center and asks before it pairs, as `center add` does.
5. The mode of that center: `allowlist`, `folder` or `user`
   ([modes](modes.md)). For `folder` it asks for one folder and its rights.

Each answer is saved when you give it, through the running node, like every
other command. You can stop setup at any point and run it again. It works on
a node that is not installed as well.

To choose the account without the question, name it:

```sh
sudo nerve-node setup --create-user nerve-work
```

Setup then makes the account as above if it is not there, runs commands as
it, and asks the other questions. An account that is there already is
taken if the node can use it. `nerve`, an account that could open the
node's folders, and a name other than a-z, 0-9, `_` and `-` are refused
before anything changes. `--create-user` works on an installed node only.

## Update

```sh
sudo nerve-node update
```

`update` downloads the program for this machine from the latest release on
GitHub (`nerve-node-x86_64-linux` or `nerve-node-aarch64-linux`, the names
`install` takes too), checks it against the release's `SHA256SUMS`, puts it
in place as `/usr/local/bin/nerve-node` and restarts the service. `HTTPS_PROXY` is used when it is set.
`--from <file>` takes a program you downloaded and checked yourself.

The config, the keys and the audit log are not touched. `update` refuses a
file that is not `nerve-node` and a program older than the installed one. If
the new program does not start, the old one is put back and started again.

`update` does not write the unit. After an update from a version without
[limits per command](limits.md), run `sudo nerve-node install` once more: it
writes the unit with `Delegate=` and restarts the node. Until then
`nerve-node status` says that commands run without their limits.

## Uninstall

```sh
sudo nerve-node uninstall           # keeps the config and state folders
sudo nerve-node uninstall --purge   # deletes them too
```

`uninstall` stops and disables the service, removes the unit, the user
`nerve` and `/usr/local/bin/nerve-node`. A session that a keyring gave
`nerve` is ended first. Without `--purge`, `/etc/nerve` and
`/var/lib/nerve` stay and belong to root from then on, so no later user with
the old uid gets the keys. The account of the commands stays, also one that
`setup` made; `sudo userdel -r <name>` removes it. A later `install` takes them up again: the node
comes back with its pairings, rules and audit log. `--purge` deletes them,
keys and audit log included.

## Windows

Run these commands in a terminal opened with "Run as administrator":

```powershell
.\nerve-node-x86_64-windows.exe install
& "C:\Program Files\Nerve\nerve-node.exe" setup
Restart-Service nerve-node
```

`install` does this, and says each step:

1. Makes the local user `nerve`, with a long random password that nobody
   types; the service manager keeps it. `nerve` may log on as a service and
   in no other way, and does not show on the sign-in screen. A `nerve` user
   that `install` did not make is refused.
2. Makes the folders and gives them an access list of their own: `nerve`,
   SYSTEM and the administrators, nothing inherited from the folders above.
3. Sets the account that commands run as: the account that runs `install`.
   An account chosen before stays. It asks once for that account's password
   and stores it with DPAPI in the config folder, so only what can open that
   folder can read it. A stored password that still works is not asked for
   again.
4. Copies the program to `C:\Program Files\Nerve\nerve-node.exe`.
5. Registers the service `nerve-node`, which runs as `nerve`, starts with the
   machine and starts again after a failure.
6. Registers the source `nerve-node` in the Windows Event Log, then starts
   the service. It waits until the node runs.

| What | Where |
|---|---|
| `node.toml`, one key per center, the stored password of the account commands run as, the sudo password while sudo is on | `C:\ProgramData\Nerve\config` |
| Audit log, [log](logs.md), config key, the last version of `node.toml`, the record of the folder grants (`grants.json`) | `C:\ProgramData\Nerve\state` |
| The program | `C:\Program Files\Nerve\nerve-node.exe` |
| Start, stop, a start that fails, a crash | The Windows Event Log, Application, source `nerve-node` ([logs](logs.md#the-windows-event-log)) |

The service writes its log to `C:\ProgramData\Nerve\state\log.jsonl`. When
it does not start, the Event Viewer says why, and the log has the rest.

The other commands work on the installed node from an administrator's
terminal. The service takes `folder add`, `folder set` and `folder rm` at
once over its [control pipe](platforms.md#the-control-pipe), and every other
change at its next start: `Restart-Service nerve-node`. `setup` asks no
account there, and `--create-user` is refused.

The installed node on Windows keeps its keys in files. The service runs as
`nerve`, and the Credential Manager is one per account: keys that `setup` or
`config set` put in the keyring would be in the Credential Manager of the
administrator who ran them, where the service does not find them. So `setup`
does not ask where the keys go, and takes keys it finds in the keyring into
files; `config set machine.secret_storage keyring` is refused and changes
nothing. A `node.toml` that keeps the keys in the keyring is refused by
`install`, before it changes anything, and the service does not start with
one. Move the keys into files first, as the account that put them in the
keyring, in a terminal opened with "Run as administrator". Name the folders:
without a registered service the commands work on your own folders, not on
the node's. Run it with the program you have, the downloaded one before a
first install:

```powershell
.\nerve-node-x86_64-windows.exe --config-dir "C:\ProgramData\Nerve\config" --state-dir "C:\ProgramData\Nerve\state" config set machine.secret_storage file
```

The same account problem keeps the proxy's values out of reach: the installed
node on Windows takes a proxy only if it needs no header and no password.
`proxy set` with either is refused and changes nothing
([proxy](proxy.md#on-the-node-installed-as-a-service-on-windows)).

To run the commands as another account, an ordinary one, name it and run
`install` again; it asks for that account's password:

```powershell
& "C:\Program Files\Nerve\nerve-node.exe" config set machine.user bob
.\nerve-node-x86_64-windows.exe install
```

### The account commands run as on Windows

Every command, and the node's file work for a center, runs as that account,
logged on with its stored password. It must be a local account that has
signed in once, so it has a profile folder. A command gets the account's
environment, its profile folder as working folder when the call names none,
and a job object that ends it with every process it started. While the
account is not signed in, its registry (`HKCU`) is not loaded: a command
then gets the usual folders of its profile (`APPDATA`, `TEMP` and so on),
but not the variables the account set itself. An
administrator's command runs as UAC gives it to a sign-in: the
Administrators group only denies. Before a command starts, the node checks
that the account can open neither the node's folders nor a file in them, and
refuses it if it can. `install` checks the same.

`folder` mode runs no command on the service yet: its AppContainer is not
started as another account ([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)).
Use `allowlist` or `user` mode for its centers.

UAC is no security boundary: a command of an administrator can get the
group's rights back and read the keys. `install` warns about an account in
Administrators or Backup Operators. Choose an ordinary account as above.
[Sudo on Windows](sudo.md#sudo-on-windows) needs an administrator: its
commands run with the account's administrator rights on purpose.

If the account's password changes, commands fail until `install` runs again
and asks for the new one. A Microsoft account works with its Microsoft
password, which can change outside the machine.

To start a process as that account, the service keeps two privileges,
`SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege`. Windows
takes every other privilege from it, `SeImpersonatePrivilege` included. No
command gets them.

### Update and uninstall on Windows

`update` downloads `nerve-node-x86_64-windows.exe` and checks it as above.
It stops the service, moves the old program aside, puts the new one in its
place and starts the service; if the new one does not start, the old one
goes back. The old program goes once nothing holds it, or at the next
restart of Windows when Windows still holds it: when `update` ran from it, or
when the Event Log read the text of the node's entries from it. `install`
over an installed node moves the old program aside the same way. `update` also registers the Event Log
source `nerve-node` again. A node installed by a program that did not
register it yet gets it from the installed program:
`& "C:\Program Files\Nerve\nerve-node.exe" install`, or the next `update`.

`uninstall` stops and removes the service, the source `nerve-node` of the
Event Log (its entries stay), the user `nerve` and its profile, and the
program. It also takes off the folder grants of `folder` mode that a node
you ran yourself put on, and removes the profiles of its AppContainers
([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)); the
service puts none on. It names the profiles it removed, and those it left
because that node runs. Without `--purge` the folders and the stored password stay,
open to the administrators only; the [sudo](sudo.md#sudo-on-windows)
password goes, so sudo is off after a later `install`. A later `install`
takes them up again.
`--purge` deletes them. Run from the installed program, `uninstall` cannot
delete that file at once: it moves it aside, and Windows deletes it at its
next start. Where Windows
still holds the profile of `nerve` (Windows Search can), `uninstall` says how
to remove it after a restart.

## The rules for these commands

- `install`, `setup`, `update` and `uninstall` are refused from a command the
  node runs for a center, as every other change of the node's settings is.
  An agent cannot install, update or remove the node. On Windows the control
  pipe does not take this check yet; there these commands need an
  administrator, which a command gets only through an account in
  Administrators (the UAC warning above).
- Each is written to the [audit log](audit.md) with the steps it did, and the
  error that stopped it, if any. `uninstall --purge` deletes the log with the
  rest.
