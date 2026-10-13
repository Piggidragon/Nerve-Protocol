# Run the node as a service

On Linux with systemd, `nerve-node` installs itself as a service. The service
starts with the machine and runs under a user of its own, `nerve`, which owns
the node's config and state folders. `install`, `update` and `uninstall` need
root. On Windows and on Linux without systemd, run `nerve-node run` under your
own service manager ([pairing](pairing.md#keep-it-running)). A node you start
that way as root, or elevated on Windows, is refused unless
`machine.allow_root` is set, and warns at start when it runs
([root and administrator](platforms.md#root-and-administrator)).

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
   that commands from a center then run as root.
4. Copies the program to `/usr/local/bin/nerve-node`.
5. Writes the unit `/etc/systemd/system/nerve-node.service`, enables it and
   starts it. It waits until the node answers.

When the settings of an earlier install keep the keys in the system keyring
([keys](config.md#where-the-node-keeps-its-keys)), `install` first checks
that a keyring answers for `nerve`. In a terminal it offers to install one;
otherwise, and on a no, it stops before it starts the service. It then leaves
the account of the commands to `setup`.

Running `install` again repairs what is missing and restarts the service.

| What | Where |
|---|---|
| `node.toml`, one key per center | `/etc/nerve` |
| Audit log, [log](logs.md), control socket, config key | `/var/lib/nerve/state` |
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
`disk`. `install` and `setup` warn about such an account. Choose one
outside these groups, or a command can read the keys after all.

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
   keyring that answers, it offers to install one.
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

## The rules for these commands

- `install`, `setup`, `update` and `uninstall` are refused from a command the
  node runs for a center, as every other change of the node's settings is.
  An agent cannot install, update or remove the node.
- Each is written to the [audit log](audit.md) with the steps it did, and the
  error that stopped it, if any. `uninstall --purge` deletes the log with the
  rest.
