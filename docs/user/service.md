# Run the node as a service

On Linux with systemd, `nerve-node` installs itself as a service. The service
starts with the machine and runs under a user of its own, `nerve`, which owns
the node's config and state folders. `install`, `update` and `uninstall` need
root. On Windows and on Linux without systemd, run `nerve-node run` under your
own service manager ([pairing](pairing.md#keep-it-running)).

## Install

Download and check the program ([install](install.md)), then run it once as
root:

```sh
sudo ./nerve-node-x86_64-linux install
sudo nerve-node setup
```

`install` does this, and says each step:

1. Makes the system user `nerve`, with its own group, no login and the home
   `/var/lib/nerve`. A `nerve` user that `install` did not make is refused.
2. Makes the folders, private to `nerve` (mode 0700). Folders an earlier
   install left behind are given to the new user.
3. Copies the program to `/usr/local/bin/nerve-node`.
4. Writes the unit `/etc/systemd/system/nerve-node.service`, enables it and
   starts it. It waits until the node answers.

Running `install` again repairs what is missing and restarts the service.

| What | Where |
|---|---|
| `node.toml`, one key per center | `/etc/nerve` |
| Audit log, [log](logs.md), control socket, config key | `/var/lib/nerve/state` |
| Home of `nerve`: a command's working folder when the call names none | `/var/lib/nerve` |
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

The commands a center runs on the node run as `nerve` as well. In `user`
mode such a command may do what `nerve` may do, not what your own account may
do.

## Setup

`sudo nerve-node setup` asks three things, one at a time. Enter keeps what is
in brackets.

1. The node's name, as centers show it. The host name by default.
2. A pairing link from the center's web UI. Enter skips it. The node shows
   the center and asks before it pairs, as `center add` does.
3. The mode of that center: `allowlist`, `folder` or `user`
   ([modes](modes.md)). For `folder` it asks for one folder and its rights.

Each answer is saved when you give it, through the running node, like every
other command. You can stop setup at any point and run it again. It works on
a node that is not installed as well.

## Update

```sh
sudo nerve-node update
```

`update` downloads the program for this machine from the latest release on
GitHub, checks it against the release's `SHA256SUMS`, puts it in place and
restarts the service. `HTTPS_PROXY` is used when it is set.
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
`nerve` and `/usr/local/bin/nerve-node`. Without `--purge`, `/etc/nerve` and
`/var/lib/nerve` stay and belong to root from then on, so no later user with
the old uid gets the keys. A later `install` takes them up again: the node
comes back with its pairings, rules and audit log. `--purge` deletes them,
keys and audit log included.

## The rules for these commands

- `install`, `setup`, `update` and `uninstall` are refused from a command the
  node runs for a center, as every other change of the node's settings is.
  An agent cannot install, update or remove the node.
- Each is written to the [audit log](audit.md) with the steps it did, and the
  error that stopped it, if any. `uninstall --purge` deletes the log with the
  rest.
