# Settings and `node.toml`

Every setting of a node is in one file, `node.toml`, in the node's config
folder ([where](install.md#where-files-live)). The commands in this guide
change it for you. `nerve-node config` reaches any setting by its name.

## Read and change by name

A name is a dotted path. A center's settings are under `center.<name>`, where
`<name>` is the name from `nerve-node center ls`.

```sh
nerve-node config get center.lab.policy.mode
nerve-node config set center.lab.policy.mode folder
nerve-node config add center.lab.policy.allow 'fs.read:~/notes/*'
nerve-node config remove center.lab.policy.allow 'fs.read:~/notes/*'
nerve-node config unset limits.max_running
nerve-node config get center.lab          # a whole table
```

| Command | Does |
|---|---|
| `config get <key>` | Print one setting or a table |
| `config set <key> <value>` | Change a setting |
| `config unset <key>` | Remove it, so its default applies |
| `config add <key> <value>` | Append to a list |
| `config remove <key> <value>` | Remove a value from a list |
| `config accept` | Take a file you edited by hand |

A value that does not fit the setting is refused, and nothing changes.

## The settings

```toml
[node]
name = "laptop"             # shown to centers; the host name by default

[machine]
shell = "/bin/bash"         # runs commands; the platform shell by default
allow_root = false          # let the node run as root, or elevated as administrator on Windows
sudo_path = "/usr/bin/sudo" # optional
user = "alice"              # installed node: the account commands and sudo run as
secret_storage = "file"     # file | keyring: where the node keeps its keys

[limits]
max_running = 16            # commands at once, over all centers
output_cap_bytes = 16777216 # for stdout and for stderr each; a result carries 1 MiB at most

[connection]
proxy = "http://proxy:3128" # set with `nerve-node proxy set`

[log]
level = "info"              # error | warn | info | debug: how much the node logs

[[center]]
name = "lab"
url = "https://lab.example:7443"
settings = "off"            # off | write: the settings grant
paused = false

[center.policy]
mode = "allowlist"          # allowlist | folder | user
until = 1790000000000       # optional end of folder or user mode, ms since the epoch
folders = [{ path = "/home/u/proj", access = "rwx" }]
caps = { "fs.write" = "off" }
allow = ["exec.run:git status", "fs.read:~/notes/*"]
deny = ["fs:~/private/*", "exec.run:rm *"]
sudo_allow = ["sudo apt update"]
protected = { extra = [], allow = [] }
```

The file also holds a `version` that grows with every write, `locked`
(set by `panic`), and per center the `url`, `pin`, `center_id` and `node_id`
the pairing filled in. Unknown keys are refused.

## Do not edit the file by hand

The node signs `node.toml`: the first line is a MAC. It rereads the file only
when you ask. A file with a missing or wrong MAC was changed outside
`nerve-node`, so the node refuses it:

- At start the node does not start.
- On a reload the old settings stay.

The message is:

```
node.toml is refused: its MAC does not match, so it was changed outside nerve-node; check it, then `nerve-node config accept` takes it as it is
```

Read the file first. Then take it:

```sh
nerve-node config accept
```

The node signs it and uses it.

The key for the MAC is `config.key` in the node's state folder, or in the
system keyring ([below](#where-the-node-keeps-its-keys)). A command that
runs as you (in `user` mode) can reach it in either place. The check protects against
`folder` mode commands and against centers, not against `user` mode. On a
node installed as a service, commands run as another account
([service](service.md#the-account-commands-run-as)) and cannot reach it.

## Where the node keeps its keys

The node has a key per center and the key for the MAC above.
`machine.secret_storage` says where they are:

- `file` (the default): files only the node's user can read, `keys/` in the
  config folder and `config.key` in the state folder.
- `keyring`: the system keyring, the Credential Manager on Windows and the
  Secret Service (GNOME Keyring, KWallet) on Linux. No copy stays in a file.
  Not on the node installed as a service on Windows: it runs as `nerve`,
  whose Credential Manager the commands you run as an administrator cannot
  reach, so it keeps its keys in files
  ([service](service.md#windows)).

```sh
nerve-node config set machine.secret_storage keyring
nerve-node config set machine.secret_storage file
```

The change moves the keys at once: each is copied, read back, and only then
deleted where it was. If the keyring cannot take them, nothing changes. On
Windows, while the node runs, the old copies stay until its next start. On
Linux, a node that runs but does not answer on its control socket (it is
still starting, say) keeps its keys in files until it is restarted, so
`config set` refuses to move them into the keyring then: stop the node, or
wait until it has started, and set it again.

A keyring hands its entries to any program of the node's user that asks,
through the user's D-Bus session. So with `keyring` on Linux the node keeps
centers out of that session's folder (`/run/user/<uid>`) and out of GNOME
Keyring's folder (`~/.local/share/keyrings`), as it does with its own
folders. A `folder` mode command cannot connect to the session either: from
Linux 7.1 on (Landlock ABI 9) Landlock refuses that. An older kernel cannot,
so there `folder` mode runs no command while the keys are in the keyring,
unless commands run as another account than root
([service](service.md#the-account-commands-run-as)), which cannot reach the
session of the node's user. The node then logs a warning, `nerve-node
status` prints `folder mode runs no command: …`, and `config set` and
`setup` say so when they move the keys. `file` brings the commands back.

A command keeps the sandbox it started with. So while a `folder` mode
command that started with the keys in files still runs, the keys do not go
into the keyring: `config set` and `setup` say how many such commands run,
and nothing changes. Wait until they end, or end every command with `nerve-node panic`,
set `keyring`, then `nerve-node unlock`. Commands that run as another
account than root do not count, as they cannot reach the session.
A process that a command takes out of its process group (`setsid`) outlives
the command and is not counted. If a center you do not trust had `folder`
mode while the keys were in files, restart the machine before you set
`keyring`.

The keyring is kept from `folder` mode commands only. An `allowlist` or
`user` mode command runs without Landlock, and a command that talks to the
Secret Service needs no path to read the keys. With `keyring`, an allow
rule for `secret-tool`, `busctl --user`, `gdbus`, `dbus-send` or the like
hands a center every key of the node, which with `file` it could not read.
Do not allow such a tool to a center, or keep the keys in files.

With `keyring`, the node needs a keyring that answers. Without one it does
not start, and `status` and the other commands that read the settings say:

```
machine.secret_storage is "keyring", but the system keyring cannot be reached (entry …): …
```

The node never falls back to the files. Start the keyring, or on a Linux
without a desktop, let `setup` install one.

### A keyring on a Linux without a desktop

A server without a desktop usually has no keyring. When you choose `keyring`
in `nerve-node setup` (on the installed node, `sudo nerve-node setup`), or
the settings say `keyring` and no keyring answers, setup asks:

```
No system keyring answers for nerve: ….
nerve-node can install GNOME Keyring: `apt-get update`, `apt-get install -y gnome-keyring dbus-user-session`, `loginctl enable-linger nerve`, so that nerve keeps a session after a reboot, and a login keyring for nerve that opens without a password.
Without a desktop nobody types a password when the machine starts, so this keyring keeps the keys unencrypted in /var/lib/nerve/.local/share/keyrings, readable by nerve as the key files are; the node keeps centers out of it as it does out of the key files, except a command you let a center run outside folder mode that asks the keyring itself (secret-tool and the like). It becomes the default keyring of nerve: any other program of nerve that keeps a secret in the system keyring keeps it there, unencrypted too.
Install it now? [y/N]
```

Enter or `n` installs nothing, and the keys stay in their files (or the node
keeps refusing, when the settings say `keyring`). `y` installs GNOME Keyring
with the system's package manager (apt, dnf or pacman), keeps a session for
the node's user from boot on, makes a login keyring for it without a
password, and checks that it answers. `install` asks the same when an
earlier install's settings say `keyring` and it runs in a terminal.

Setup offers this only where the user has no desktop session. On a desktop,
start the desktop's keyring instead (GNOME Keyring, or KWallet with its
Secret Service on).

A node that runs and found no keyring before does not look for one again
until it restarts. After installing one, setup restarts the installed node.
For a node you run yourself, setup stops and asks you to restart it, then to
run setup again.

Such a keyring survives a reboot, but as the question says, it keeps the
keys unencrypted on disk, as safe as the files. Whether a server should
keep its keys there is your call; the default stays `file`.

## When a change applies

While `nerve-node run` is running, a change applies at once. Without a running
node, the command says:

```
the change is in node.toml; it takes effect at the next start of the node
```

On Windows the node has no control socket, so a running node always takes a
change at its next start.
