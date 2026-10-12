# Policy on a node

What a node allows is set on the machine with `nerve-node`. This page lists the
commands. [`spec/node-local.md`](../spec/node-local.md) explains how a call is
decided; `nerve-node --help` lists every command.

Start the node first (see [Run](../README.md#run) in the README):

```sh
nerve-node center add 'nerve://pair?center=...&code=...&pin=...'
nerve-node run      # stays in the foreground; run the commands below in another shell
```

## Starting point

A new center starts in `allowlist` mode (default deny) with no rule, so every
call is refused at once: nothing waits for an answer. Either allow what you
want, or give it full access in some folders and deny the commands you never
want to see.

## Modes

| Command | What it does |
| --- | --- |
| `nerve-node mode set folder` | Full access in the folders below. |
| `nerve-node mode set user` | Full access as the user (`--for N`: only for N hours). |

Without one of these, the node stays in `allowlist` mode.

## Allow rules

Allow rules count in `allowlist` mode only.

| Command | What it does |
| --- | --- |
| `nerve-node rule add allow 'git status'` | Allowlist mode: this command may run. |
| `nerve-node rule add allow 'git status' --wildcard` | The same, and `git` with anything after. |
| `nerve-node config add center.lab.policy.allow 'fs.read:~/notes/*'` | Allows a path. `lab` is the center's name (`center ls`). |
| `nerve-node rule ls allow` | Shows the allow list. `rule ls` shows all three lists. |
| `nerve-node rule rm` | Takes one rule off. |

## Folders

| Command | What it does |
| --- | --- |
| `nerve-node folder add ~/proj +r +w +x` | Adds a folder: read, write, run commands; any mix. |
| `nerve-node folder set ~/proj -w` | Changes a folder's rights, chmod style: `=rwx`, `+x`, `-w`, left to right. |

## Deny rules

| Command | What it does |
| --- | --- |
| `nerve-node rule add deny 'rm *' --wildcard` | Refuses command lines that start with `rm`, in every mode. |

Deny rules count in every mode. A deny rule matches the whole command line. It
does not see `rm` inside `x; rm …`, `/bin/rm`, a script or another program
that deletes files. In folder and user mode it guards against mistakes; it is
not a sandbox.

## Audit and panic

| Command | What it does |
| --- | --- |
| `nerve-node audit` | Shows what was allowed and refused. |
| `nerve-node panic` | Ends every link. `unlock` undoes it. |

## Sudo

Sudo is a switch per machine, off by default. While it is off, no command runs
with sudo, whatever the rules say. Switched on (the node checks the password
with `sudo -v` and keeps it in memory only), a sudo command runs only when the
sudo allow list names it, in every mode.

| Command | What it does |
| --- | --- |
| `nerve-node rule add sudo 'sudo apt update'` | A sudo command goes on its own list. |
| `nerve-node sudo on` | Asks for the password; needs `nerve-node run` (Linux only). |

## Letting a center change settings

A center the machine granted settings write may switch sudo as well; the
password then travels sealed from the browser to the node.

| Command | What it does |
| --- | --- |
| `nerve-node center grant settings write` | The center may now change this machine's rights for itself (up to user mode and sudo). |

## Changing `node.toml`

Change settings with `nerve-node`, not in an editor: the node signs
`node.toml` and refuses a file changed by hand.

| Command | What it does |
| --- | --- |
| `nerve-node config accept` | Takes a hand-edited `node.toml`, after you have looked at it. |

## Linux and Windows

| System | How commands are confined |
| --- | --- |
| Linux | Folder mode runs commands under Landlock. |
| Windows | Commands in `allowlist` and `user` mode run in Windows PowerShell 5.1, each owned by a Job Object that ends all of its processes with it, but not confined to folders. Folder mode runs no command there until a file confinement exists. |

On Windows the node has no control socket, no sudo switch and no sandbox, so a
command the node runs can change its policy (see
[`spec/node-local.md`](../spec/node-local.md) §5).
