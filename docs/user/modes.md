# Modes and folders

Every pairing has a mode. It sets how much that center may do on the machine.

| Mode | What is allowed | Commands |
|---|---|---|
| `allowlist` (default) | Only what an [allow rule](rules.md) names | Run as the rule says |
| `folder` | Full access inside the folders you grant, by their rights | Confined to those folders |
| `user` | Everything you could do yourself | Not confined |

[Deny rules](rules.md#deny-a-command) and [protected paths](protected-paths.md)
apply in every mode. A call that nothing allows is refused at once. Nothing
waits for an answer.

## Set the mode

```sh
nerve-node mode set allowlist
nerve-node mode set folder
nerve-node mode set user
```

`folder` and `user` stay until you change them. To set a time limit, add
`--for` with hours. When it ends, the pairing goes back to `allowlist`, not to
`folder`.

```sh
nerve-node mode set user --for 2
```

`--for` needs at least 1 and does not go with `allowlist`. Setting a mode
again without `--for` removes an earlier limit.

## Folders

A folder gives rights. Each right is its own flag:

| Flag | Allows |
|---|---|
| `r` | Read: `fs` stat, list, read, grep, find |
| `w` | Write files |
| `x` | Run commands whose working directory is in the folder |

The flags do not imply each other. A write needs `w` and not `r`. A read needs
`r` and not `w`. A command needs `x` and not `r`. A folder covers everything
below it. Where folders nest, the deepest one decides.

Folders count in `folder` mode only.

| Command | Does |
|---|---|
| `nerve-node folder add ~/proj +r +w +x` | Add a folder. Name at least one right |
| `nerve-node folder set ~/proj -w` | Change rights, like `chmod`: `+x` adds, `-w` removes, `'=rx'` sets exactly. Applied left to right |
| `nerve-node folder rm ~/proj` | Remove the folder |
| `nerve-node folder ls` | List folders and rights |

Quote `'=rx'` so zsh leaves it alone. `folder add` on a path that is listed
already replaces its rights. `folder set` leaves a folder with no rights in
the list. `folder rm` removes it.

## What a command can reach in `folder` mode (Linux)

The node confines commands with Landlock:

| A command can | Where |
|---|---|
| Read | the system folders (`/usr`, `/bin`, `/lib`, `/etc`, `/opt`, `/proc`, `/sys`, `/dev`, `/run` and similar) and the `r` folders |
| Write | the `w` folders and the null and terminal devices |
| Run programs | the system folders and the `x` folders |

- A folder with `w` and no `r` can be written but not read or listed by a
  command.
- Landlock cannot run a file it may not read. So an `x` folder also lets a
  command read files there by name. It still cannot list the folder.
- The node's own folders are in none of these sets.
- On a node installed as a service the command runs as the account
  commands run as ([service](service.md#the-account-commands-run-as)), and
  what that account may not open stays closed as well. Landlock only takes
  away; it gives the account nothing it lacks.

Check that your kernel supports it, with the node running:

```sh
nerve-node status
```

The first line reads `daemon: running (confinement landlock v…)`. With
`confinement none` the node cannot confine commands, so `folder` mode refuses
every command.

## What a command can reach in `folder` mode (Windows)

Each pairing's commands run in an AppContainer of their own. Windows lets a
process there open only what is granted to that container, and what it opens
to every AppContainer. This holds for a node you run yourself. The
[installed service](service.md#windows) runs every command as another account,
and does not start the AppContainer as that account yet: there `folder` mode
runs no command (`confinement none`), and the service puts no grants on
folders.

| A command can | Where |
|---|---|
| Read and run programs | the Windows folder and Program Files |
| Read, write, run programs | each folder by its rights |

- The node gives each folder a permission entry for the pairing's container,
  with the folder's rights. Everything below the folder inherits it. Adding a
  large folder takes as long as changing its permissions with `icacls`.
- `folder rm` and `folder set` change the entry, and removing the pairing
  takes it off. A running node takes changes from the CLI at its next start
  ([platforms](platforms.md#no-control-socket)), and gives its folders their
  entries again until then.
- `uninstall` takes off the entries of the node in your own folders
  (`%USERPROFILE%\.config\nerve` and `.local\state\nerve`, or those you name
  with `--config-dir` and `--state-dir`). Once a service is installed, the CLI
  reaches the service, so name the folders to change the node you run
  yourself. Before you delete its folders, remove its pairings: the record of
  the entries is in its state folder.
- A granted folder you move or rename on the same drive takes its entry
  along, as Windows keeps its permissions. At its next sync (at start, on a
  change, before a command, and when the CLI changes the config) the node
  finds it by its file ID and takes the entry off where it is now. A granted
  folder you delete and make again gets its entry back at the next sync.
- A file or folder you move out of a granted folder on the same drive keeps
  the entry it inherited. `icacls <path> /reset` gives it the permissions of
  its new place.
- The flags stay independent: `w` without `r` writes but neither reads nor
  lists, `x` runs programs and reads files by name but does not list.
- The node's own folders and the [protected paths](protected-paths.md) get no
  entry, also inside a folder you grant. That folder is granted as its other
  entries instead, as on Linux.
- PowerShell starts on a drive `Work:` that is the working folder, because the
  container may not look at the folders above it. Relative paths and native
  programs work as usual. `cd` to a whole path above the folder does not.
- The command has the network, but not `localhost`, and no folder for
  temporary files. It has its own desktop, so it cannot reach your windows or
  clipboard.
- What the AppContainer does not stop: what Windows opens to every
  AppContainer (reading the system folders, the network), and work a command
  gets another program outside the container to do for it, such as a service
  or the task scheduler.

`nerve-node status` cannot ask the running node on Windows
([platforms](platforms.md#no-control-socket)). The node names its
confinement when it starts, in its output and its [log](logs.md):
`node daemon running (…, confinement appcontainer, …)`. The center sees it in
the node's `exec` state, `confinement appcontainer`, or `none` on the
installed service.

## `user` mode

`user` mode allows everything you could do yourself, except
[protected paths](protected-paths.md). Commands run as your user, without
confinement. A command can do what you can do, including changing the node's
own state. Use it only for a center you would trust with a shell.

On a node [installed as a service](service.md#the-account-commands-run-as)
the node runs as its own user, `nerve`, and commands in every mode run as
the account you chose at `install` or `setup` instead. In `user` mode they
can do what that account can do, and cannot read the node's keys or change
its state, unless that account can become root (root itself, or a member
of a group such as `docker`; see
[the account commands run as](service.md#the-account-commands-run-as)). In `folder` mode they are the same account, held to their
folders.

## Which mode

| You want | Use |
|---|---|
| The agent may run a few known commands | `allowlist` with [rules](rules.md) |
| The agent works freely in a project folder | `folder` with one folder `+r +w +x` |
| The agent acts as you | `user`, maybe with `--for` |
