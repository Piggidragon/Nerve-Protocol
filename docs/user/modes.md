# Modes and folders

Every pairing has a mode. It sets how much that center may do on the machine.

| Mode | What is allowed | Commands |
|---|---|---|
| `allowlist` (default) | Only what an [allow rule](rules.md) names | Run as the rule says |
| `folder` | Full access inside the folders you grant, by their rights | Confined to those folders (Linux) |
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
- The node's own folders are in none of these sets. That keeps a command from
  the node's files, but only as far as Landlock reaches. While the commands
  run as the node's own user (a node you run yourself, with no `machine.user`),
  `folder` mode is no boundary against that user's other programs: a command
  can ask one that runs commands on request, such as the user's systemd session
  or a tmux server, to run a program outside the sandbox, and that program
  reads the node's files and changes its settings through the control socket.
  Run the commands as another account to keep them out: see
  [Linux](platforms.md#linux).
- A command with `w` on a folder can put a link in place of a folder inside
  it, and a link would give that folder's rights in a place you never named.
  So a folder is left out of the sets, and the node logs a warning, when its
  path passes through a link that lies inside a `w` folder (of any pairing).
  That holds for a link you made yourself too, and a link of yours that
  leads into the `w` folder is followed to its end and judged on the way.
  The folder is back once its path is a plain folder again. A link of your
  own above the `w` folder is followed. Two gaps are left:
  - Only the `w` folders in the config count. If a command made a link while
    the outer folder had `w`, and you then take `w` off it (narrow it to `r`,
    or remove the pairing), the node follows the link again. Before you do,
    look for links (`find <folder> -type l`). A fix that remembers the place
    you judged when you added the folder is tracked in #77.
  - A command that runs without Landlock (`user` mode, `sudo`, and what an
    `allowlist` rule allows) can make a link wherever you can write, also
    where no `w` folder is, and the folder of another pairing there follows
    it. Look for links in the folders you grant before you give a pairing one
    of those.
- With the keys in the system keyring, the node's D-Bus session and GNOME
  Keyring's folder count as its own, and a command cannot connect to a
  socket there ([keys](config.md#where-the-node-keeps-its-keys)). That needs
  Linux 7.1. On an older kernel the keys stay in files
  ([keys](config.md#an-older-linux-kernel)).
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
every command. A line `folder mode runs no command: …` says the same, and
why.

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
