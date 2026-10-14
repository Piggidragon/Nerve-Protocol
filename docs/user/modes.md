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

## What a command can reach in `folder` mode (Windows)

Each pairing's commands run in an AppContainer of their own. A new pairing
gets a new one, also when you pair the same center again under the same
name. Windows lets a
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
  takes it off. That is the node's entry on the folder: permissions a
  command gave what it made there stay (see "What the AppContainer does not
  stop" below). A running node takes changes from the CLI at its next start
  ([platforms](platforms.md#no-control-socket)), and gives its folders their
  entries again until then.
- `uninstall` takes off the entries of the node in your own folders (not
  those of a folder that holds hard links the check refuses, see below)
  (`%USERPROFILE%\.config\nerve` and `.local\state\nerve`, or those you name
  with `--config-dir` and `--state-dir`). Once a service is installed, the CLI
  reaches the service, so name the folders to change the node you run
  yourself. Before you delete its folders, remove its pairings: the record of
  the entries is in its state folder.
- A granted folder you move or rename on the same drive takes its entry
  along, as Windows keeps its permissions. At its next sync (at start, on a
  change, before a command, and when the CLI changes the config) the node
  finds it by its file ID and takes the entry off where it is now, also on a
  drive mounted in a folder. A granted folder you delete and make again gets
  its entry back at the next sync. One on a drive that is not connected keeps
  its entry until the drive is back; `uninstall` names those it leaves on.
- A file or folder you move out of a granted folder on the same drive keeps
  the entry it inherited. `icacls <path> /reset` gives it the permissions of
  its new place.
- The flags stay independent: `w` without `r` writes but neither reads nor
  lists, `x` runs programs and reads files by name but does not list. Hard
  links and the permissions a command gives what it makes are the
  exceptions, see "What the AppContainer does not stop" below.
- Deleting and renaming need `r` and `w`, since Windows allows a move with
  the same right as a delete: a command must not move what it cannot read
  to a folder where it can. So in a folder with `w` but not `r`, a command
  adds and changes files, but does not delete, rename or move any. A
  granted folder or file itself is deleted, renamed or moved only through
  the folder above it, with `r` and `w` there; on Linux too that needs a
  right on the folder above.
- A folder you grant inside another granted folder with `w` gets its entry
  only while it is a folder of its own there: not a junction or link to
  another place, not a file with a second name (a hard link), and with
  permissions that inherit. A command may write there, so it could put a
  junction in its place, and the entry would land on the folder it leads
  to. This holds for a folder inside a `w` folder of any pairing. The node
  names such a folder in its log (`left out of the command's sandbox: it
  passes through the link …`) and grants it once it is a plain folder again.
  A junction of yours that leads into the `w` folder is followed to its end
  and judged on the way. One gap is
  left here: if a command makes such a junction while the outer folder has
  `w`, and you then take the `w` off that folder (narrow it to `r`, or
  remove the pairing it belongs to), the node no longer knows commands could
  write there and follows the junction again. Before you take `w` off a
  folder or remove a pairing, check it for junctions and links
  (`dir /AL /S <folder>`). A fix that remembers the place you judged when
  you added the folder is tracked in #77.
- The node's own folders and the [protected paths](protected-paths.md) get no
  entry, also inside a folder you grant. That folder is granted as its other
  entries instead, as on Linux.
- PowerShell starts on a drive `Work:` that is the working folder, because the
  container may not look at the folders above it. Relative paths, whole paths
  and native programs work as usual. `cd` and `pushd` to the whole path of a
  folder the command may see, or with `..` up out of the working folder into
  one, put PowerShell on a drive of that folder (`Work2:`, `Work3:`, …), and
  native programs start in the folder itself. These drives open nothing; the
  container decides what the command reaches. `cd` to a folder the command
  may not see fails as any other access does, also with `..`: PowerShell stays
  where it was, `$?` is false, and a command that ends with that `cd` fails.
- The command has the network, but not `localhost`, and no folder for
  temporary files. It has its own desktop, so it cannot reach your windows or
  clipboard.
- What the AppContainer does not stop: what Windows opens to every
  AppContainer (reading the system folders, the network), and work a command
  gets another program outside the container to do for it, such as a service
  or the task scheduler.
- A command sets the permissions of a folder or file it makes, as every
  Windows program may, so it can give them an entry of its own, of three
  kinds: for its pairing's container (`S-1-15-2-…`), for all AppContainers
  (`ALL APPLICATION PACKAGES`, `S-1-15-2-1`), or for a capability that
  every pairing's container has (`S-1-15-3-1`, `-2` and `-3`, which
  `icacls` shows as `APPLICATION PACKAGE AUTHORITY\Your …`). The node
  neither sees nor removes these. They stay when you remove the folder,
  change its flags, remove the pairing or run `uninstall`. An entry for the
  container belongs to that pairing: no later pairing runs in that
  container, also not one of the same center or under the same name. The
  other two kinds count at once, for every pairing of the
  node and for every app on the machine that runs in an AppContainer (for
  a capability: every such app that has it). In a
  folder with `w` but not `r`, a command can make a folder that lets it
  read what you or another pairing save into it later. So do not save
  files a pairing must not read into a folder where it may write. After you
  take `w` off a pairing's folder or remove the pairing, clean the folder.
  Only `icacls <folder> /reset /T` removes all of them with certainty; it
  also resets permissions of your own below the folder. To keep those,
  find the entries with
  `icacls <folder> /T | findstr /C:"S-1-15-" /C:"APPLICATION PACKAGE"` and
  remove each with `icacls <folder> /remove *<SID> /T`: every `S-1-15-2-…`
  and `S-1-15-3-…` entry, and `ALL APPLICATION PACKAGES` as `*S-1-15-2-1`.
- A hard link is one file under two names, and both share one access list.
  When the node grants, changes or moves a folder that commands may write
  in, or a folder that holds one, Windows passes the change to everything
  below it, and that includes hard links. Before such a change the node
  checks the folder and refuses if a file below it has more than one name.
  A command of any pairing that may write in that folder can still make a
  link between the check and the change, and the file it links then gets
  the folder's rights. Hard links only work within one drive. So put a
  write-only folder whose files commands must not read on a drive where the
  pairing can write nowhere that it can also read or run programs, also
  through a folder above.
- Build tools make hard links of their own. cargo builds each program
  under two names in `target`, so a file in a folder named exactly `target`
  inside the folder passes the check when every one of its names lies in
  such a folder of the same granted folder, under the same grants, no
  pairing has `w` without `r` on that folder, one above it or one inside
  it, and the node finds no granted folder moved or renamed in that sync.
  (A command may give a folder it makes permissions of its own, and the
  change would pass them to a file it linked there; the check keeps a file
  it may only write from getting them this way.) So a built
  Rust project you rename or move needs `cargo clean` before its entry can
  come off at its new place; until then the record of the entry stays stale
  and that pairing's commands stop. Any other
  second name is still refused, also a `target` file whose other name lies
  outside the folder or under another grant, and one whose names Windows
  cannot list. Other tools' links are refused too: pnpm links
  `node_modules` to its store, uv links a `.venv` to its cache, and a local
  `git clone` links its objects. A folder that holds such links does not get
  its entry, and its entry is not changed or taken off. A refused removal
  stops that pairing's commands, and `uninstall` leaves the entry on, until
  the links are gone. Keep them out of granted folders: pnpm's
  `package-import-method=copy`, `UV_LINK_MODE=copy`, `git clone
  --no-hardlinks`. Or remove them (delete `node_modules` or `.venv`) before
  you add, change or remove the folder.

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
