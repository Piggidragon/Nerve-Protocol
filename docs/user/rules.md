# Rules

Rules say which calls are allowed and which are refused. Each pairing has
three lists.

| List | Counts in | Does |
|---|---|---|
| `allow` | `allowlist` mode only | A matching call may run |
| `deny` | every mode | A matching call is refused. A deny rule beats every other rule and mode |
| `sudo` | every mode, while [sudo](sudo.md) is on | A matching `sudo` command may run |

In `folder` and `user` mode, allow rules do nothing. The mode decides.

## Allow a command

```sh
nerve-node rule add allow 'git status'
nerve-node rule add allow 'git status' --wildcard
```

The first allows that exact command line. The second allows `git` with
anything after it. A rule applies to one command line, so `git status` does not
allow `git status --short`. Use `--wildcard` for that.

## Deny a command

```sh
nerve-node rule add deny 'rm' --wildcard
nerve-node rule add deny 'git push origin main'
```

A deny rule matches the whole command line. It does not see `rm` inside
`x; rm …`, in `/bin/rm`, in a script, or in another program that deletes
files. In `folder` and `user` mode it guards against mistakes. It is not a
sandbox.

## The guard against changing the node

Every new pairing starts with deny rules that keep its commands off this
node itself: a command that runs `nerve-node` or `nerve-node-desktop` (at
the start of a command, after `sudo`, or by a path, `.exe` too), a command
line that names the node's socket or pipes or its config and state folders
(`/etc/nerve`, `/var/lib/nerve`, `~/.config/nerve`, `~/.local/state/nerve`,
`%ProgramData%\Nerve`), a write into those folders, and a command that
stops, restarts, disables or kills the node's service or process by its name, as the node's own `service stop` would.
The name alone is not refused: `cargo build -p nerve-node` and
`journalctl -u nerve-node` run. `rule ls deny` shows them; remove any you do
not want.

| | Refused | Still runs |
|---|---|---|
| Linux | `systemctl stop`, `restart`, `try-restart`, `reload-or-restart`, `disable`, `kill` or `mask` on `nerve-node` (or `nerve-node.service`); `service nerve-node stop`, `restart`, `try-restart`, `force-reload` or `condrestart`; `pkill` or `killall` on `nerve-node` or `nerve-node-desktop`, with flags such as `-9`, `-f` or `-x`. With or without `sudo`, a path to the program, or flags such as `--now` | `systemctl status`, `is-active`, `show`, `cat` on it, `service nerve-node status`, `journalctl -u nerve-node`, `pgrep`, `ps` |
| Windows | `sc stop`, `config` or `delete`; `net stop`; `Stop-Service`, `Restart-Service`, `Set-Service` or `Remove-Service`; `Stop-Process -Name`; `taskkill` with `nerve-node.exe` or `nerve-node-desktop.exe`; `Get-Service` or `Get-Process` on the node piped into one of the cmdlets | `sc query`, `sc qc`, `Get-Service nerve-node`, `Get-Process nerve-node` |

The Windows commands match in any case (`STOP-SERVICE`, `NET STOP`,
`sc stop Nerve-Node`, `taskkill /IM NERVE-NODE.EXE`), as Windows reads them.
The rules see a line break or a tab after a name or before a command as they
see a space or `;`, so the second line of a script counts, with its indent.
That holds for the rules that name the node's programs, sockets and folders
too. A rule with such a character is listed with `\t`, `\r` and `\n` written
out, so `rule ls` and the app's rule lists keep one line a rule, and `rule rm`
and `rule edit` take the entry as it is listed there (the new entry of `rule
edit` too).

The rules match the whole line, so some lines are refused that only mention
the node: a line that stops some other service and names `nerve-node` later,
and a quoted text with `;`, `|` or `(` in front of a command's words
(`git commit -m "Docs (Stop-Service nerve-node)"`). A quoted mention is
otherwise left alone: `sudo` counts only at a command's start, so
`git commit -m "run sudo systemctl stop nerve-node"` runs. The rules do not
read `kill` with a process id (`kill $(pidof nerve-node)`), `pkill nerve` as
a part of the name, or `sudo` behind another program (`env X=1 sudo ...`).

```sh
nerve-node rule guard --center lab   # puts back the ones a pairing lacks
```

A pairing made before the guard has none: `rule guard` adds them, and the
desktop app offers it on **Permissions**. It also takes off the older text of
a rule that the guard has changed, and puts the new one in its place.

The guard catches an agent's mistakes, such as an agent that tries to give
itself more rights. It does not stop a command written to get around it (a
name built at run time, a copy of the program). The real protection is that
commands run as an account of their own, which may not change the node
([service](service.md)), and the node's own folders, which no rule or mode
opens ([protected paths](protected-paths.md)).

## List, change and remove rules

```sh
nerve-node rule ls            # all three lists
nerve-node rule ls allow
nerve-node rule edit allow 'exec.run:git status' 'git status --short'
nerve-node rule rm allow 'git status'
nerve-node rule rm allow 'git status' --wildcard
```

`rule edit` changes one entry in its place, as one change in the audit: the
entry as `rule ls` prints it, then what it becomes. That is an entry in the
same form (`'exec.run:git *'`, `'fs.read:~/notes/*'`), or a plain command
line, which becomes the rule `rule add` makes of it. It works on every list,
and on the rules of the guard too. The desktop app's Permissions page edits a
rule the same way (the pencil beside it).

`rule rm` takes the same arguments as `rule add`. It also takes an entry as
`rule ls` prints it, such as `'exec.run:git *'`. When the arguments could mean two entries on the list, `rule rm`
removes none and tells you the two commands that remove them one after the
other.

## Rules for files and other actions

`rule add` writes command rules, and refuses an entry in the pattern form
(`fs.read:...`, `fs:...`, and also `exec.run:...` and `exec:...`, the form
`rule ls` prints), which would never match as a command. Give `rule add` the
bare command (`'git *'`), not that form. (`rule rm` does take it.) For files and
other actions, add the rule to the policy by name. `lab` is the center's name on this machine (see
`nerve-node center ls`).

```sh
nerve-node config add center.lab.policy.allow 'fs.read:~/notes/*'
nerve-node config add center.lab.policy.deny  'fs:~/private/*'
```

The web UI's [Audit](web-ui.md#audit) page writes the same rules with four
buttons. That needs the [settings grant](settings-grant.md).

`--action` makes the rule such a button makes for an audit entry of that
action: the entry's path, or the folder it is in with `--wildcard`. An action
without a path takes `''`, and covers its capability with `--wildcard`.

```sh
nerve-node rule add allow /srv/data/report.txt --action fs.read
nerve-node rule add deny /srv/data/report.txt --action fs.write --wildcard   # fs.write:/srv/data/*
```

## Rule syntax

A rule is `<scope>` or `<scope>:<pattern>`.

- The scope is a capability (`fs`, `exec`) or one action (`fs.read`,
  `exec.run`).
- The pattern is a glob over the call's target. `*` matches across `/` and
  spaces.
- Without a pattern the rule covers every target of its scope.
- A pattern ending in ` *` also matches the bare program. One ending in `/*`
  also matches the folder itself.

| Target of | Is |
|---|---|
| `exec.run` | The whole command line |
| every `fs` action | The resolved path. `~/` is your home. On Windows the form is `/c/Users/x` |
| any other action | `<cap>.<action>` |

| Rule | Covers |
|---|---|
| `exec.run:git status` | That command line, exactly |
| `exec.run:git *` | `git` and anything after it |
| `fs.read:/home/u/notes/*` | Reading the folder and below (not `list` or `grep`) |
| `fs:~/private/*` | Every `fs` action on the folder and below |
| `exec` | Every `exec` action, so every command |

Commands and paths never mix: `fs:/tmp/*` is not a command rule. An unknown
rule shape is refused when you add it.

## What a wildcard covers

A wildcard allow rule covers plain commands only. A command is plain when it
has none of these:

- shell characters: `; & | $ ` ( ) < > @ { } % ' " # , \`
- a line break or another control character
- a word that starts another shell or runs text as code, such as `powershell`,
  `pwsh`, `cmd`, `sh`, `bash`, `eval`, `iex`, `Invoke-Expression`,
  `Start-Process`, `-Command`, `-EncodedCommand`, `-File`, `/c`, `/k`

Only an allow rule that names the whole line covers such a command. This keeps
`git *` from allowing `git x; rm -rf ~`. A Windows path with `\` needs an exact
rule, or `/` in the path.

## Switch a capability off

`cap set` turns a capability or one action on, off or hidden for a center.

```sh
nerve-node cap set exec.run off
nerve-node cap set fs hidden
nerve-node cap ls
```

| Setting | Effect |
|---|---|
| `on` | Normal. Rules and mode decide |
| `off` | Calls are refused with `disabled`. The center lists it as off |
| `hidden` | The node leaves it out of what it tells the center, and refuses it |

A capability is `fs` or `exec`. An action is `fs.write` or `exec.run`. A
switch applies in every mode.
