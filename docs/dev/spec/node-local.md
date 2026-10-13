# The node's own side: config, policy, control socket

This part is not wire protocol: a center never sees it directly. It describes
how `nerve-node` decides, so that other node implementations can behave the
same way and so the owner knows what each setting does.

## 1. Folders

| What | Default | Override |
|---|---|---|
| `node.toml` and one key per center | `~/.config/nerve` | `--config-dir`, `NERVE_CONFIG_DIR` |
| control socket `run/ctl.sock`, audit log `audit.jsonl`, log `log.jsonl`, the config's MAC key `config.key` | `~/.local/state/nerve` | `--state-dir`, `NERVE_STATE_DIR` |

A node that `nerve-node install` put on a Linux machine
([service](../../user/service.md)) runs as the system user `nerve` with
`/etc/nerve` and `/var/lib/nerve/state`; without `--config-dir`,
`--state-dir` and their variables the CLI uses those two folders, and a
command root runs on them runs as their owner, so that what it writes stays
the node's.

On that node `nerve` only holds the config, keys and state: every command
of a center, in every mode, runs as the account `machine.user` names (§2),
with that account's ids and groups, `HOME`, `USER` and `LOGNAME` set to it,
and its home as the working directory when the call names none. `folder`
mode differs from `user` mode only by its confinement: the same account,
held by Landlock to its folders (§Modes), with the account's home as the
`~` of those rules. The sudo switch uses the account too (§4). `install`
sets it to the account that ran `sudo` (root when there was none), unless
one is set; `setup` chooses another and can make one (`useradd`, a group
and a home of its own, no login shell). The account must exist and must not
be `nerve`; with none set, or one that cannot be used, no command runs
(`unavailable`), after its call was decided and audited. Before a command
starts, in the child, the node checks with `access()` that the account can
neither list nor enter the config and state folders, and refuses to run it
if it can. Root is allowed: `install` and `setup` warn that commands of a
center then run as root, keys included, and that the owner is responsible;
root's command runs without `no_new_privs`, so it has root's rights (in
`folder` mode the shim still sets it with Landlock).

For this the service keeps one privilege: `CAP_SETUID` and `CAP_SETGID`
(`AmbientCapabilities=` in the unit), and nothing else. The owner chose it,
so that commands run as a real account that cannot read the node's keys.
Every command the node starts drops every capability, ambient and
inheritable ones included, before exec; the bounding set is not narrowed,
since an allowed sudo command needs root's. The node signals a command of
another account from a child that takes that account's uid, since it has no
`CAP_KILL`; the child changes only its effective uid, so the account's
processes cannot signal it, and the node waits for it two seconds at most.
The `fs` actions of a center, and the path checks of every call (resolving
paths, the protected list, the folders), are done by the node itself, on
the calling thread under the account's file-system uid and gid and its
groups (`setfsuid`, `setfsgid`, and `setgroups` as a plain system call, all
per thread on Linux); the audit entry is written as `nerve` again. So a
file the node makes for a center belongs to the account, and `~` in rules
and in the protected list is the account's home. With root as the account
the file-system ids are root's without root's capabilities
(`CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`), so these checks
and the `fs` actions reach only what root owns or what the permission bits
open to others; a command itself is really root. The CLI, which
runs as `nerve` on the installed node, keeps a folder it may not look into
in its normal form (`folder add`), unresolved. A node not installed as a
service runs commands as its own user and refuses a `machine.user` it
cannot switch to. The installed node is known by its folders or its user,
not by its capabilities: started without them (by hand, as `nerve`), it
runs no command at all, and none as itself while no account is chosen.

`install`, `update` and `uninstall` run as root and write into folders
that belong to `nerve`: they write there as the folder's owner (the
thread's file-system ids), refuse a link in place of one of the node's
folders, and give the folders away by walking them through descriptors
opened without following links. A file with more than one name (a hard
link) is not given away: the walk stops there with an error, since its
other name may be outside the node's folders. A folder that belongs to
root already (`uninstall` without `--purge` gives the folders to root
before it writes its entry) is written as root, so the audit log there must
be a plain file with one name; a link or a hard link in its place is not
written to, and the command says so.

`node.toml` is written private to the owner (mode 0600 on Unix). The daemon
refuses to run as root, or in an elevated token on Windows, unless
`machine.allow_root = true`; when it runs that way, it logs a warning at
start (stderr and the node's log file, not the center) that commands then run
with full rights (on Unix unless `machine.user` names another account; an
elevated administrator on Windows cannot start a command as another account,
so its commands keep the node's token), and the owner is responsible.

These two folders are the node's own. No call of a center reaches them, in
any mode and whatever the rules, folders or `protected.allow` say (§3), and
no Landlock rule of a command covers them (§Modes).

### Who writes `node.toml`

Only the owner's path changes the config: the CLI (through the control
socket while the daemon runs, §5, else on the file itself), and a center
through `settings.set` within its grant. The daemon keeps the config in
memory. It reads the file at start-up and when the owner asks for it
(`SIGHUP`, the socket's `reload`); nothing rereads it on a timer.

Every file the node writes is signed: its first line is
`# mac hmac-sha256 <hex> (…)`, an HMAC over the rest of the file. The key is
`<state>/config.key` (0600), made the first time the node opens its config.
It sits in the state folder rather than beside `node.toml`, so the key does
not hang on a setting of the file it checks, and whatever could read the
config folder would still not hold it. `machine.secret_storage = "keyring"`
changes nothing, for this key as for the center keys: they stay files.

A file whose MAC is missing or does not match was changed outside the
owner's path. It is refused and the refusal is audited (§6): at start-up the
node does not start; on a reload the old config stays in force. A reload also
refuses a signed file older than the one in force. After looking at a refused
file, the owner takes it as it is with `nerve-node config accept`; the node
then signs it. A `node.toml` without a MAC line (no key yet) is taken once
as it is and signed.

The check stands on `config.key`. A process that can delete or read it, and a
`user` mode command is one (it runs unconfined as the user), can make the node
take another file at its next start: with the key gone, an unsigned file
counts as a first file and is signed. The start-up audits that as
`signed`. In `folder` mode Landlock keeps commands out of the state folder.

On Windows there is no control socket: the CLI writes the signed
file itself, and a running node takes the change at its next start. After
a change no daemon answered for, the CLI says so in one line ("takes effect
at the next start of the node").

## 2. `node.toml`

```toml
version = 1                 # bumped on every write; config.write checks it
locked = false              # `panic` sets it: no link, nothing runs

[node]
name = "laptop"             # shown to centers; the host name by default

[machine]
shell = "/bin/bash"         # for exec.run; the platform shell by default
allow_root = false
sudo = "off"                # off | on: the sudo switch (§4); off when missing
sudo_path = "/usr/bin/sudo" # optional; `sudo` from PATH by default
user = "alice"              # optional: the account commands and the sudo switch run as (§1)

[limits]
max_running = 4             # commands at once, per node
output_cap_bytes = 16777216

[connection]
proxy = "http://proxy:3128" # optional; HTTP CONNECT, never with user:password@
headers = ["X-Proxy-Token"] # names of extra headers on the CONNECT request;
                            # their values are in the system keyring

[[center]]
name = "home"               # the owner's name; the CLI's --center
url = "https://center.example:8443"
pin = "<sha-256 of the center certificate, base64url>"
center_id = "…"
node_id = "…"
settings = "off"            # off | write: may the center set this policy
paused = false              # the center may pause; only the owner unpauses
revoked = false             # the center sent `bye revoked`
unknown = false             # the center answered 401

[center.policy]
mode = "allowlist"          # allowlist | folder | user (the default is allowlist)
until = 1790000000000  # optional, folder and user: ms since the epoch; then allowlist
folders = [{ path = "/home/u/proj", access = "rwx" }]  # folder mode; r w x in any mix, "" for none
caps = { "fs.write" = "off" }   # on | off | hidden
protected = { extra = [], allow = [] }  # a center may add to extra; only the owner removes or releases,
                                        # also by a folder at or inside an entry
allow = ["exec.run:git status", "fs.read:~/notes/*"]   # allowlist mode only
deny = ["fs:~/private/*", "exec.run:rm *"]             # every mode
sudo_allow = ["sudo apt update"]                       # sudo commands, every mode
```

Unknown keys are refused, and so is a rule that does not parse. Two centers
with one name are refused. Folder paths are absolute in the platform's own
form, kept without a doubled or trailing separator or a `.` part; a path with
`..`, and one place named twice with different access, are refused. On the
wire they travel as `/c/Users/...` on Windows (protocol §7.2).

### Commands

`exec.run` runs its command line with `machine.shell`: `/bin/sh -c`, on
Windows `powershell.exe -NoProfile -Command` (Windows PowerShell 5.1: `;`
chains commands, `&` does not); the action's text in the descriptor names the
shell. Output that is not UTF-8 is read in the console code page (Windows).
A command is killed with its process group when its call ends: on
`timeout_ms`, `cancel`, `session.end` of the session that started it, a
dropped link, and when the call returns. Windows has no process groups:
there each command runs in a Job Object of its own. The shell starts
suspended, is put in the job, and only then runs, so every process it starts
is in the job, however deep and also when its parent has exited; ending the
job ends them all, and the job closes with the node, so a node that dies
leaves no command running. Where the node runs in a job already (a service,
the task scheduler), the command's job is nested in it; when Windows cannot
put the shell in its job, the command is not run and the call says why. A
process started on the command's request by another program, such as WMI
(`Win32_Process.Create`), a service or the task scheduler, is that program's
child and not in the job. Only when Windows makes no job at all does the node
fall back to recording the processes below the shell every 25 ms, best
effort. A Job Object does not restrict file access: it is no confinement
(see folder mode below).

### Proxy

`nerve-node proxy set <url> [--header "Name: value"]...` sets the proxy. The
header values are secrets: the node keeps them in the system keyring
(Keychain on macOS, Credential Manager on Windows, the Secret Service on
Linux), in one entry per node under the service `nerve`, named
`proxy:<config folder>`. A user name and password in the URL
(`http://user:password@host:port`) become a `Proxy-Authorization: Basic`
header in the same entry. `node.toml` keeps only the URL without them and the
header names. No value is written to a file, the audit log, a log line, an
error text or the output of a command; `proxy set` and `proxy ls` print the
header names only, and `proxy rm` deletes the entry with the config entries.

There is no fallback to a file. Where the keyring cannot be reached (a Linux
without a desktop session has no Secret Service), `proxy set` with a header or
a password refuses and changes nothing; a proxy without either works there.
When the daemon dials through the proxy it reads the entry; a missing or
unreadable entry, or one without a value for a named header, stops the link
with a status that names the entry, and the node does not dial directly
instead (fail closed).

A `node.toml` that holds header values (`headers = { Name = "value" }`) or a
user name and password in `connection.proxy` is refused on load, without the values in the message: take them out of the
file, accept it (`nerve-node config accept`) and run `nerve-node proxy set`
again.

### Modes

- **allowlist** (the default after pairing): default deny. A call runs only
  when an `allow` rule lets it through. `folders` do not count.
- **folder**: full access inside the `folders` (and everything below them),
  by their flags. `access` is three independent flags, any combination
  (`"r"`, `"w"`, `"x"`, `"rw"`, `"rx"`, `"wx"`, `"rwx"`, `""` for none; the
  letters in any order, each once). `r` allows the read actions of `fs`
  inside it, `w` the write actions, `x` commands with a working directory in
  it. The flags do not imply each other: a write needs `w` and no `r`, a read
  `r` and no `w`, a command `x` and no `r`. Where folders nest, the deepest
  one that holds a path decides for it. Commands are confined where the
  platform can confine them. Windows has no file confinement for commands,
  so there folder mode refuses every command and offers no `exec`
  action (unless the sudo allow list has an entry), and only `allowlist` and
  `user` run them, each owned by its Job Object but not confined. `allow` rules do not count. On Linux a command
  reads the system folders and its `r` folders, writes its `w` folders and
  runs programs from the system folders and its `x` folders (Landlock), each
  flag with its own rule. A folder with `w` and not `r` can be written but
  not read or listed by the command: its rule carries the write rights only.
  Landlock cannot run a file it may not read, so the rule of an `x` folder
  carries the right to read files by name (no listing); the `fs` actions of
  the center stay decided by `r`. The node's own folders are in none of these
  sets: a folder that holds one is granted as its other entries, level by
  level down to it, so the command can neither list those levels nor make
  new entries right in them.
- **user**: full access as the user, protected paths aside. `allow` rules
  do not count.

Folder and user have no time limit by default: once set, they stay until the
owner changes them. A limit is opt-in (`until`, or `nerve-node mode set user
--for HOURS`). When it runs out, the center is back in `allowlist`, the default
deny mode, not in `folder`.

`deny` rules count in every mode and a matching deny always wins. A rule
matches the whole target: `exec.run:rm *` refuses `rm -rf x`, but not
`git status; rm -rf x` or `/bin/rm -rf x`. Sense and
actuate actions are allowed by no full-access mode, only by the owner's
`caps` entry `on`; in `allowlist` mode an allow rule allows them (a center
may not add one for a sense capability itself).

### Rules

A rule in `allow` and `deny` is `<scope>` or `<scope>:<pattern>`. The scope is
a capability or `cap.action`, as in `caps`. The pattern is a glob over the
call's target: the whole command line for `exec.run`, the resolved path for
every `fs` action (in the center's form, `/c/Users/x` on Windows; `~/` is the
owner's home), and
`<cap>.<action>` for any other action. `*` matches across `/` and spaces. A
rule without a pattern covers every target of its scope. A pattern ending in
` *` also matches the bare program, one ending in `/*` the folder itself.
Commands and paths never mix: `fs:/tmp/*` is no command rule.

| Rule | Covers |
|---|---|
| `exec.run:git status` | that command line, exactly |
| `exec.run:git *` | `git` and anything after it |
| `fs.read:/home/u/notes/*` | reading the folder and below (the action, not `list` or `grep`) |
| `fs:~/private/*` | every fs action on the folder and below |
| `camera.snap`, `camera` | that action, or every action of the capability |

The four buttons of the center's audit view and `nerve-node rule add allow|deny|sudo
<command> [--wildcard]` write exactly these forms: exact (`exec.run:git status`) or
wildcard (`exec.run:git *`, `fs.read:/home/u/notes/*` for the folder of the
path, the capability for another action). They only add a rule to a list;
rules can be written by hand as well (`nerve-node config add
center.<name>.policy.allow '<rule>'`).

In `allowlist` mode a command with `; & | $ \` ( ) < > @ { } % ' " # , \`,
a line break or another control character, or with a word that starts
another shell or runs a string as code (`powershell`, `pwsh`, `cmd`, `sh`,
`bash`, `iex`, `Invoke-Expression`, `Invoke-Command`, `start`,
`Start-Process`, `eval`, `-Command`, `-EncodedCommand`, `-File`, `/c`,
`/k`, without case and `.exe`) is covered only by an allow rule that names
the whole line, never by a wildcard: such commands run unconfined, `git *`
must not cover `git x; rm -rf ~`, and `echo *` must not cover PowerShell's
`echo @{a=<command>}`, which runs the command. A wildcard rule therefore
covers plain words only; a Windows path with `\` needs an exact rule or `/`.

## 3. Deciding a call

The default is deny. A call runs only when the mode and the rules allow it;
otherwise it is refused at once with `forbidden`, and nothing waits for an
answer. For each call the node takes the center's policy and, in this order:

0. An `exec.run` command line over 64 KiB is `forbidden` first, before
   anything is checked. A call that touches the node's own folders (§1) is
   `forbidden` before anything else is looked at; no rule, mode, folder or release lifts that.
   It looks at every path of an `fs` call (resolved), at the working
   directory of `exec.run`, and at paths the command line names plainly
   (absolute, or from `~/`, `$HOME/`, `${HOME}/`). The line is compared
   without case, with `\` and `/` alike on Windows, with `seg/..` and
   doubled separators folded, with the home in each shell's spelling (also
   `$env:USERPROFILE`, `%USERPROFILE%` and `%HOMEDRIVE%%HOMEPATH%` on
   Windows) and with relative words taken from the working directory
   (`..\node-config`). Each path segment is matched as a shell wildcard
   (`node-st*`, `node-s?ate`, `[...]`); on Windows a segment with an 8.3
   short name (`NODE-S~1`) stands for any name, an admin share
   (`\\localhost\C$\...`, any host) for its drive, and a path without a
   drive (`\Users\...`) for that path on every drive, as does a volume or
   device path (`\\?\Volume{...}\...`); a dot at the end of a name is
   dropped as Windows drops it (`node-state.\`), and a drive-relative
   `C:name` is taken from the working directory on that drive. A path a
   command builds at run time (`cd ~/.config; cat nerve/node.toml`) is not
   seen there; in `folder` mode Landlock keeps the command out all the
   same, while a `user` mode command runs as the user, unconfined.
1. A `locked` node (after `panic`) keeps no links and runs nothing; a paused,
   revoked or unknown center is not dialled.
2. The capability setting: `off` refuses (`disabled`), `hidden` leaves it
   out of the descriptor.
3. A sudo command (§4) with the sudo switch off: `forbidden`.
4. A matching `deny` rule: `forbidden`, in every mode.
5. A sudo command is allowed only when `sudo_allow` names it, in every mode.
6. Any other call in `allowlist` mode is allowed only when an `allow` rule
   matches (every path of the call needs one).
7. In `folder` and `user` mode the mode itself decides (§Modes). `allow`
   rules are not looked at.
8. Protected paths (keys, shell profiles and the built-in list) are refused
   whatever allowed the call, `user` mode too. On Windows the built-in list
   also holds `%ProgramData%\ssh` (the OpenSSH server's config, host keys
   and `administrators_authorized_keys`), `%SystemRoot%\System32\config`
   (the registry hives with the password hashes), the all-users Startup
   folder `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp`,
   Windows PowerShell's home `%SystemRoot%\System32\WindowsPowerShell\v1.0`
   (and its SysWOW64 twin) with the all-users profiles, and the user's
   `NTUSER.DAT`. It also holds `%ProgramFiles%\PowerShell` (and
   `%ProgramFiles(x86)%\PowerShell` where that is set), PowerShell 7's home
   `$PSHOME` with its profiles and modules as the MSI and winget install it;
   a PowerShell 7 unpacked from the zip, installed as a .NET tool or into a
   folder of the user's choice is not covered. The user's PowerShell
   profiles and modules (`Documents\PowerShell`, `Documents\WindowsPowerShell`)
   are protected below `%USERPROFILE%\Documents` and below the Documents
   folder where Windows really has it (read with the known-folder API, so
   OneDrive's backup or a redirect does not move them out of the list).
   A folder spelled so that it matches nothing (a `..` segment, and on
   Windows an 8.3 short name or a name ending in a dot or space) is refused,
   from a center and in the owner's own `node.toml`; the full name is needed.
   Protected paths apply to the
   file actions and to the working directory of a command, not to what a
   command reads; in `user` mode a command runs as the user without a
   sandbox. A center's folder at or inside a protected entry is
   judged by the access the owner's folders give that place, and may set no
   flag the deepest of them lacks; the spellings of one place
   (`/home/u/.ssh/`, `/home/u/.ssh`) are compared by path, not as text.
   A folder releases a protected entry only for the access the call needs
   there, in every mode: a read needs `r`, a write `w`, a command run in it
   `x`, so an owner's `~/.ssh` with `r` lets no write through in `user`
   mode. A center's folder that is, or passes through, a link into a
   protected entry is refused unless the owner's folders release the place
   it leads to with its flags, and a folder that has become such a link
   since is left out of a command's Landlock rules. A folder that holds a
   protected entry gives a command in `folder` mode none of it: its Landlock
   rules take the folder's other entries, level by level down to the
   protected one, in the read, write and run sets alike, so the command
   cannot list those levels or make new entries right in them.

Every refusal names its reasons in the error and in the audit log.

What the center is shown follows the same policy, so that its harness builds
no tool the node would refuse. In `allowlist` mode an `fs` or `exec` action
is in the descriptor only when an `allow` rule covers it by scope: `<cap>`
covers every action of the capability, `<cap>.<action>` that action, with or
without a `:<pattern>`. The pattern is not looked at there; a rule may allow
only some paths or commands, and each call is still decided as above.
`exec.run` is also shown when `sudo_allow` has an entry, since a sudo command
runs by that list alone. In `folder` and `user` mode the actions are shown as
before and allow rules do not matter, except a sense or actuate action such
as `exec.signal`, which is shown there only when the owner set it to `on`;
deny rules never hide an action.
`off` actions stay listed (exposure `off`), `hidden` ones and the actions
left out here are absent, and a capability with no action left is absent.
`settings` and `audit` follow their own rules. The descriptor's `rev` follows
its content, so adding or removing a rule that changes the set sends
`node/descriptor_changed`; a call naming an action that is not shown still
reaches the policy and is refused and audited.

## 4. The sudo switch

Sudo is a switch per node, not a mode, and its commands have an allow list of
their own, `sudo_allow`: globs over the whole command line (`sudo apt *`).
The normal `allow` list does not count for them.

- **Off** (the default): the node holds no sudo password, and a command whose
  first word is `sudo` (or a path ending in `/sudo`) is refused with
  `forbidden`, even when `sudo_allow` names it.
- **On**: such a command runs only when `sudo_allow` names it, in every
  mode; `deny` rules and protected paths still refuse it. A sudo command must
  be one simple command: one with `; & | $ \` ( ) < >` or a line break is
  refused. A `sudo_allow` glob covers only the plain lines a wildcard allow
  rule covers (§2, Rules); any other line runs only when an entry is that
  whole line, escaped as `rule add sudo` writes it. The node runs it as `sudo -S -k -p <prompt> …` without Landlock
  (which would stop sudo from gaining privileges), with a random prompt per
  command, started as the account the commands run as (§1), so sudo raises
  it from that account. It writes the password to stdin only after sudo
  printed that prompt; when sudo asks for none (a `NOPASSWD` entry, root), the command
  finds no password on its stdin.
- Every other command runs with `no_new_privs` (Linux), so a `sudo` later in
  a command line, or any setuid program, cannot gain privileges.

The switch is never on without a working password. Turning it on takes the
password from a client: `nerve-node sudo on` (it asks on the terminal) or a
center with the settings grant `write` (protocol §7.4.1, sealed end to end so
the center cannot read it). The node checks it with `sudo -S -k -v` (output
discarded), run as the account the commands run as (§1, `machine.user` on
the installed node, else the node's own user), so the password is that
account's and refuses a wrong one with `invalid_args`; the switch then stays
as it was. Turning it off drops the password. On Linux the password is kept
in memory only, never at rest, so a restarted node, or
a `node.toml` that says `on` without a password held, has the switch off. It
never reaches a center: the node replaces every copy in an outgoing frame and
in the audit log with `[redacted]`. `machine.sudo` changes only through the
switch; a value written into the file is turned off at start-up, since no
password is held. The switch works on Linux and Windows.

On Windows there is no `sudo` program. The switch works on the installed
node only (§1: the service, which may start a process with another
account's token), and its password is the one of the account the commands
run as, which must be an administrator. `sudo on` checks it with a logon of
that account as a batch job (`LogonUserW`, `LOGON32_LOGON_BATCH`), which UAC
does not filter: the logon must succeed and its token must hold the
Administrators group enabled; else the switch stays as it was. The node then
keeps the password with DPAPI in the config folder (`sudo.dpapi`, like the
command account's password), and holds it in memory as on Linux. A restart
holds the kept password again when `machine.sudo` says on and the file is
the current account's. A sudo command runs what followed `sudo` in the
shell, started with a fresh batch logon's full token (`CreateProcessAsUserW`)
with the account's own environment, in a job like every command; the check
that the account cannot open the node's folders does not apply to it. Without
a control channel, `nerve-node sudo on` (elevated) checks the password,
writes the file and sets `machine.sudo` in the signed file, which the service
takes at its next start; `nerve-node sudo off` removes the file, and the
running node drops a held password whose file is gone within a second and
switches off. `uninstall` removes the file.

## 5. Control socket

`<state>/run/ctl.sock` (Unix only; on Windows the CLI writes the
signed `node.toml` itself, §1). One JSON object per line: the client sends
`{"method", "params"}`, the server answers `{"ok": value}` or
`{"error": "text"}`, or, for streaming methods, several `{"item": value}`
lines until it closes. The socket is 0600 in a 0700 folder; only its own user
or root may talk to it. Methods:

| Method | Params | |
|---|---|---|
| `status` | | daemon and links |
| `config.read` | | `node.toml` and its `version` |
| `config.write` | `config`, `if_version` | replaces it when the version matches |
| `config.accept` | | takes `node.toml` as it is after it was refused, and signs it (§1) |
| `reload` | | rereads `node.toml`; only a file the node signed is applied (§1) |
| `sudo.status` | | `{sudo: "on"|"off"}` |
| `sudo.on` | `password` | checks it with `sudo -v` and turns the switch on (§4) |
| `sudo.off` | | turns the switch off and drops the password |
| `owner.check` | | changes nothing; the CLI asks it before `install`, `setup`, `update` and `uninstall` |

`config.write`, `config.accept`, `reload`, `sudo.on`, `sudo.off` and
`owner.check` are refused from a process that runs below a command the node
started for a center, so on Linux an agent cannot change its own policy
through the socket, nor install, set up, update or remove the node.
**Windows has no socket and no sandbox:** the CLI signs node.toml
itself, so a command the node runs for a center can change the policy, and
the change applies at the next start. On Windows, allow commands only to
centers you would also give `settings = write`.

## 6. Audit log

`<state>/audit.jsonl`, one JSON line per event: settings changes (with old
and new value), calls allowed or forbidden (a refusal with its reason), and what happened to the config
file itself (`"kind": "config"`, `event` `refused`, `signed` or `accepted`,
with the file and the reason), and what the owner did to the node
(`"kind": "node"`, `event` `install`, `setup`, `update` or `uninstall`, with
its `steps` and the `error` that stopped it). It holds targets (paths, command lines), never
file content or output; a target longer than 512 characters is cut there
and says so; the `audit/decision` event carries the same cut target, and the
center cuts what it gets the same way and keeps at most 500 decisions and
1 MiB of them. When the file would pass 10 MiB it is moved to `audit.jsonl.1`,
replacing the older one, so the log keeps at most about 20 MiB; when the
move fails the entry is still written, past that bound, and the node logs the
failure once. Refused calls get at most half of a full file: past that the
oldest refusals are dropped instead of the file being moved, so a center
that makes refused calls cannot push out what the node allowed or changed.
`nerve-node audit [--denied] [--follow]` shows both files, `audit.jsonl.1`
first, and `--follow` finishes the old file after a move before it reads the
new one.
