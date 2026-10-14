# The node's own side: config, policy, control socket

This part is not wire protocol: a center never sees it directly. It describes
how `nerve-node` decides, so that other node implementations can behave the
same way and so the owner knows what each setting does.

## 1. Folders

| What | Default | Override |
|---|---|---|
| `node.toml` and one key per center (`keys/<name>.key`); on Windows also `sudo.dpapi` and, on the installed node, `command-account.dpapi` | `~/.config/nerve` | `--config-dir`, `NERVE_CONFIG_DIR` |
| control socket `run/ctl.sock` and its token `run/ctl.token`, audit log `audit.jsonl`, log `log.jsonl`, the config's MAC key `config.key`, `keys.lock`, `keys.moving`; on Windows the record of the folder grants `grants.json` and its lock `grants.json.lock` | `~/.local/state/nerve` | `--state-dir`, `NERVE_STATE_DIR` |

With `machine.secret_storage = "keyring"` the keys are in the system keyring
instead of `keys/` and `config.key` ([where the keys are](#where-the-keys-are)).

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
runs as `nerve` on the installed node, cannot judge a folder it may not look
into: with a node running, `folder add` is done by the node as the account
(`folder.add`, §5); with none, the folder is kept in its normal form,
unresolved, and not recorded. A node not installed as a
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
`<state>/config.key` (0600), made the first time the node opens its config,
or its keyring entry ([where the keys are](#where-the-keys-are)). It sits in
the state folder rather than beside `node.toml`, so whatever could read the
config folder would still not hold it.

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

On Windows there is no control socket. A running node takes the folder
changes over its control pipe (§5); for every other change the CLI writes
the signed file itself, and a running node takes it at its next start. After
a change no daemon answered for, the CLI says so in one line ("takes effect
at the next start of the node").

### Where the keys are

`machine.secret_storage` says where the node keeps its own keys: the key of
the config's MAC and its key per center.

- `file`, the default: `<state>/config.key` and `<config>/keys/<name>.key`,
  each 0600.
- `keyring`: the system keyring (Credential Manager on Windows, the Secret
  Service on Linux), under the service `nerve`, one entry per key, named
  `config-key:<state folder>` and `center-key:<name>:<config folder>`. Each
  holds the key's hex text. No copy stays in a file.

The proxy's header values are in the keyring either way (§2), except on the
installed node on Windows, which takes none (§2, Proxy).

Two kinds of node keep their keys in files whatever is asked:

- The installed node on Windows (the service, which runs as `nerve`). The
  Credential Manager is one per account, and the CLI that writes the config
  there runs as an administrator, so a move into the keyring would put the
  keys in that administrator's Credential Manager, out of the service's
  reach. The node counts as installed on the folders `install` uses, in any
  spelling of their case, or when it runs as `nerve`.
- A Linux node whose kernel has a Landlock ABI below 9. Landlock there
  cannot keep a command off the session bus the keyring answers on (§1,
  the paragraphs on the session bus below), so with the keys in the keyring
  a `folder` mode command could not run programs from its folders: the
  sandbox cannot grant the keyring's access and execute together. This
  holds whatever account runs the commands. Only an ABI that is read
  counts: where Landlock is missing or off, so that its ABI cannot be read,
  the keyring is allowed (folder mode then runs no command anyway), and
  `setup` warns that it cannot tell.

On such a node:

- A change to `keyring` is refused before anything moves, by whatever
  writes the config (`config set`, setup, `config accept`); `node.toml` and
  the keys stay as they were. This refusal comes before the count of running
  commands below, as it holds whatever runs. A running node does not reload a
  file another writer saved with `keyring`.
- `config accept` refuses a file that says `keyring`, even when the keys are
  in the keyring already, so nothing would move.
- `setup` does not ask where the keys go. It prints a warning with the
  reason, and moves keys left in the keyring into files. On Linux it first
  checks that the keyring answers, and offers to install one as it does
  elsewhere, so that it can read the keys it moves; on the installed node on
  Windows it asks no keyring.
- `install`, and the node at its start, refuse a `node.toml` that says
  `keyring`. The message names the file and the command that moves the keys
  into files, with `--config-dir` and `--state-dir` of the folders it
  refused, so it works whether or not a service is registered yet. It is run
  as the account whose keyring holds them: on Windows the administrator
  that put them there, on Linux the node's user (sudo becomes it).

The node looks for the key that checks `node.toml` where that file says,
read before its MAC is checked. A file that names another place than the one
its key is in does not check, and is refused like any changed file.

With `keyring` and no keyring that answers, the node does not start, and a
command that reads the config refuses. The message names the entry and the
keyring's error. Nothing falls back to a file. On Linux the sudo password is
never at rest, whatever the setting; on Windows the node keeps it with DPAPI
in `sudo.dpapi` in the config folder, whatever the setting (§4).

A change of the setting moves the keys once, through the settings store, in
whatever writes the config (the running node, else the CLI):

1. `<state>/keys.moving` is written. It holds no secret.
2. Every key is copied to the new place and read back; a copy there that
   holds the same key already is left as it is. When a copy fails or reads
   back otherwise, the copies this move wrote are deleted, the failing one
   included, and the change is refused: `node.toml` stays as it was, and so
   do the keys.
3. `node.toml` is saved with the new setting.
4. Each old copy is deleted once the new place holds the same key, then
   `keys.moving` goes.

A running node holds `<state>/keys.lock` for its life. A CLI that writes
`node.toml` itself (no daemon answers: on Windows always, on Linux while a
node starts) moves the keys only while it holds that lock too. When a node
holds it, step 4 is left to that node's next start, and the running node goes
on reading its keys where they were. On Linux a move into the keyring is
refused then: that node goes on with the keys in files, so its `folder` mode
commands would get a sandbox for keys in files while they are in the keyring,
and the CLI does not see its count of such commands (below). At start-up, with `node.toml` checked
and the lock held, the node finishes a move by the config in force: a key
still in the other place moves into the configured one. That covers a move
`keys.moving` marks and one a crash stopped; with `keyring`, keys still in
files move in too. With `file` and no mark, the keyring is not asked. When
`node.toml` changed since the node read it, the move waits for the next
start. `config accept` of a file that names the other place moves the keys
there; when the place it names holds no key and the other one does, the key
is taken from there.

A CLI that writes `node.toml` itself holds `keys.lock` for each write it
can (no node holds it), and refuses a change whose file is no longer the
version it read: a change made before another CLI moved the keys would undo
that move in the file. `center rm` deletes the center's key in both places
while `keys.moving` is there, since the start that finishes the move no
longer looks for a removed center.

With `keyring` the MAC key is in no file that a process can read. The check
still stands on that key: a process that can write both folders can still
set `file` with a key of its own, and a process of the node's user can ask
the keyring for its entries over the user's D-Bus session.

So with `keyring` on Linux the node's own folders, which no policy opens
and Landlock's rules leave out, also take in the places that reach the
keys: the node's `XDG_RUNTIME_DIR`, `/run/user/<uid>`, a socket that a
`unix:path=` `DBUS_SESSION_BUS_ADDRESS` names, and `keyrings` in
`XDG_DATA_HOME` and in `~/.local/share`. A `folder` mode command then also
gets a Landlock rule for connecting to socket files
(`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`, ABI 9, Linux 7.1): everywhere but the
own folders. Where the kernel has a Landlock ABI below 9 the keys do not go
into the keyring at all ([where the keys are](#where-the-keys-are)).

The code keeps a gate as a second line, which an owner cannot reach while
that refusal holds: with the keys in the keyring and no ABI 9, `folder`
mode would offer no `exec`, as on a machine without Landlock, unless
commands run as an account other than root and the node's own (the bus
folder is the user's alone, 0700); the node would log it, its status would
say it (`folder_commands_off`), and a refused command would name the
keyring. The gate and the command's Landlock rules go by one answer per
call, from the same config and account.

A Landlock domain does not change while its command runs, so a `folder`
mode command that started while the keys were in files keeps a way to the
session bus for its whole life, unless it runs as an account other than
root. The running node counts these commands, and a move of the keys into
the keyring is refused while one runs: nothing moves, and the refusal says
how many run. The command is counted first and looks at the keys' place
then, under the store lock that a move holds, so a command whose config was
taken before a move that finished first does not start either. A reload
(SIGHUP, `reload`) of a file that another writer saved with `keyring` is
refused the same way while one runs, and the config in force stays. A process
that a command takes out of its process group (`setsid`) outlives its call
and is not counted.

`allowlist` and `user` mode commands get no Landlock rules, so an allowed
command that talks to the Secret Service (`secret-tool`, `busctl --user`,
`gdbus`, `dbus-send`) reads the node's keys with `keyring`; it names no
path the protected list could refuse.

#### A keyring on a Linux without a desktop

A Linux without a desktop usually has no Secret Service. When the keys are to
be in the keyring (the config says so, or the owner chooses it in `setup`)
and none answers for the node's user, `setup` asks whether to install one.
`install` asks the same when it runs in a terminal and the config of an
earlier install says `keyring`; without a terminal it refuses before it
starts the service. No is the default and keeps the refusal. Yes runs, as
root:

- the package manager: `apt-get update` and `apt-get install -y
  gnome-keyring dbus-user-session` (Debian, Ubuntu), `dnf install -y
  gnome-keyring` (Fedora, RHEL) or `pacman -S --needed --noconfirm
  gnome-keyring` (Arch);
- `loginctl enable-linger <user>`: the user keeps a session with its own
  D-Bus from boot on, and D-Bus starts GNOME Keyring there when the node
  asks;
- a login keyring for the user in GNOME Keyring's plain format,
  `~/.local/share/keyrings/login.keyring`, that opens without a password. A
  login keyring that is there is left as it is.

Then it checks that the keyring answers. Whether a keyring answers is asked
by `nerve-node` itself in a process of its own, as the node's user and in
that user's session.

Nothing is offered where the user has a graphical session: the
environment of a setup run in it (`DISPLAY`, `WAYLAND_DISPLAY`,
`XDG_CURRENT_DESKTOP`, `XDG_SESSION_TYPE`), or logind's display session of
the user when its type is x11, wayland or mir. A password-less login keyring
would become the default for every program of that desktop.

The keyring crate connects once per process and keeps a failure for the
process's life. A running node reports one in its status
(`keyring_failed`); once a keyring answers setup, installed by setup or
not, it restarts the installed node (`systemctl restart`, then waits for
it), and stops with a message on a node run by hand.

The kernel keyring (keyutils) needs no daemon, but its keys are gone after a
reboot, and the node's with them, so it is not used. A keyring that opens
without anyone typing a password keeps its entries unencrypted on disk,
readable by the node's user like the key files, and kept from centers like
them (above); the question says so, and that it becomes the user's default
keyring. At boot the node can start before its user's session; it then
exits with the refusal, and systemd starts it again 5 seconds later.
`uninstall` ends that session (`loginctl disable-linger`).

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
secret_storage = "file"     # file | keyring: where the node keeps its keys (§1)

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
places = ["/home/u/proj"]  # folders `folder add` recorded at their real place; the owner's, a center's write keeps it
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

The installed node on Windows (§1, where the keys are: the folders `install`
uses, or the account `nerve`) takes no header value and no password either,
though its keyring answers. The service runs as `nerve`, the Credential
Manager is one per account, and `proxy set` runs as an administrator, so the
values would be in the administrator's Credential Manager, out of the
service's reach. The node keeps no proxy secret in a file, so there is nowhere
else for them. `proxy set` with a header or a password refuses before it asks
the keyring, and changes nothing (`node.toml`, the keyring); a proxy without
either works, and its `proxy set` deletes the entry of an earlier call, as it
does anywhere. Reading is as consistent: with headers named in `node.toml`
(set before the install) the link stops with `bad proxy:` and the same reason
(in the center's status and in the log; on Windows `status` does not ask the
node, whose pipe takes folder changes only, so it shows no link status there
and the log is the only place), and
`proxy ls` shows it, both without asking the keyring: an entry may be in the
administrator's Credential Manager, but the service does not find it, so
`proxy ls` must not call the values good.

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
  platform can confine them; where it cannot (Linux without Landlock),
  folder mode refuses every command and offers no `exec` action (unless the
  sudo allow list has an entry). On Windows a command runs in an AppContainer
  of its pairing (named from the state folder and the pairing's `node_id`,
  so a later pairing, also of the same center or under the same name, runs
  in another one and finds none of its entries), which reaches the system folders Windows opens to every
  AppContainer and the paths of the same sets as on Linux, each by a grant
  for the container on the folder with the rights of its flags; the
  installed Windows service, whose commands run as another account, has no
  such confinement and refuses them. `allow` rules do not count. On Linux a command
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
   since is left out of a command's Landlock rules, as is a folder whose path
   crosses a link that lies inside a `w` folder of any center (a command may
   have put the link there). A folder the owner added with `folder add` is
   stored by its resolved path and listed in `policy.places`; such a folder
   is also left out when its path resolves to another place now, whatever the
   `w` folders say, and a center's settings document cannot change the list.
   `folder add` itself does not follow a link that lies inside a `w` folder
   of any center: it refuses, so that a link a command made is not stored,
   and recorded, at its target. It judges and resolves in one pass
   (`exec::settle`): a link is judged by the folder that holds it as spelled
   and as it resolves, either inside a `w` folder refuses it and so does a
   holder that is not the place it was looked at as, and the place the pass
   ends at must resolve to itself, so that what is stored is what was looked
   at. A `w` folder that cannot be resolved only makes a clean walk "cannot
   tell" (the folder is stored as given, not recorded). On Windows the walk
   goes through a `subst` drive's folder name by name (`QueryDosDeviceW`),
   never through the drive resolved, writes out the short names of the
   folder it maps, and refuses a path with a drive but no root or that is not
   on a drive letter. A link target is taken the same way: a drive, a volume
   root (as the drive or folder it is mounted at), or refused.
   For a folder without an entry only the `w` folders in the config count,
   and a command that runs without Landlock can make a link elsewhere. A folder
   that holds a protected entry gives a command in `folder` mode none of it:
   its Landlock rules take the folder's other entries, level by level down
   to the protected one, in the read, write and run sets alike, so the
   command cannot list those levels or make new entries right in them.

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
in memory only, whatever `secret_storage` says, so a restarted node, or
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
that the account cannot open the node's folders does not apply to it. The
control pipe takes folder changes only, so `nerve-node sudo on` (elevated) checks the password,
writes the file and sets `machine.sudo` in the signed file, which the service
takes at its next start; `nerve-node sudo off` removes the file, and the
running node drops a held password whose file is gone within a second and
switches off. `uninstall` removes the file.

## 5. Control socket

`<state>/run/ctl.sock` (Unix; Windows has the control pipe below). One
JSON object per line: the client sends
`{"method", "params", "token"}` (the token is explained below), the server answers `{"ok": value}` or
`{"error": "text"}`, or, for streaming methods, several `{"item": value}`
lines until it closes. The socket is 0600 in a 0700 folder; only its own user
or root may talk to it. That does not keep out a command the node runs as
that very user (a node a person runs, with no `machine.user`) or as root:
Landlock stops a process connecting to a socket file only from ABI 9 on, and
`setsid` takes a process out of the tree below its command. So the node makes
a token at each start,
`<state>/run/ctl.token` (0600), and answers a request only if it carries it.
The CLI reads the file and sends it. The
file lies in the node's own folders, which a `folder` mode command's rules
leave out, so such a command, and a process it left behind, are refused for
every method.

The one answer without the token is `status`: `{"ok": {"running": true}}`,
nothing of the config. `update` of 0.0.2 asks it that way to wait for the
node it restarted, and puts the old program back if it does not answer `ok`;
since 0.0.3 `install`, `update` and `setup` send the token.

The token holds as far as the sandbox does. While the commands run as the
node's own user, `folder` mode is no boundary against that user's other
programs: any of them that runs commands for whoever connects to its socket
runs them outside the sandbox, as the user's own process, which reads the
token, `node.toml` and the keys as the CLI does. The user's systemd and D-Bus
session (`systemd-run --user`) is one, a tmux or screen server another
(`tmux run-shell`, its socket in `/tmp`); there are more. A connect rule
(`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`, ABI 9) that leaves out only the session
does not close them, and the node sets none while the keys are in files
(`exec.rs`). The boundary is `machine.user`: the commands run as another
account that only the node uses and that gets root in no way without a
password: not root, not in `docker`, `lxd`, `incus-admin`, `libvirt` or
`disk`, no `NOPASSWD` sudo, and nobody works as it and uses `sudo` or `su`
from it (user docs, service.md "The account commands run as"). Root passes
the socket's uid check, and an account that becomes root is root.
`no_new_privs` and Landlock hold the command's own process tree only: a
program the account's user manager or a tmux or screen server starts for it
has neither, and the command can type into the tmux or screen panes of a
person who works as the account, where sudo has a live ticket, and change
what their shell runs. So for such an account every command is root, not
only the sudo commands. `install` takes the account that ran `sudo`, the one
its owner logs in as, so that default is no boundary whatever its sudo asks
for; `setup --create-user` makes an account for the node. The node's own sudo
calls pass `-k` and leave no ticket, so a node-only account may be a sudoer
with a password for the sudo switch. Where `machine.user` is such an account,
the boundary keeps out every command but a sudo command: that one runs as
root whatever account `machine.user` names (no `no_new_privs`, and the unit
keeps the capabilities it needs), so it reads the token, passes the uid check
and can leave the tree.

A connection the node cannot take (for want of
descriptors, memory or epoll watches, or for any other reason of that one
connection) does not end the socket: the node takes the next one once the
cause is gone. Only an error that says the listener itself is broken ends it.
A connection carries one request: the node closes it after the answer (for a
streaming method, after the last item), closes one that sends no request line
within 30 s, and serves at most 64 at once; one over that is answered with
`{"error": "the node does not take connections now; try again"}` and closed.

What a client makes of a connect that fails: only a missing socket (ENOENT)
and a refused connect (ECONNREFUSED) mean that no node runs, and only then may
the CLI write `node.toml` itself. A queue that is full (EAGAIN) means a node
runs and takes no connection now (`the node does not take connections now; try
again`): the command fails and writes nothing. Any other connect error names
itself and decides nothing about a node. A call that gets no answer in 90 s
gives up (`the node did not answer in time; try again`). A caller that maps
every connect error to "not running" would write the file and report a change
the running node never got.
Methods:

| Method | Params | |
|---|---|---|
| `status` | | daemon and links |
| `config.read` | | `node.toml` and its `version` |
| `config.write` | `config`, `if_version` | replaces it when the version matches |
| `config.accept` | | takes `node.toml` as it is after it was refused, and signs it (§1) |
| `folder.add` | `center`, `path`, `access` | `folder add`, done by the node so that it is judged as the account commands run as (`exec::settle`): the path is followed a link at a time and must resolve to itself, the folder is stored at that place with `access` (replacing the entry there) and recorded in `policy.places`; `{stored, recorded, mode}`. An error, with nothing changed, when the path crosses a link inside a `w` folder of any center, leads nowhere, or changed while it was looked at. Where the node cannot tell either (a folder it may not look into, or a `w` folder it cannot resolve) the folder is stored as given, `recorded` is false, and a record it had stays. The CLI uses it whenever a node runs |
| `reload` | | rereads `node.toml`; only a file the node signed is applied (§1) |
| `sudo.status` | | `{sudo: "on"|"off"}` |
| `sudo.on` | `password` | checks it with `sudo -v` and turns the switch on (§4) |
| `sudo.off` | | turns the switch off and drops the password |
| `owner.check` | | changes nothing; the CLI asks it before `install`, `setup`, `update` and `uninstall` |

Every method is refused from a process that runs below a command the node
started for a center, the reading ones (`status`, `config.read`,
`sudo.status`) too, as they hand over the whole config. That catches the
processes that stay below the command, in any mode. A `folder` mode command
is kept out by the token as well, including a process it left behind, as far
as the sandbox holds (above). A command without a sandbox (`allowlist` and
`user` mode) can read the token file as it can read `node.toml`, and a sudo
command is root and reads it and passes the uid check, whatever account
`machine.user` names. Both can leave the tree at once (`( … & )`,
`setsid -f`, a daemon fork), while the command still runs. For such a command
the socket is no boundary at any time, as the node's files are none; the
refusal stops what stays below it.

### The control pipe (Windows)

`\\.\pipe\nerve-node-<hash>`, where the hash is the first 16 bytes of the
SHA-256 of the state folder's real path in lower case, in hex: one pipe per
state folder. The lines and the connection rules are those of the socket: one
request per connection, 30 s for it, at most 64 at once, `the node does not
take connections now; try again` over that. Only a missing pipe
(`ERROR_FILE_NOT_FOUND`) means that no node runs. The CLI sets no 90 s limit
on the answer: a folder change brings the folder grants in line before it is
answered, which takes long on a large folder. Methods:

| Method | Params | |
|---|---|---|
| `status` | | as on the socket |
| `folder.add` | `center`?, `path`, `access` (`r`, `w`, `x`, at least one), `recorded` | adds the folder, or replaces its rights (the same place in another spelling is the same folder); with `recorded` the folder is also entered in `policy.places`, as the real place the CLI settled it at |
| `folder.set` | `center`?, `path`, `given`, `changes` (1 to 64 of `=rwx`, `+x`, `-w`) | changes the rights of a folder the center has |
| `folder.rm` | `center`?, `path`, `given` | takes a folder away |

`path` is the folder as the CLI judged it: for `add` the real place it
settled the path at (`exec::settle`, as this process sees it: the pipe takes
the change, not the judging, which on Windows is the CLI's alone), for `set`
and `rm` the stored folder it found (`stored_folder`). `given` is the folder
as typed or, after that lookup, the stored path again; `set` and `rm` find the
folder by either. A `rm` takes the folder's `places` entry with it (the
config's validation drops an entry that names no folder). Without `center`
the only paired center is meant.
While `node.toml` is newer than the config in force (the CLI wrote another
change there for the next start), a folder change is refused: the node saves
its whole config and would undo that change.
A field the method does not take refuses the request. The node checks a
change as the CLI does when it writes the file, saves it, brings the folder
grants in line, and answers `{center, path, access, mode, version}`
(`access` is `null` after `rm`).

Who may write:

- The DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<node account>)`) lets
  SYSTEM, the administrators (elevated) and the node's account open the
  pipe. An AppContainer gets no access, nor does a command account whose
  token has the administrators deny-only. Remote clients are refused
  (`PIPE_REJECT_REMOTE_CLIENTS`).
- Every request from a process in the job object of a command the node runs
  is refused, `status` included: the node lists the processes of every job
  it holds open (`JobObjectBasicProcessIdList`, nested jobs included) and
  looks for the caller's process id (`GetNamedPipeClientProcessId`). While
  a command runs without a job, and for a caller whose id Windows does not
  tell, every request is refused.
- The node makes the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`
  and makes the next one before it hands a connection on, so the pipe always
  has one of its own. A node that cannot make the pipe (another process made
  one of that name first) logs it and runs on without it.
- The CLI opens the pipe for identification only and sends nothing unless
  its owner is SYSTEM, the administrators or the node's account (`nerve` for
  the installed node, else the CLI's own). When the pipe is another's and no
  node holds `keys.lock` (none runs), the CLI writes the change to
  `node.toml` itself, as with no pipe at all; with a node running it stops
  with an error that says how to free the name.

Not covered: a process another program starts for a command (the task
scheduler, WMI) is in no job of the node's; it opens the pipe only if its
account may. A sudo command (an administrator token) and a command of a node
run by hand (the node's own account) pass the DACL; the job check stops them
on the pipe, but they can still change `node.toml` itself. On Windows, allow
commands only to centers you would also give `settings = write`, or install
the node as a service.

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
