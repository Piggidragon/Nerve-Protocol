# The node's own side: config, policy, control socket

This part is not wire protocol: a center never sees it directly. It describes
how `nerve-node` decides, so that other node implementations can behave the
same way and so the owner knows what each setting does.

## 1. Folders

| What | Default | Override |
|---|---|---|
| `node.toml` and one key per center | `~/.config/nerve` | `--config-dir`, `NERVE_CONFIG_DIR` |
| control socket `run/ctl.sock`, audit log `audit.jsonl`, the config's MAC key `config.key` | `~/.local/state/nerve` | `--state-dir`, `NERVE_STATE_DIR` |

`node.toml` is written private to the owner (mode 0600 on Unix). The daemon
refuses to run as root unless `machine.allow_root = true`.

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
is not done in 0.0.1, for this key as for the center keys.

A file whose MAC is missing or does not match was changed outside the
owner's path. It is refused and the refusal is audited (§6): at start-up the
node does not start; on a reload the old config stays in force. A reload also
refuses a signed file older than the one in force. After looking at a refused
file, the owner takes it as it is with `nerve-node config accept`; the node
then signs it. A `node.toml` from before the node kept a MAC (no key yet, no
MAC line) is taken once as it is and signed.

The check stands on `config.key`. A process that can delete or read it, and a
`user` mode command is one (it runs unconfined as the user), can make the node
take another file at its next start: with the key gone, an unsigned file
counts as one from before the MAC and is signed. The start-up audits that as
`signed`. In `folder` mode Landlock keeps commands out of the state folder.

On Windows there is no control socket in 0.0.1: the CLI writes the signed
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
protected = { extra = [], allow = [] }  # a center may add to extra; only the owner removes or releases
allow = ["exec.run:git status", "fs.read:~/notes/*"]   # allowlist mode only
deny = ["fs:~/private/*", "exec.run:rm *"]             # every mode
sudo_allow = ["sudo apt update"]                       # sudo commands, every mode
```

Unknown keys are refused, and so is a rule that does not parse. Two centers
with one name are refused. Folder paths are absolute in the platform's own
form; on the wire they travel as `/c/Users/...` on Windows (protocol §7.2).

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
user name and password in `connection.proxy`, as earlier builds wrote it, is
refused on load, without the values in the message: take them out of the
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
  platform can confine them. Windows has no file confinement for commands
  yet, so there folder mode refuses every command, and only `allowlist` and
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

In `allowlist` mode a command with `; & | $ \` ( ) < >` or a line break is
covered only by an allow rule that names the whole line, never by a wildcard:
such commands run unconfined, and `git *` must not cover `git x; rm -rf ~`.

## 3. Deciding a call

The default is deny. A call runs only when the mode and the rules allow it;
otherwise it is refused at once with `forbidden`, and nothing waits for an
answer. For each call the node takes the center's policy and, in this order:

0. A call that touches the node's own folders (§1) is `forbidden` before
   anything else is looked at; no rule, mode, folder or release lifts that.
   It looks at every path of an `fs` call (resolved), at the working
   directory of `exec.run`, and at paths the command line names plainly
   (absolute, or from `~/`, `$HOME/`, `${HOME}/`). The line is compared
   without case, with `\` and `/` alike on Windows, with `seg/..` and
   doubled separators folded, with the home in each shell's spelling (also
   `$env:USERPROFILE` and `%USERPROFILE%` on Windows) and with relative
   words taken from the working directory (`..\node-config`). A path a
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
   (the registry hives with the password hashes) and the user's
   `NTUSER.DAT`.

Every refusal names its reasons in the error and in the audit log.

What the center is shown follows the same policy, so that its harness builds
no tool the node would refuse. In `allowlist` mode an `fs` or `exec` action
is in the descriptor only when an `allow` rule covers it by scope: `<cap>`
covers every action of the capability, `<cap>.<action>` that action, with or
without a `:<pattern>`. The pattern is not looked at there; a rule may allow
only some paths or commands, and each call is still decided as above.
`exec.run` is also shown when `sudo_allow` has an entry, since a sudo command
runs by that list alone. In `folder` and `user` mode the actions are shown as
before and allow rules do not matter; deny rules never hide an action.
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
  refused. The node runs it as `sudo -S -k -p <prompt> …` without Landlock
  (which would stop sudo from gaining privileges), with a random prompt per
  command. It writes the password to stdin only after sudo printed that
  prompt; when sudo asks for none (a `NOPASSWD` entry, root), the command
  finds no password on its stdin.
- Every other command runs with `no_new_privs` (Linux), so a `sudo` later in
  a command line, or any setuid program, cannot gain privileges.

The switch is never on without a working password. Turning it on takes the
password from a client: `nerve-node sudo on` (it asks on the terminal) or a
center with the settings grant `write` (protocol §7.4.1, sealed end to end so
the center cannot read it). The node checks it with `sudo -S -k -v` (output
discarded) and refuses a wrong one with `invalid_args`; the switch then stays
as it was. Turning it off drops the password. The password is kept in memory
only (`secret_storage` at rest is not done in 0.0.1), so a restarted node, or
a `node.toml` that says `on` without a password held, has the switch off. It
never reaches a center: the node replaces every copy in an outgoing frame and
in the audit log with `[redacted]`. `machine.sudo` changes only through the
switch; a value written into the file is turned off at start-up, since no
password is held. The switch works on Linux only in 0.0.1.

## 5. Control socket

`<state>/run/ctl.sock` (Unix only in 0.0.1; on Windows the CLI writes the
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

`config.write`, `config.accept`, `reload`, `sudo.on` and `sudo.off` are
refused from a process that runs below a command the node started for a
center, so on Linux an agent cannot change its own policy through the socket.
**Windows in 0.0.1 has no socket and no sandbox:** the CLI signs node.toml
itself, so a command the node runs for a center can change the policy, and
the change applies at the next start. On Windows, allow commands only to
centers you would also give `settings = write`.

## 6. Audit log

`<state>/audit.jsonl`, one JSON line per event: settings changes (with old
and new value), calls allowed or forbidden, and what happened to the config
file itself (`"kind": "config"`, `event` `refused`, `signed` or `accepted`,
with the file and the reason). It holds targets (paths, command lines), never
file content or output; a target longer than 512 characters is cut there
and says so. When the file would pass 10 MiB it is moved to `audit.jsonl.1`,
replacing the older one, so the log keeps at most about 20 MiB.
`nerve-node audit [--denied] [--follow]` shows it.
