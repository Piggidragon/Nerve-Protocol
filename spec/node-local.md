# The node's own side: config, policy, control socket

This part is not wire protocol: a center never sees it directly. It describes
how `nerve-node` decides, so that other node implementations can behave the
same way and so the owner knows what each setting does.

## 1. Folders

| What | Default | Override |
|---|---|---|
| `node.toml` and one key per center | `~/.config/nerve` | `--config-dir`, `NERVE_CONFIG_DIR` |
| control socket `run/ctl.sock`, audit log `audit.jsonl` | `~/.local/state/nerve` | `--state-dir`, `NERVE_STATE_DIR` |

`node.toml` is written private to the owner (mode 0600 on Unix). The daemon
refuses to run as root unless `machine.allow_root = true`.

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
proxy = "http://proxy:3128" # optional; HTTP CONNECT
headers = {}                # extra headers on the link request

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
user_until = 0              # required with user: falls back to folder then
folders = [{ path = "/home/u/proj", access = "rw", execute = true }]  # folder mode
caps = { "fs.write" = "off" }   # on | off | hidden
protected = { extra = [], allow = [] }
allow = ["exec.run:git status", "fs.read:~/notes/*"]   # allowlist mode only
deny = ["fs:~/private/*", "exec.run:rm *"]             # every mode
sudo_allow = ["sudo apt update"]                       # sudo commands, every mode
```

Unknown keys are refused, and so is a rule that does not parse. Two centers
with one name are refused. Folder paths are absolute in the platform's own
form; on the wire they travel as `/c/Users/...` on Windows (protocol §7.2).

### Modes

- **allowlist** (the default after pairing): default deny. A call runs only
  when an `allow` rule lets it through. `folders` do not count.
- **folder**: full access inside the `folders` (and everything below them),
  by their access; commands run in `execute` folders, confined where the
  platform can confine them. `allow` rules do not count.
- **user**: full access as the user, protected paths aside, until
  `user_until` (at most 8 hours), then the center is back in `folder`.
  `allow` rules do not count.

`deny` rules count in every mode and a matching deny always wins. Sense and
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

The four buttons of the center's audit view and `nerve-node allow|deny
[--wildcard]` write exactly these forms: exact (`exec.run:git status`) or
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
8. Protected paths (keys, shell profiles, the node's own folders and the
   built-in list) are refused whatever allowed the call, `user` mode too.

Every refusal names its reasons in the error and in the audit log.

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
  refused. The node runs it as `sudo -S -k -p '' …` with the password on its
  stdin and without Landlock (which would stop sudo from gaining privileges).
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
switch, never through `config.write`. The switch works on Linux only in
0.0.1.

## 5. Control socket

`<state>/run/ctl.sock` (Unix only in 0.0.1; on Windows the CLI edits
`node.toml` directly). One JSON object per line: the client sends
`{"method", "params"}`, the server answers `{"ok": value}` or
`{"error": "text"}`, or, for streaming methods, several `{"item": value}`
lines until it closes. The socket is 0600 in a 0700 folder; only its own user
or root may talk to it. Methods:

| Method | Params | |
|---|---|---|
| `status` | | daemon and links |
| `config.read` | | `node.toml` and its `version` |
| `config.write` | `config`, `if_version` | replaces it when the version matches |
| `reload` | | rereads `node.toml` |
| `sudo.status` | | `{sudo: "on"|"off"}` |
| `sudo.on` | `password` | checks it with `sudo -v` and turns the switch on (§4) |
| `sudo.off` | | turns the switch off and drops the password |

`config.write`, `reload`, `sudo.on` and `sudo.off` are refused from a process that runs below a
command the node started for a center, so an agent cannot change its own
policy.

## 6. Audit log

`<state>/audit.jsonl`, one JSON line per event: settings changes and calls allowed
or forbidden. It holds targets (paths, command lines), never
file content or output. `nerve-node audit [--denied] [--follow]` shows it.
