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
elevation = "off"           # not done in 0.0.1

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
mode = "folder"             # folder | user (the default is folder)
user_until = 0              # required with user: falls back to folder then
folders = [{ path = "/home/u/proj", access = "rw", execute = true }]
caps = { "fs.write" = "off" }   # on | off | hidden
deny = ["~/private"]        # paths nothing may touch
protected = { extra = [], allow = [] }

[center.policy.commands]    # globs over the whole command line
deny = []                   # never run
allow = []                  # when not empty, only these run at all
permit = []                 # run in any mode unless the call is tainted
```

Unknown keys are refused, with one exception: a `node.toml` written by an
earlier build is migrated when it is read (§3.1). Two centers with one name are refused. Folder paths
are absolute in the platform's own form; on the wire they travel as
`/c/Users/...` on Windows (protocol §7.2).

## 3. Deciding a call

The default is deny. A call runs only when the mode or a rule allows it;
otherwise it is refused at once with `forbidden`, and nothing waits for an
answer. For each call the node takes the center's policy and, in this order:

1. A `locked` node (after `panic`) keeps no links and runs nothing; a paused,
   revoked or unknown center is not dialled.
2. The capability setting: `off` refuses (`forbidden`), `hidden` leaves it
   out of the descriptor.
3. Protected paths (keys, shell profiles, the node's own folders and the
   built-in list) and `deny` paths: `forbidden`, in every mode.
4. Command rules, with wildcards over the whole command line: a command
   matching `deny` is refused; when `allow` is not empty, only commands
   matching it run at all.
5. The mode. `folder` (the default) allows a read inside a folder, a write
   inside a folder with `rw` access, and a command whose working directory is
   in a folder with `execute` (confined where the platform can confine it);
   with no folder it allows nothing. `user` allows reads, writes and commands
   everywhere the user could, until `user_until` (at most 8 hours), then the
   center is back in `folder`. Actions with the effect `sense` or `actuate`
   are allowed by no mode: only the owner's `caps` entry `on` allows them.
6. `permit` allows a command in any mode.
7. A call the center marks tainted (`ctx.tainted`, it has read device content
   in that session) is refused for any write or command, whatever allowed it.
   Protected paths stay refused in `user` mode too.

There is no sudo mode in 0.0.1. Every refusal names its reasons in the error
and in the audit log.

### 3.1 Older files

An earlier build had a mode `ask` and asked the owner. A `node.toml` or a
settings document that still has the old values loads, and everything that
asked now refuses: mode `ask` becomes `folder` without its folders, a
capability `ask` becomes `off`, `always_ask` rules join `deny`, `never_ask`
is `permit`, `folders` is `folder`, `full` is `user` (`full_until` is
`user_until`), and the `approvals` entries are dropped.

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

`config.write` and `reload` are refused from a process that runs below a
command the node started for a center, so an agent cannot change its own
policy.

## 6. Audit log

`<state>/audit.jsonl`, one JSON line per event: settings changes and calls allowed
or forbidden. It holds targets (paths, command lines), never
file content or output. `nerve-node audit [--denied] [--follow]` shows it.
