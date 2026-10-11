# The node's own side: config, policy, approvals, control socket

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
approvals = "both"          # both | local: who answers this node's questions
paused = false              # the center may pause; only the owner unpauses
revoked = false             # the center sent `bye revoked`
unknown = false             # the center answered 401

[center.policy]
mode = "ask"                # ask | folders | full
full_until = 0              # required with full: falls back to folders then
folders = [{ path = "/home/u/proj", access = "rw", execute = true }]
caps = { exec = "ask", "fs.write" = "off" }   # on | ask | off | hidden
deny = ["~/private"]        # paths nothing may touch
protected = { extra = [], allow = [] }

[center.policy.commands]    # globs over the whole command line
deny = []                   # never run
allow = []                  # when not empty, only these run at all
always_ask = []
never_ask = []              # run without asking unless the call is tainted

[center.policy.approvals]
timeout_s = 120
on_timeout = "deny"         # deny | allow (this one call)
remember_minutes = 480      # longest `session` answer
max_minutes = 480           # longest `time` answer
```

Unknown keys are refused. Two centers with one name are refused. Folder paths
are absolute in the platform's own form; on the wire they travel as
`/c/Users/...` on Windows (protocol §7.2).

## 3. Deciding a call

For each call the node takes the center's policy and, in this order:

1. A `locked` node (after `panic`) keeps no links and runs nothing; a paused,
   revoked or unknown center is not dialled.
2. Protected paths (keys, shell profiles, the node's own folders and the
   built-in list) and `deny` paths: `denied`, in every mode.
3. Command rules: `deny`, then `allow` when it is not empty: `denied`.
4. The capability setting: `off` refuses, `hidden` leaves it out of the
   descriptor, `ask` asks.
5. The mode: `ask` asks for every read, write and command; `folders` allows
   inside a folder by its access and asks outside; `full` allows everywhere
   until `full_until`.
6. `never_ask` allows a command in any mode; `always_ask` asks where the mode
   would allow.
7. A call the center marks tainted (`ctx.tainted`, it has read device content
   in that session) asks before any write or command, whatever allowed it.

Execute answers are strict: a command can be allowed once or denied, never for
a session.

> **Open point p04.** The modes keep the architecture's names `ask`, `folders`
> and `full`; whether they become Folder/User/Sudo is not decided.

## 4. Approvals

A call that asks waits in the node's pending queue. With `approvals = "both"`
the center hears `approvals.requested` and may answer; the owner may always
answer locally (`nerve-node approve|deny <id>`). The first answer wins; later
answers are refused. Answers: `once`, `session` (until `remember_minutes`),
`time` (`--minutes`, at most `max_minutes`), `deny`. With no answer within
`timeout_s`, `on_timeout` applies.

> **Open point.** Approvals are a node-side queue in 0.0.1; they are not asked
> through MCP elicitation.

## 5. Control socket

`<state>/run/ctl.sock` (Unix only in 0.0.1; on Windows the CLI edits
`node.toml` directly). One JSON object per line: the client sends
`{"method", "params"}`, the server answers `{"ok": value}` or
`{"error": "text"}`, or for `approvals.follow` several `{"item": value}`
lines until it closes. The socket is 0600 in a 0700 folder; only its own user
or root may talk to it. Methods:

| Method | Params | |
|---|---|---|
| `status` | | daemon and links |
| `config.read` | | `node.toml` and its `version` |
| `config.write` | `config`, `if_version` | replaces it when the version matches |
| `reload` | | rereads `node.toml` |
| `approvals.list` | | open approvals |
| `approvals.answer` | `center?`, `id`, `answer`, `minutes?` | |
| `approvals.follow` | | streams new approvals |

`config.write`, `approvals.answer` and `reload` are refused from a process
that runs below a command the node started for a center, so an agent cannot
answer its own questions.

## 6. Audit log

`<state>/audit.jsonl`, one JSON line per event: settings changes, calls asked,
allowed or denied and by whom. It holds targets (paths, command lines), never
file content or output. `nerve-node audit [--denied] [--follow]` shows it.
