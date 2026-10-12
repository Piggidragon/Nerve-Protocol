# Logs

The center and every node keep a log of what they do: links that drop and come
back, pairing, changes to settings, calls that were refused or failed, errors,
and start and stop. Use it to find out why a machine is offline or why a
call did not go through.

The log is not the [audit log](audit.md). The audit log records the node's
decision about every call, including the ones it allowed. The log does not
record a call that worked.

## Where it is

| Program | File |
|---|---|
| Center | `log.jsonl` in the center's state folder |
| Node | `log.jsonl` in the node's state folder |

The state folders are listed under [where files live](install.md#where-files-live).
The file is readable by its owner only. At 5 MiB the program moves it to
`log.jsonl.1`, which replaces the older copy, so a log takes at most about
10 MiB. The node writes it while `nerve-node run` is running.

The center's [web UI](web-ui.md#log) shows its log, and its **Download the
file** link gives you `log.jsonl.1` and `log.jsonl` as one file. Both programs
also print every line on stderr.

Each line is a JSON object:

```json
{"ts":1791900202123,"level":"warn","node":"web-1","node_id":"4f1c…","msg":"link dropped: no frame from the node for 45 s, not even a ping (it was up for 3 h 2 min)"}
```

| Field | Is |
|---|---|
| `ts` | Milliseconds since the Unix epoch |
| `level` | `error`, `warn`, `info` or `debug` |
| `node` | In the center's log, the machine the line is about, by its name at that time |
| `node_id` | Its id, which a rename does not change |
| `msg` | What happened, in one line, at most 1000 characters |

A node that comes back says how long it was away. After a link that went quiet,
the time counts from the last frame the node sent.

## Levels

A level includes the ones above it in this table.

| Level | Is for |
|---|---|
| `error` | Something the program could not handle and you have to act on |
| `warn` | Something wrong that the program handled: a link lost, a call that failed |
| `info` | Normal use: links, pairing, changes, refused calls. The default |
| `debug` | Detail for tracking down a problem |

A change of the level applies to the next line.

| Where | How |
|---|---|
| Center | **Settings** in the web UI, or `--log` (`NERVE_LOG`) |
| Node | `nerve-node config set log.level debug` |

The center keeps the level you set in the web UI for the next start. `--log`
sets the level for one run and wins over the stored one. A running node takes
a new `log.level` within a second.

## What the center logs

| Level | Lines |
|---|---|
| `error` | The state file cannot be written. A call failed inside the center or the node (`internal`) |
| `warn` | A link dropped without a bye, or went quiet (no frame for 45 s). A link failed authentication, or the node speaks another protocol version. A second link while the first is alive (the key may be copied). A description of a node that cannot be used. A pairing was refused: the code is unknown, used, expired or out of tries (one line in ten seconds, with the number left out), or the name or key is taken. Pairing codes ran out of tries. A call failed: the node is offline, busy, too slow, or the link ended. A node refused a change from the web UI. A wrong token at the web UI sign-in, and the lock after too many |
| `info` | The center started and stopped. A link came up, with how long the node was away if it was; a link closed with a bye, with how long it was up. A node is going away, or changed its settings. A pairing code was made, or expired unused. A node paired, was renamed, disabled, enabled, removed or unpaired itself. A harness session started or ended. A call was refused, by the node's rules or because the node is disabled here. A call failed because of its own arguments or the node's answer (a missing file, a bad path). A harness token was made or deleted. Someone signed in to the web UI. Settings, a rule or the sudo switch were changed from the web UI. The center's settings or the log level were changed |
| `debug` | A handshake that did not finish. A node that is not paired tried to connect. A pairing request in a wrong form. A node's description changed. A call was cancelled |

The line for a refused or failed call names the action and the reason the node
gave, cut at 300 characters:

```
fs.read was refused (forbidden): no allow rule matches /etc/hostname
exec.run failed (timeout) after 30 s: the node did not answer in time
```

A reason can quote the path or command line of the call. The audit log has the
whole call.

## What the node logs

| Level | Lines |
|---|---|
| `error` | A key or the center's address or the proxy cannot be used, so the node stops dialling that center. The audit log or `node.toml` cannot be written. The control socket stopped |
| `warn` | The node cannot reach a center (the first time after a link, the rest are `debug`). A handshake failed. A link closed without a bye, or went quiet. A center said bye because of a duplicate or an error, or ended the pairing, or does not know this node. A reload of `node.toml` was refused. A call failed |
| `info` | The node started and stopped. It linked to a center, and when it will dial again after a link ended, with the wait. A center said bye, or the node closed the link and why. A change to the settings, by whom, the new version and each setting that changed. A call was refused, with the reason. A call failed because of its own arguments or the files it named |
| `debug` | Each dial. The dials that follow a failed one. A reload that changed nothing |

The line for a change to the settings names the setting and, for a plain value,
the old and the new one. For a list it names what was added (`+`) and what was
removed (`-`). It never shows a setting of the proxy:

```
settings changed by center lab (version 7): center.lab.policy.mode: allowlist -> folder
settings changed by local (version 8): center.lab.policy.allow +fs.read:~/notes/*; machine.sudo: off -> on
```

A change made with `nerve-node` while the node is not running is not in the
log; the audit log has it.

## What is never in it

- A call that worked. That is in the node's audit log.
- File contents and command output.
- The sudo password, a harness token, the token typed into a wrong sign-in, a
  pairing code, the node's key, a proxy's header values.

The programs do not put a secret into a line. As a second guard, every line is
checked before it is kept: a value after a name like `password`, `token`,
`secret`, `api_key`, `authorization` or `cookie`, a bearer or basic credential,
the user and password in a URL, the `code` of a pairing link and a harness
token (`nrv_…`) are replaced by `[redacted]`. The center also holds back the
harness token it was started with, and the node the sudo password while sudo is
on, wherever they would appear.
