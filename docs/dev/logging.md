# Logging

The center and the node each keep a log of what they do, apart from the audit
log. What a user sees is in [logs](../user/logs.md); this page is how it is
built.

## One module

`nerve_transport::log` holds everything both programs share:

| Piece | Does |
|---|---|
| `Level` | `error`, `warn`, `info`, `debug`, in that order of verbosity. `trace` is taken for `debug` |
| `Log` | The level (changeable at any time), a window of the latest 2000 entries, and the file. It also holds the secrets the program knows (`set_secret`) |
| `Entry` | One line: `ts`, `level`, `node`, `node_id`, `msg` |
| `redact` | Takes secrets out of text ([below](#redaction)) |
| `LogLayer` | A `tracing` layer that hands every event to a `Log` |
| `install`, `global` | Make the process's `Log` once and set the layer as the global subscriber |
| `emit` | `tracing` at a level only known at run time |
| `call_line` | The level and the text of a refused or failed call, the same in both programs |

Nothing else formats a log line.

## Two ways in

- **`tracing` macros.** `nerve-center` and `nerve-node` call `install` in
  `main`. After that `tracing::info!`, `warn!` and the rest reach the `Log`.
  The fields `node` and `node_id` say what an event is about; any other field
  is put after the message as `name=value`. The layer asks the `Log` for the
  level on every event and tells `tracing` that no callsite stays disabled, so
  a changed level applies to the next event.
- **`Log::record`.** The center calls it through `Center::note` and
  `Center::log()`. A center holds its own `Log` (`Options.log`, else a private
  one), so the entries of one center are its own and a test needs no global
  subscriber.

The node uses the macros only. Its sites are in many places that have no
handle to the daemon.

## The file

`Log::attach_file` opens `log.jsonl` in the state folder (mode 0600), reads the
latest entries of both files back into the window, then writes what was logged
before the file was attached. A line is one write. At 5 MiB the file is moved
to `log.jsonl.1` and replaces the older one. A file that cannot be opened or
written is told once on stderr; the program goes on with the window.

The center attaches the file in `Center::open`, after it holds the state
folder's lock, so a second `nerve-center` that only attaches to the first does
not write to it. The node attaches it in `Daemon::start`. A CLI command that is
not the daemon writes no log file.

## Levels

- **Center.** The level is in `state.json` (`log_level`), changed in the web
  UI's settings (`POST /api/center`, `Center::set_log_level`). `--log` wins for
  one run (`Options.log_level`) and leaves the stored level alone. A change is
  told in the log while the more verbose of the old and the new level is in
  force, so it is always kept.
- **Node.** The level is `log.level` in `node.toml`. The supervisor sets it
  from the config it holds on every pass, so any writer (the CLI, a reload)
  is followed within a second.

## Redaction

`redact` works on every message before it is kept:

- the value after `password`, `passwd`, `passphrase`, `pwd`, `secret`, `token`,
  `api_key`, `apikey`, `api-key`, `authorization`, `cookie`, `sealed`,
  `private_key` or `credential`, written `name=value`, `name: value` or as
  JSON, in any letter case;
- the credential after `Bearer` or `Basic`;
- `user:password@` in a URL;
- the `code` parameter of a pairing link;
- a harness token, `nrv_` and eight or more characters.

Then the secrets the program holds are replaced by `[redacted]`: the center
registers the harness token from its flag, the node the sudo password while the
switch is on. Then control characters become spaces and the message is cut to
1000 characters.

The scanner is by hand, since the workspace has no regex crate. It works on
bytes and cuts only at ASCII, so it cannot split a character.

The messages the programs write do not name a secret. The pairing code is never
passed to the log. Redaction is the net under text that is only passed on: the
reason of a refusal, an error from the system.

## What the center logs

The calls are logged in `Center::call`, where a result is known:

| Result | Level |
|---|---|
| `forbidden`, `disabled`, a node switched off in the center | `info`, "refused" |
| `unavailable`, `busy`, `timeout`, `too_large`, `connection_lost` | `warn`, "failed" |
| `internal` | `error`, "failed" |
| `invalid_args`, unknown members, the profiles' own codes (`io`, `bad_path`, `conflict`) | `info`, "failed" |
| `cancelled` | `debug` |

`call_outcome` in `nerve_transport::log` has the table, and the node uses the
same one for the calls it answers.

Links are logged where the link task ends (`link.rs`), with the reason in
words. The center keeps when each node's link last ended in memory (`down`),
so the next link says how long the node was away. A link is closed after 45 s
without a frame (`Center::dead_after`); a test shortens it with
`set_dead_after`.

A pairing code that runs out unused is noticed by `Center::sweep_codes`, which
the center calls every five seconds, so its line is at most that late. The
pairing endpoint is open to anyone who reaches the port, so a refusal for a
wrong code is logged once in ten seconds, with the number left out.

## The web UI

`GET /api/log` answers from the window:

| Parameter | Is |
|---|---|
| `level` | The least severe level to show |
| `node` | A node id, or `-` for entries about no node |
| `q` | Text the message or the node's name contains |
| `after` | Only entries numbered above this one |
| `limit` | At most this many, 500 unless given, 1000 at most |

The answer has `entries` (newest first, each with `seq`, `ts`, `level`,
`node`, `node_id`, `msg`), `nodes` (every paired node, and the ones only the
log remembers, with `paired`), the `level` the log is kept at and `file`,
whether there is a file. `GET /api/log/download` sends the file, the older half
first, as `application/x-ndjson` with `Content-Disposition: attachment`. Both
need a signed-in browser like every API call.

The page polls every two seconds. The level and machine lists are the
searchable list of the Statistics page (`picker` in `app.js`); the page builds
its boxes once and fills them in place, so a poll does not cut off what is
typed.

## The node's changes

`SettingsStore::on_change` takes a callback that runs after every saved change
with who made it, the new version and the leaves that differ. The daemon sets
one that logs `describe_change`. The CLI opens the store for one command and
sets none. The paired centers are a list, so the diff names them as one leaf;
`describe_change` looks into each by name. The proxy's settings and the pins
and ids of a center are named, never shown.
