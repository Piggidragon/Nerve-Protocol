# Nerve Protocol, version "0"

This is the wire protocol between a **node** (a machine that offers
capabilities) and a **center** (the server harnesses plug into). The
implementations in this repository are `nerve-node` and `nerve-center`. The
conformance suite in `crates/nerve-conformance` checks the rules below; each
check names the section it tests.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Versions

- The protocol version is the string `"0"`. A node lists the versions it
  speaks in `hello.versions`; the center picks one it speaks too and names it in
  `welcome.version`. Version `"0"` matches only `"0"` exactly.
- If no version matches, the center sends `bye {reason: "unsupported_version"}`
  and closes. The node stops dialling that center.
- The descriptor carries `nerve: "0"`.

## 2. Identity

### 2.1 Center

- The center holds a TLS key and a self-signed certificate. Its **pin** is the
  base64url (no padding) SHA-256 of the certificate's SubjectPublicKeyInfo, 43
  characters.
- The center has an id (a UUID-shaped random string) and a name.

### 2.2 Node

- A node holds one Ed25519 key per center it is paired with.
- The **node id** is the lowercase base32 (RFC 4648 alphabet, no padding) of the
  first 16 bytes of SHA-256 of the 32-byte raw public key: 26 characters.
- A **node name** is 1 to 32 characters of `a-z`, `0-9` and `-`. The default is
  derived from the host name.

## 3. Pairing

### 3.1 Pairing link

```
nerve://pair?center=<percent-encoded center URL>&code=<code>&pin=<pin>
```

- `center` is an `https://` URL, or `http://` to a loopback address. No user
  info, query or fragment; the path MUST NOT contain `.` or `..` segments.
- `code` is 1 to 64 characters `A-Za-z0-9`. `pin` is optional; without it the
  node checks the certificate against the system roots.
- A parser MUST refuse: unknown keys, a key given twice, bad percent escapes, a
  fragment, a link longer than 4096 bytes.
- The node MUST show the owner the center URL and the defaults it will store
  (mode `allowlist` with no rule, so every call is refused until the owner
  allows something; settings grant `off`) and store nothing before the
  owner confirms.

### 3.2 Pair request

`POST <center>/nerve/v0/pair` with `Content-Type: application/json`:

```json
{"code": "…", "name": "laptop", "platform": "linux", "arch": "x86_64",
 "public_key": "<64 hex chars>"}
```

Unknown fields are refused. Answers:

| Status | Body | Meaning |
|---|---|---|
| 200 | `{"center_id", "center_name", "node_id"}` | paired |
| 400 | `{"error"}` | malformed request or name |
| 403 | `{"error"}` | code unknown, used, expired or out of tries |
| 409 | `{"error"}` | another node already has this name or key |

- A code is valid for the lifetime the owner set when it was made (10 minutes
  by default, at most 24 hours), for one successful pairing, and for 10 tries
  in all; a wrong code counts against every open code.
- The center MUST compute `node_id` from `public_key` itself.

### 3.3 Unpairing

- The node owner unpairs: the node sends `bye {reason: "unpaired"}` if a link
  is up, deletes its key, and the center forgets the node when it sees that bye.
- The center owner removes a node: the center sends `bye {reason: "revoked"}`
  and closes; the node stops dialling that center (it keeps its key so the
  owner can see what happened, until `center rm`).

## 4. Link

### 4.1 Connect

- The node opens `GET <center>/nerve/v0/connect` as a WebSocket, with the
  header `Nerve-Node: <node id>`. Over `https` the node checks the pin (or
  system roots). Over `http` only loopback is allowed, and on Linux the node
  MUST check that the listening socket belongs to its own user.
- An unknown node id is answered with HTTP 401. The node stops dialling and
  tells the owner the center no longer knows it.

### 4.2 Handshake

1. Center → node, notification `challenge {nonce, center_id}`: `nonce` is 32
   random bytes as 64 hex characters.
2. Node → center, notification `hello`:
   ```json
   {"node_id": "…", "auth": {"sig": "<128 hex>"}, "versions": ["0"],
    "software": {"name": "nerve-node", "version": "…"},
    "limits": {"message_bytes": 4194304, "blob_bytes": 67108864, "calls": 64, "streams": 16},
    "rev": 7}
   ```
   `sig` is the Ed25519 signature over the bytes
   `"nerve-connect/0" || center_id (UTF-8) || nonce (32 raw bytes)`.
3. Center → node, notification `welcome {version, limits}`.

Before `welcome`, any other message is a protocol error: the receiver sends
`bye {reason: "protocol_error"}` and closes. A wrong signature or a `node_id`
that differs from the header closes with `protocol_error`. Each side has 15
seconds for its handshake step.

After `welcome` the center fetches the descriptor with `describe {detail:
"full"}`.

### 4.3 One live link per node

When a second link authenticates for a node that already has one, the center
sends a WebSocket ping on the held link and waits 3 seconds. If the held link
answers, the new link is refused with `bye {reason: "duplicate"}` and the
center raises an alert (a copied key). If not, the held link is closed with
`bye {reason: "replaced"}` and the new link takes its place.

### 4.4 Liveness

The node pings every 20 seconds. Either side treats 45 seconds without any
frame as a dead link.

### 4.5 Ending a link

`bye {reason}` is the last message on a link. Reasons: `shutdown`, `paused`,
`unpaired`, `revoked`, `duplicate`, `replaced`, `unsupported_version`,
`protocol_error`. The node MUST stop dialling after `revoked`, `unpaired` and
`unsupported_version`. A node that knows it is about to lose the network (a
suspend, an address change) sends the event `node/going_away {reason}` first,
so the center can show why it dropped.

There is no resume. When a link ends, calls in flight on it fail with
`connection_lost`, and commands it started are killed.

### 4.6 Reconnect

The node redials with a back-off starting at 1 second and doubling to 60
seconds; each wait loses a random part of up to 10 %. The back-off resets once
a link has lasted 60 seconds.

### 4.7 Proxies

A node MAY reach a center over an HTTP `CONNECT` proxy (`connection.proxy` in
its config, else `HTTPS_PROXY`/`NO_PROXY`). The inner TLS is still pinned. If
the proxy fails the node does not fall back to a direct connection. The pair
request (§3.2) to an `https` center goes through the same proxy.

An `http://` proxy takes the `CONNECT` in plain HTTP. An `https://` proxy is
reached over TLS of its own first, checked against `connection.pin` as a
center's certificate is against its pin (§2.1), else against the system
roots; the `CONNECT` and its `Proxy-Authorization` travel inside that TLS,
and the link's own TLS to the center inside the tunnel.

### 4.8 Relays

A node in a network that reaches no center MAY reach one through another
node, its **relay** (a jump node). This is a transport binding below the
message layer: the relay carries bytes, never messages.

- The relayed node names the relay as its `https://` proxy (§4.7) with the
  pin of the relay's certificate, and authenticates with
  `Proxy-Authorization: Basic base64(<name>:<token>)`, the relay node name and
  token the relay's owner gave it. Everything above the tunnel is the relayed
  node's link as without a relay: TLS to the center with its pin, the
  `Nerve-Node` header and the signed `hello`, end to end.
- A relay is off unless its owner turns it on. It speaks TLS only, with a
  certificate of its own (its key kept as the node's other keys are). A
  connection that does not start with a TLS handshake is answered `400` in
  plain HTTP and closed; nothing it sent is used. Over TLS it answers
  `CONNECT host:port` only:
  - `407` with `Proxy-Authenticate: Basic` unless the name and token are
    those of a node it knows. It MUST check this before it looks at the
    target, so a peer without a token learns nothing of its centers;
  - `403` unless `host:port` is the host (without case) and port of an
    `https` center the relay itself is paired with, that has not revoked it
    and still knows it (no `bye revoked`, no 401), and, when the owner gave
    the node a list of centers, every such center at that host and port is
    on the list (centers behind one reverse proxy share it; the relay cannot
    tell them apart, so it grants them together or not at all). A center off
    the list MUST get the same answer as one the relay does not have. The
    relay MUST NOT
    open a tunnel anywhere else: not to an `http` center (it is on the
    relay's loopback), not to any other port of its machine or network. An
    `https` center the relay is paired with at a loopback address (or
    `localhost`) is a target; a center paired at a name is not reached on
    this machine: when the relay dials it directly and the name resolves to
    a loopback or unspecified address, the tunnel is refused with `502`.
    Through the relay's own proxy the next hop resolves the name;
  - `503` when it is off, when its node is locked, or when a limit is reached
    (tunnels at once over all nodes and per node, tunnels a node opens a
    minute);
  - `502` when it cannot reach the center;
  - `200` once it has a connection to the center. From then on it copies
    bytes both ways and nothing else.
- The relay dials the center as its own link would, through its own proxy if
  it has one (§4.7). A chain of relays follows the same rules at each hop:
  each one tunnels only to centers it is paired with itself.
- What a tunnel reaches is the center's host and port, from the relay's
  address: whatever is served there (other names and paths of a reverse
  proxy) as much as the center, since what goes inside the tunnel (the TLS
  server name, the HTTP `Host`, the path) is the relayed node's. An owner
  judges a token by that.
- A relay keeps at most a few undecided connections per peer (an IPv4
  address, or an IPv6 /64), and a bounded number in all; one over either is
  closed unread. The first byte, TLS and the `CONNECT` head share one
  deadline of 15 seconds. Refusals without a valid token are not logged one
  by one but counted, so a peer cannot flood the relay's log; nor are a
  node's refusals for a limit. A node opens a bounded number of tunnels a
  minute, so one with a token cannot rotate the audit log either.
- A relay MUST end a tunnel when its owner turns the relay off, takes the
  node's token away or the center off the node's list, unpairs the center or
  locks the node, and when the tunnel carried nothing either way for 90
  seconds by the monotonic clock (a link pings every 20 seconds, §4.4).
- A relay keeps no token in clear at rest. `nerve-node` keeps the SHA-256 of
  each token in `node.toml`. The relayed node keeps its token with its own
  keys.
- The relay writes one audit entry per tunnel when it ends: the node, the
  center, the peer's address, start, end, why it ended and the bytes each
  way; never a token.
- The relay can cut a relayed node off but cannot read or alter its link:
  an altered byte fails the TLS record, and the link ends before any message
  of it counts. The relayed node's policy is its own; the relay's policy is
  not asked, and no call runs on the relay for a tunnel.

## 5. Messages

Text frames carry JSON-RPC 2.0. No batches; `params` is always an object.
Errors carry a string code in `error.data.code` (§5.3).

### 5.1 Methods

| Method | Kind | Direction | Params | Result |
|---|---|---|---|---|
| `challenge` | notification | C→N | `{nonce, center_id}` | |
| `hello` | notification | N→C | see §4.2 | |
| `welcome` | notification | C→N | `{version, limits}` | |
| `describe` | request | C→N | `{detail, cap?}` | descriptor (§6) |
| `invoke` | request | C→N | `{cap, action, args, ctx, deadline_ms?, blobs?}` | action result |
| `progress` | notification | N→C | `{id, data}` | |
| `cancel` | notification | C→N | `{id}` | |
| `get` | request | C→N | `{cap, keys}` | `{key: value}` |
| `sub` / `unsub` | request | C→N | `{topics}` | `{}` |
| `event` | notification | N→C | `{cap, name, seq, ts, data}` | |
| `state` | notification | N→C | `{cap, seq, ts, changed}` | |
| `stream.open` | request | C→N | `{cap, stream, params}` | `{sid}` |
| `stream.close` | request | either | `{sid, reason}` | `{}` |
| `session.end` | notification | C→N | `{session}` | |
| `bye` | notification | either | `{reason}` | |

- `detail` is `summary`, `capability` (needs `cap`) or `full`.
- `ctx` is `{session?}`: `session` is at most 256 bytes. Other fields are
  refused. There is no field for "allowed", a mode or a folder.
- `deadline_ms` is a duration in milliseconds from receipt; past it the node
  fails the call with `timeout`.
- `progress.id` and `cancel.id` are the `invoke` request id.
- Topics are `<cap>/<event>`, `<cap>/state` or `<cap>/*`. Events of the `node`
  and `settings` capabilities are implicit: they are sent without
  `sub`. Everything else needs one.
- `seq` counts per capability from 1 within a link; `ts` is milliseconds since
  the Unix epoch.

### 5.2 Strictness

A node MUST be strict about what a center sends: unknown fields in `invoke`,
`ctx` and `challenge`, and unknown methods, are refused. A center SHOULD be
tolerant of unknown fields a node sends, so newer nodes keep working.

### 5.3 Error codes

| Code | JSON-RPC code | Meaning |
|---|---|---|
| `invalid_args` | -32602 | arguments do not match the action |
| `forbidden` | -32001 | policy refuses: no rule allows the call, or a rule forbids it |
| `disabled` | -32004 | the capability or action is off |
| `unavailable` | -32005 | the node or capability is not reachable now |
| `busy` | -32006 | too many calls or commands running |
| `timeout` | -32007 | the deadline passed |
| `cancelled` | -32008 | cancelled by the caller |
| `too_large` | -32009 | over a size limit |
| `unknown_capability` | -32010 | no such capability (or hidden) |
| `unknown_member` | -32011 | no such action, event or stream |
| `connection_lost` | -32012 | the link ended during the call |
| `internal` | -32603 | a bug or an unexpected failure |

Profiles add codes of their own: `conflict` (stale `if_match`/`if_version`),
`bad_path`, `io`. Their JSON-RPC code is -32000. `parse`, `invalid_request` and
`method_not_found` use the JSON-RPC codes -32700, -32600 and -32601.

### 5.4 Binary frames

Binary WebSocket frames have a 10-byte header, big-endian:

```
u8 kind | u8 flags | u32 id | u32 seq | payload (at most 65536 bytes)
```

- kind 1: blob chunk. `id` is the blob id named as `{"$blob": id}` in a JSON
  message and listed in `invoke.blobs`; `seq` counts from 0; flag bit 0 marks
  the last chunk. A blob larger than `limits.blob_bytes` fails with `too_large`.
- kind 2: reliable stream data; `id` is the stream's `sid`.
- kind 3: media, reserved. In version "0" it is refused (`protocol_error`).

Each side keeps at most 64 frames queued for sending; a full queue pushes back
on the producer.

### 5.5 Limits

`limits` in `hello` and `welcome` announce what each side accepts: message
bytes (default 4 MiB), blob bytes (64 MiB), concurrent calls (64), streams (16).
A message over the receiver's limit closes the link with `protocol_error`; a
call over the call limit fails with `busy`.

## 6. Descriptor

```json
{"nerve": "0",
 "node": {"id": "…", "name": "laptop", "platform": "linux", "arch": "x86_64",
          "software": {"name": "nerve-node", "version": "…"}},
 "rev": 7,
 "summary": "Linux laptop of the owner (under 60 words)",
 "capabilities": [
   {"id": "fs", "profile": "fs", "provider": "node", "exposure": "on",
    "summary": "…",
    "actions": {"read": {"effect": "read", "summary": "…",
                         "params": {JSON Schema}, "result": {JSON Schema}}},
    "events": {}, "state": null, "streams": {}}]}
```

- Capability ids and action names use ASCII letters, digits and `-`, never
  `_`: a harness joins node, capability and action with `_` into one tool
  name (`docs/dev/spec/harness.md`), and a `_` inside a part would make that name
  ambiguous. A center ignores a descriptor with a name outside that set.
- Effects: `read`, `sense`, `write`, `actuate`, `execute`.
- Exposure: `on`, `off`. A capability that is `hidden` for a center is
  absent from that center's descriptor; `off` is listed with exposure `off`.
- The descriptor is filtered per center. `rev` changes whenever that center's
  view changes; the node then sends `node/descriptor_changed {rev}` and the
  center fetches the descriptor again.
- `detail: "summary"` drops `params`, `result` and schemas;
  `"capability"` returns only `cap`, in full; `"full"` returns everything.

## 7. Profiles

Shapes are given as `params → result`. Paths are absolute; on Windows they use
the wire form `/c/Users/…`.

### 7.1 `node` (always present)

- state: `{status: "online" | "busy" | "paused"}`.
- events (implicit): `descriptor_changed {rev}`, `going_away {reason}`,
  `capability_changed {cap}`.

### 7.2 `fs`

| Action | Effect | Params → result |
|---|---|---|
| `stat` | read | `{path}` → `{type: "file"|"dir"|"link"|"other", size, mtime_ms}` |
| `list` | read | `{path}` → `{entries: [{name, type, size}]}` |
| `read` | read | `{path, offset?, length?}` → `{content, encoding: "utf8"|"base64", size, etag}` |
| `grep` | read | `{path, pattern, glob?, max?}` → `{matches: [{path, line, text}], truncated}` |
| `find` | read | `{path, glob, max?}` → `{paths, truncated}` |
| `write` | write | `{path, content, encoding?, if_match?}` → `{etag, size}` |

`etag` is the hex SHA-256 of the file's bytes. A `write` with an `if_match`
that no longer matches fails with `conflict`. fs and exec calls run
concurrently.

### 7.3 `exec`

| Action | Effect | Params → result |
|---|---|---|
| `run` | execute | `{command, cwd?, timeout_ms?}` → `{exit_code, signal?, stdout, stderr, truncated}` |
| `signal` | actuate | `{call, signal: "term"|"kill"|"int"}` → `{}` |

- `command` is a string run by the node's shell. `call` is the `invoke` id of a
  running `run`.
- state: `{shell, confinement}`; event `exit {call, exit_code}` (needs `sub`).
- Output is capped at `limits.output_cap_bytes` of the node's config;
  `truncated` says it was cut. Output comes in the result; the
  `output` reliable stream is declared for later.

### 7.4 `settings` (only with the settings grant `write`)

- `get {cap: "settings", keys: ["document", "version"]}` → `{document,
  version}`; `document` is this center's entry of the node config (policy,
  folders, caps, command rules).
- actions: `set {document, if_version}` → `{version}` (effect `write`); a stale
  `if_version` fails with `conflict`; a change to a client-only field refuses
  the whole document with `forbidden` and names the field. One field of the
  document is the owner's without being refused: `policy.places`, the node's
  record of the folders it recorded at their real place. A `set` keeps it as
  it was (less the entries of folders the document removes), whatever the
  document says there. `pause {}` → `{}`.
- `get` key `sudo` → `{sudo: "on" | "off"}`: the node's sudo switch.
- event (implicit): `changed {version}`.

### 7.4.1 The sudo switch

A center with the settings grant `write` may switch the node's sudo switch
(node-local §4) on and off; it is the only machine setting a center may
change. The password travels sealed end to end from the client (the owner's
browser or tool) to the node; the center only relays it.

- `sudo-offer {}` → `{offer, key, ts, sig}` (effect `write`): `offer` is 16
  random bytes and `key` a fresh X25519 public key, both base64; `ts` is the
  node's clock in ms; `sig` is the hex Ed25519 signature, with the node's key
  for this center (§2.2), of the UTF-8 bytes
  `"nerve-sudo-offer\n" + center_id + "\n" + offer + "\n" + key + "\n" + ts`.
  A client checks it against the key the node paired with. A new offer
  replaces the center's open one.
- The client makes its own X25519 key, derives a key with HKDF-SHA256 (salt
  `"nerve-sudo-v1"`, info `offer`) from the shared secret, and seals the JSON
  `{password, offer, ts}` (its own clock in `ts`) with AES-256-GCM, a random
  12-byte nonce `iv` and `offer` as associated data.
- `sudo {on: true, sealed: {offer, key, iv, ct}}` → `{sudo: "on"}` (effect
  `write`; `key`, `iv` and `ct` base64). The node opens an offer at most once,
  right or wrong, and only within 60 s of making it; the inner `offer` must
  match and the inner `ts` be within 60 s of the node's clock. A replayed,
  late, tampered or foreign box is `invalid_args`, and so is a password that
  `sudo -v` refuses, or on Windows the account's logon (the message says the
  password is wrong; node-local §4); the switch then stays as it was.
- `sudo {on: false}` → `{sudo: "off"}` drops the password.
- The password never appears in a frame the node sends.

### 7.5 `audit`

- event `decision {ts, cap, action, target, decision, code?, session?}`
  (needs `sub`); `decision` is `allowed` or `forbidden`.

## 8. Center side

The center serves harnesses. `nerve-center` is an MCP server ([harness.md](harness.md)). It maps capabilities to tools, holds sessions, and never stores file contents, command output or secrets.
