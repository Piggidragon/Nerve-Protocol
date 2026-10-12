# Nerve architecture

Status: the design behind 0.0.1, written before the code. Where this page and `spec/` differ, `spec/` describes what 0.0.1 does; the points that changed are marked "0.0.1:" below. It replaces the Pithagoras-Sync design (`pithagoras-sync` 0.0.1 and 0.0.2, its `docs/protocol.md` and `docs/permissions.md`) as the basis of new work, and it takes no code, names or wire format from it unless this page says so.

The words MUST, SHOULD and MAY are used as in RFC 2119. Section 11 lists what is decided and what comes later, with its version.

## 1. Scope and non-goals

Nerve lets an agent harness use computers it does not run on. A harness (Claude Code, pi, Hermes, a script, anything with tool calls) reaches a **Nerve center**; the computers run a **Nerve node** each; the center gives the harness tools built from what the nodes say they can do, and routes the harness's calls to the nodes under the rules of the node and the center.

In scope for 0.0.1:

- The Nerve Protocol: the wire format between node and center, the interface between center and harness (the center exposes it as an MCP server, §6), and a conformance suite for both.
- Two deliverables built on it, both in Rust, both in one repo (`Piggidragon/Nerve-Protocol`): the center with its web UI, and the headless node with its CLI.
- Pairing, identity, transport (including an HTTP proxy on the way), several centers per node.
- Where policy lives, what a center may change on a node, and what never leaves the node.

Later, outside the first delivery (§11): the Nerve Desktop add-on (`Piggidragon/Nerve-Desktop`), the node's Slint setup GUI, resume after a dropped link, and a node acting as proxy for other nodes. The MCP server surface of the center is not later: it is part of 0.0.1. Per-token scopes and native harness plugins are backlog, not planned. None of these drive the 0.0.1 design; where 0.0.1 leaves room for them, this page says so in one line.

Non-goals:

- **No portal in the design.** Nothing in the protocol, the center or the node knows about the Pithagoras portal or any other product. Pithagoras connects to the center's MCP server like any other harness; it is not a special case.
- **No per-harness code in the protocol or the center.** No harness names, tool names, session formats or hooks of a particular harness appear in the spec, the center or the node. Harnesses connect to the center's MCP server (§6) as they are. Native harness plugins are backlog, written and kept by each harness's community. We provide the spec, the conformance suite and the MCP server surface in the center.
- No message relaying between nodes (the later node proxy forwards TLS bytes, never messages), no node-to-node calls, no fleet management, no remote install of software on a node by the center.
- No agent loop, model access, memory or chat history in the center. The center is a gate and a router, not a brain.
- No web UI on nodes. A node is configured on the machine (CLI in 0.0.1), or by a center the owner gave write rights.
- No compatibility with Pithagoras-Sync (§9).

## 2. Components

```
        harness A ── MCP ────┐
        harness B ── MCP ────┤  harness interface (local to the center)
                             ▼
                      ┌──────────────┐
   browser ── web UI ─│ Nerve center │  pairing, links, rules, tools, statistics
                      └──────▲───────┘
          node link (wss)    │    node link (wss, through an HTTP proxy)
        ┌────────────────────┴──────────────────────┐
  ┌─────┴─────┐                               ┌─────┴─────┐
  │ node 1    │                               │ node 2    │
  │ fs, exec  │                               │ fs, exec  │
  │ ▲ local   │  nerve-node CLI               │ ▲ local   │
  └─┴─────────┘  (later: Slint GUI, Desktop)  └─┴─────────┘
```

The node is the only component that talks to a center. Anything else on the machine (the CLI now; the setup GUI and the desktop add-on later) talks to the node through its local interface (§7.2).

### 2.1 Nerve Protocol (spec, wire, conformance)

Two network-facing interfaces in 0.0.1, one message layer (§4.5):

| Interface | Between | Carries |
|---|---|---|
| Node link | node → center, over the network | descriptor, invokes, events, state, reliable streams, settings |
| Harness interface | harness → center's MCP server, local | tools from descriptors, session grants (0.0.1: no session grants, §5.5) |

The node's local interface (§7.2) is part of the node, not of the wire spec, in 0.0.1. When the desktop add-on comes, its attach part becomes a third interface in the spec (§11).

The spec is versioned as a whole (§9). Profiles (`nerve:fs/1`, `nerve:exec/1`, ...) are versioned one by one. 0.0.1: the node names its profiles plainly (`fs`, `exec`, ...), with no version (spec/protocol.md §6).

Conformance suite (0.0.1):

| Part | Runs against | Checks |
|---|---|---|
| node | any node | handshake, describe at three levels, schema validation, deadlines, cancel, errors, events and implicit events, reliable streams, limits, strict parsing of center input, per-center isolation |
| center | any center | pairing, challenge auth, one live link per node, descriptor cache by `rev`, center-side rules (a refused call is never sent; 0.0.1: the center has none, §5.5), refusal to send fields only the node may set, session end |
| harness | the center's MCP server surface | one session per connection, `session.end`, tool generation from descriptors |

An `echo` node with toy capabilities (every member kind, no hardware) gives the suite something to run against, and a matching `echo` harness drives the center part. 0.0.1: the harness part is a skeleton that runs no check (spec/conformance.md). Conformance levels: **Core** (describe, invoke, errors), **Reactive** (events, state, subscriptions) in 0.0.1; **Media** (media streams) later with the desktop add-on.

### 2.2 Nerve center

One daemon, `nerve-center`, written once in Rust: the center is the gate for remote code execution and exists in one implementation. It holds:

- its TLS key and certificate (self-signed by default; its SPKI pin goes into pairing links), its id and name;
- the paired nodes: id, name, public key, last descriptor (cached by `id` + `rev`), online state;
- pairing codes;
- the registered harnesses and their tokens;
- sessions;
- statistics per node, counts and timings only (§7.1);
- for each node that gave it write rights, a copy of that node's settings document (§5.2).

It has a web UI it serves itself (§7.1). 0.0.1: it has no subcommands; every setting is a flag or a variable (spec/harness.md §1). It never stores node secrets, command output or file content beyond what a call in flight needs.

### 2.3 Nerve node

One daemon, `nerve-node`, Rust, Linux and Windows first, macOS later. It holds:

- one pairing per center (center URL, pin, center id, the node key for that center);
- the policy per center entry and the machine settings (§5);
- the built-in capabilities: `node`, `fs`, `exec`, `settings`, `audit`;
- the sandbox (Landlock, cgroup scope and exec shim on Linux; on Windows a Job Object per command, which ends its whole process tree but confines no files, so folder mode runs no command there; the dedicated-user install);
- the sudo password, while the sudo switch is on (§5.1);
- the local interface: a control socket used by the CLI (§7.2; 0.0.1: Unix only).

It runs headless: a server, an LXC, a CI box, a laptop. It is fully configurable on its own, without any center having write rights, and it declares no sensing capability of its own.

### 2.4 Harness integration

Harnesses connect over MCP, and only over MCP in 0.0.1 (decided; native plugins are backlog, §11). There is no separate process in between: the center itself exposes the Nerve Protocol as an MCP server (§6.3), and any MCP-capable harness plugs it in as is. That is the whole 0.0.1 integration.

### 2.5 Repo

One repo, `Piggidragon/Nerve-Protocol`, all Rust:

| Path | Contains |
|---|---|
| `spec/` | core, node link, harness interface, profiles, conformance levels |
| `schemas/` | descriptor, settings documents, config files, as JSON Schema |
| `crates/nerve-proto` | types and codecs, no I/O, `no_std` + `alloc` capable |
| `crates/nerve-transport` | WebSocket, unix socket and named pipe, stdio (0.0.1: no named pipe) |
| `crates/nerve-policy`, `crates/nerve-sandbox` | the node's policy engine and sandbox |
| `crates/nerve-node`, `crates/nerve-center` | the two binaries (the center with its web UI built in, and its MCP server surface) |
| `crates/nerve-conformance` | the conformance runner, `nodes/echo`, `harnesses/echo` (0.0.1: no runner binary; `cargo test -p nerve-conformance` runs the parts, spec/conformance.md) |

A wire change, its spec text and both ends land in one PR. Ships: `nerve-center` package, `nerve-node` package, the conformance runner (0.0.1: no runner binary).

`Piggidragon/Nerve-Desktop` is a later, separate repo (§11). It will depend on `nerve-proto` and `nerve-transport` by release tag and talk only to the local node.

## 3. Identity, pairing, transport

### 3.1 Identity

- **Center**: a random id (UUID) and a name, both made on its first start (0.0.1 has no `nerve-center init`; the name comes from `--name` and can be changed in the web UI); its TLS key, whose SPKI sha256 (base64url, no padding) is the pin.
- **Node**: an Ed25519 key pair **per center**, generated at pairing, kept in a 0600 file (0.0.1: always `keys/<name>.key` in the config folder; the keyring is not done, spec/node-local.md §1). The node id a center knows is derived from that public key (base32 of the first 16 bytes of its sha256). Two centers see two unrelated ids for the same machine, so centers cannot correlate a node across trust domains.
- **Node name**: chosen on the node (default from the host name, 1 to 32 of `a-z0-9-`), shown by the center; the center may give it a local display name, which never goes back to the node.
- **Harness**: a token, from `--harness-token` or made in the web UI's settings (0.0.1 has no `nerve-center harness add`); the token is local to the center host (§6.1).

There is no bearer token for nodes. A copied config without the private key cannot connect, and a copied key is detected by the one-link rule (§3.4).

### 3.2 Pairing

1. On the center: "Add node" in the web UI (0.0.1 has no `nerve-center pair new`) creates a one-time code (10 minutes unless the owner set another lifetime up to 24 hours, 10 tries, single use) and shows the link and the code as text (no QR code in 0.0.1):
   `nerve://pair?center=<pct-encoded https URL>&code=<code>&pin=<spki>`
2. On the node: `nerve-node center add '<link>'`. The link is parsed strictly (unknown or doubled keys, bad escapes, paths with `.`/`..` segments, user info, query or fragment in the URL, and links over 4 KiB are refused). The owner sees the parsed center URL, the center name after step 3, and the policy and grant the new center entry starts with (default deny, so every call is refused until an allow rule or a mode allows it, and `settings = off`, §5.1, §5.2), and confirms. Nothing is stored before the confirmation.
3. The node generates the key pair for this center and sends `POST {center}/nerve/v0/pair` with `{code, name, platform, arch, public_key}` over TLS checked against the pin.
4. The center answers `{center_id, center_name, node_id}` and stores the public key. The node shows the center name and stores the pairing.

`pin` is optional: without it the system roots and the usual name checks apply (a center behind a reverse proxy with a public certificate). `http://` is accepted only for loopback, with a same-user listener check on Linux.

Unpairing works from both sides. `nerve-node center rm` tells the center (`bye` reason `unpaired`) and deletes the key; removing the node in the center's web UI (0.0.1 has no `nerve-center node remove`) closes the link with `revoked` and drops the key; a node told `revoked` stops dialling that center.

### 3.3 Who dials

The node always dials the center. A node never listens for centers, which keeps nodes behind NAT, on laptops and in isolated networks reachable without opening anything on them.

#31 let either side dial. The center-dials case is left out: it needs a listening node and a second auth direction for no use case we have. The stdio binding (a center process that spawns a node, used by the conformance suite and the `echo` node) is the one exception, and it has no network side.

### 3.4 Connection and authentication

- `GET {center}/nerve/v0/connect`, WebSocket upgrade over TLS (pin or roots as paired), header `Nerve-Node: <node_id>`. An unknown node id gets 401 and the node stops dialling that center.
- The center sends the first frame: `challenge {nonce: 32 random bytes, center_id}`.
- The node answers `hello` with `auth.sig = Ed25519(node_key, "nerve-connect/0" || center_id || nonce)`, its protocol versions, software, limits and descriptor `rev`. The center checks the signature, then answers `welcome` with the chosen version and its limits. No other message is valid before `welcome`.
- **One live link per node.** A second authenticated link for the same node id makes the center ping the held link (WebSocket ping, 3 s). If it answers, the new link is refused (close `duplicate`) and the center raises an alert: the key exists twice. If it does not answer, the held link is closed and the new one takes over without an alert.
- Heartbeat: WebSocket ping every 20 s from the node; a link on which nothing arrived for 45 s is dead. JSON `ping`/`pong` exist only on stdio and unix-socket bindings, which have no control frames.
- Close is a `bye {reason}` notification followed by the WebSocket close. Reasons: `shutdown`, `paused`, `unpaired`, `revoked`, `duplicate`, `replaced`, `unsupported_version`, `protocol_error`. A node stops dialling on `revoked`, `unpaired`, `unsupported_version`; it retries on everything else.

### 3.5 Reconnect and address changes

- Backoff 1 s doubling to 60 s, up to 10 % jitter subtracted, reset after a link that lasted 60 s.
- The node listens for network changes (netlink route and address events on Linux, `NotifyIpInterfaceChange` on Windows) and for suspend and resume. On a change it sends `going_away {reason: "network"}` if the old link still writes, drops it, resets the backoff and dials at once. The old link no longer answers pings, so the new one replaces it without an alert.
- Before suspend or shutdown the node sends `going_away {reason, back_in_ms?}` so the center can tell "asleep" from "lost" and tell the harness.
- **No resume in 0.0.1.** When a link ends, every call in flight on it ends: the center fails them with `connection_lost` (retryable for the harness), the node kills the commands started on that link and drops uploads. Resume comes later (§11): after a dropped link, the node reconnects and running commands and event streams continue where they stopped (a 30 s grace period in which the node keeps the link's commands and buffers their output, plus replay of events by `seq`). 0.0.1 already numbers events and stream frames (`seq`) so this can be added without a new frame format.

### 3.6 HTTP proxy

Per center entry or for all, `connection.proxy = "http://host:port"`; `HTTPS_PROXY` and `NO_PROXY` apply when nothing is set. The node opens the TLS link to the center inside a CONNECT tunnel; pin and name checks apply to that inner TLS, so the proxy sees only TLS records. Extra header lines on the CONNECT request (`connection.headers`) serve authenticating proxies. No fallback to a direct route when a configured proxy is down (fail closed).

The secrets live in the operating system's keyring (Keychain, Credential Manager, Secret Service), one entry per node under the service `nerve`: the header values, and a user name and password given in the proxy URL, which become a `Proxy-Authorization` header. `node.toml` holds only the URL without credentials and the header names. No secret is in a link, a log, an error text or the audit log. Without a reachable keyring (a headless Linux) `nerve-node proxy set` refuses a header or a password instead of writing it to a file, and a missing entry stops the link rather than dialling directly (spec/node-local.md §2, Proxy).

A node acting as proxy for other nodes (jump node → node) is later (§11). It will be a transport binding below the message layer, with TLS, pin and signature end to end between the far node and the center, so 0.0.1 needs nothing for it beyond keeping the transport layer separate from messages.

### 3.7 Several centers

A node MAY be paired with any number of centers (0.0.1). Each pairing is a **center entry** with its own key, link, backoff, policy and grants. **A center is a trust domain** and the node MUST keep apart, per center: policy and its grant, sessions, audit records (each names its center), the descriptor it is shown, and settings reads and writes. A center cannot learn whether other centers exist.

Shared and device-only are the machine settings (§5.3) and the limits that protect the machine: running commands, output caps and audit log size are one pool, split fairly so one busy center does not starve another. `panic` and `unlock` act on all centers at once.

## 4. Capability model

### 4.1 From #31: kept

#31 (RFC, layer 1 capabilities) is rewritten fresh in Nerve-Protocol; its text is not reused. Its ideas that carry over:

- **The descriptor** as the node's complete self-description, generated from its capability registry, with `rev` changing on every change and a center caching by `node_id` + `rev`.
- **Capabilities** as named instances with four member kinds: actions (center → node, with a reply), events (node → center), state (readable, change-notified), streams (continuous, timed).
- **Profiles** as published, versioned contracts (`nerve:<name>/<major>`); a capability without a profile is usable from its schemas alone; several instances of one profile on a node.
- **Three levels of detail**: `summary` (always in a model's context), `capability`, `full`.
- **Effect classes** per action, used by the node's policy and by the center's own rules.
- **`exposure`** per capability as the node's report of how the capability is reachable for this center.
- **JSON Schema 2020-12** for params, results and state; `x-` vendor members; reverse-DNS names for non-`nerve:` profiles.
- **Conformance levels** and the `echo` node.
- **Input is data**: anything a node returns (file content, command output, a tool result) is untrusted content at the center and in the harness.

### 4.2 Deviations from #31

| # | #31 | Here | Why |
|---|---|---|---|
| D1 | Own `type` messages | JSON-RPC 2.0 framing (no batches), methods and notifications below | One well-known framing with id correlation; MCP speaks it too |
| D2 | Receivers ignore unknown fields | Node parses center input strictly (unknown fields, methods, malformed frames are errors); the center tolerates unknown fields from nodes and harnesses | The device defends itself; a reader of descriptors must accept newer minor versions and `x-` members |
| D3 | Either side dials | Node dials | §3.3 |
| D4 | Bare token in `hello`, pairing not in v1 | Pairing link with pin, per-center Ed25519 node key, challenge signature | No bearer secret to copy; pairing is the only practical way in for a person |
| D5 | 6-byte binary header, blob and lossy stream | 10-byte header; blob and reliable stream in 0.0.1, media frame kind reserved (§4.6) | Command output and large file content are ordered, reliable and of unknown length |
| D6 | Four effects | Five: `execute` added | Running a command subsumes every other effect; policies treat it apart (no standing permission for a shell) |
| D7 | Nothing pushed before `sub` | `node` and `settings` events are implicit; the rest needs `sub` | A center that forgets to subscribe must still learn when the node's descriptor or settings change |
| D8 | No per-call context | `ctx {session}` on `invoke` | The node needs the id to tell sessions apart in its audit records, and the center must never be able to send "allowed" |
| D9 | Scopes per token | No scopes; the node's policy per center entry is the only authority, and the descriptor a center sees is filtered by it | One authority instead of two that can disagree; scopes stay in the backlog (§11) |
| D10 | `ask`: a person decides per call at the node | Rules only: allow or deny, with wildcards, default deny; a call no rule allows is refused at once (§5.4) | Nothing waits for a person; the owner adds the rule that is missing |
| D11 | No center-to-node messages besides requests | `session.end` notification, settings actions (when granted) | The nodes a session used learn that it ended and cancel that session's calls, so its commands stop; an MCP `notifications/cancelled` becomes `cancel` for its call |
| D12 | Session resume, `idem` | Not in 0.0.1, later | §3.5 |
| D13 | HTTP binding, CBOR, center-dials | Left out | No node listens; no constrained node exists yet |
| D14 | Nodes MAY accept several centers, no isolation rules | MUST isolate per center (§3.7) | Several centers are only safe as separate trust domains |
| D15 | Default `busy` for a second driver | Per profile: concurrent for `fs` and `exec`; a profile that needs one driver says `busy` | Two sessions may run commands at once |

### 4.3 Descriptor

```json
{
  "nerve": "0",
  "node": { "id": "k3v7…", "name": "laptop", "platform": "linux", "arch": "x86_64",
            "software": { "name": "nerve-node", "version": "0.0.1" } },
  "rev": "b3f1c2",
  "summary": "Linux laptop, user alice, bash. Files and commands under Folder mode (~/src rw).",
  "capabilities": [
    { "id": "exec", "profile": "nerve:exec/1", "provider": "node", "exposure": "open",
      "summary": "Runs bash commands as alice, in folders flagged x.",
      "actions": { "run": { "effect": "execute", "params": {…}, "result": {…} },
                   "signal": { "effect": "actuate", "params": {…} } },
      "events": { "exit": { "schema": {…} } },
      "state": { "shell": {…}, "confinement": {…}, "max_running": {…} },
      "streams": { "output": { "kind": "reliable", "direction": "source" } } },
    { "id": "fs", "profile": "nerve:fs/1", "provider": "node", "exposure": "open",
      "summary": "Reads and writes files under ~/src.", "actions": {…} }
  ]
}
```

- 0.0.1: `profile` is the plain name (`fs`, `exec`), `exposure` is `on` or `off`, and `rev` is an integer (spec/protocol.md §6).
- `nerve` is the protocol version (§9). `provider` says which process serves the capability; in 0.0.1 always `node`. The field exists so later attached providers (desktop add-on) fit without a format change.
- The descriptor a center receives is filtered by that center's policy: capabilities `hidden` for it are absent, `off` ones are listed with `exposure: "off"`. In default deny (`allowlist` mode) an `fs` or `exec` action is also absent unless an allow rule covers its capability and action (`exec.run` too when the sudo allow list has an entry), so the center builds no tool the node would refuse; `folder` and `user` mode show their actions as before.
- The top-level `summary` is generated by the node from facts the model needs (user, shell, mode, folders) and stays under 60 words.
- `rev` changes on every change of what this center sees; the node sends `node/descriptor_changed` and the center describes again.

### 4.4 Effect classes

| Effect | Meaning | Examples |
|---|---|---|
| `read` | Returns data the node already holds | stat, list, read a file |
| `sense` | Captures the user or the surroundings | screenshot, microphone, clipboard read (none built in for 0.0.1) |
| `write` | Changes data on the node | write a file |
| `actuate` | Acts on the outside world or injects input | send a signal, click, type |
| `execute` | Runs code the center chose | run a command |

The node's policy maps modes and rules onto effects (Folder mode allows `read` inside folders flagged `r`, `write` inside folders flagged `w` and `execute` in folders flagged `x`; `sense` and `actuate` are refused in Folder and User mode unless the owner set the action `on`, and in default deny unless an allow rule names them). The center MAY refuse effects per harness by its own rules (§5.5; not in 0.0.1).

### 4.5 Messages

JSON-RPC 2.0, one object per text frame, integer or string ids, `params` always an object.

| Method or notification | Direction | Purpose |
|---|---|---|
| `challenge` (n), `hello` (n), `welcome` (n) | c→n, n→c, c→n | Handshake, §3.4 |
| `describe {detail, cap?}` | c→n | Descriptor at a level |
| `invoke {cap, action, args, ctx, deadline_ms?, blobs?}` | c→n | Run an action; reply is the result or an error |
| `progress {id, data}` (n) | n→c | Intermediate data for a running invoke, keyed by its request id |
| `cancel {id}` (n) | c→n | Stop a running invoke; exactly one final reply still follows |
| `get {cap, keys}` | c→n | Read state |
| `sub {topics}`, `unsub {topics}` | c→n | Topics `<cap>/<event>`, `<cap>/state`, `<cap>/*` |
| `event {cap, name, seq, ts, data}` (n) | n→c | Something happened |
| `state {cap, seq, ts, changed}` (n) | n→c | State changed |
| `stream.open {cap, stream, params}`, `stream.close {sid, reason}` | c→n, both | Reliable streams (media streams later) |
| `session.end {session}` (n) | c→n | A harness session ended |
| `bye {reason}` (n) | both | Clean close |

Errors carry the JSON-RPC numeric code and, in `data.code`, a string code (`invalid_args`, `forbidden`, `disabled`, `unavailable`, `busy`, `timeout`, `cancelled`, `too_large`, `unknown_capability`, `unknown_member`, `connection_lost`, `internal`), plus capability-specific codes from profiles (`conflict`, `bad_path`, `io`). `message` is for people and models and says what to do next.

`ctx` holds `session` (an opaque id the center chose, at most 256 bytes, namespaced per center on the node). Any other field is refused. There is no field for "allowed", a mode or a folder.

### 4.6 Binary frames

```
u8 kind | u8 flags | u32 id | u32 seq | payload (≤ 64 KiB)
```

| kind | Name | Use |
|---|---|---|
| 1 | blob chunk | A sized binary value referenced as `{"$blob": id}` in args, results or events; flag bit 0 = last chunk |
| 2 | reliable stream | Ordered, flow-controlled, unknown length (command output, file content of a streamed read); ends with flag bit 0 and the stream's final message |
| 3 | media frame | Reserved; not sent or accepted in 0.0.1 (voice and screen streams belong to the desktop add-on, §11) |

Big-endian integers. `seq` counts per id and direction from 0. Backpressure: each side has a bounded send queue (64 frames); reliable streams wait. Limits (message size, blob size, calls at once, streams) are announced by each side for what it receives: the node in `hello`, the center in `welcome`. Defaults: 4 MiB message, 64 MiB blob, 64 calls.

### 4.7 Built-in profiles of the node (0.0.1)

| Capability | Profile | Members |
|---|---|---|
| `node` | `nerve:node/1` | state `status` (`online`, `busy`, `paused`); events `descriptor_changed`, `going_away`, `capability_changed` (implicit) |
| `fs` | `nerve:fs/1` | actions `stat`, `list`, `read`, `grep`, `find` (`read`), `write` (`write`, with `if_match`); one path form on every platform (`/c/Users/…` on Windows) |
| `exec` | `nerve:exec/1` | action `run` (`execute`), `signal` (`actuate`); stream `output` (reliable); event `exit`; state `shell`, `confinement`. The `run` text names the shell (Windows PowerShell 5.1 on Windows). `signal` actuates, so it is offered only where the policy allows it: by an allow rule in allowlist mode, with `caps.exec.signal = on` in folder and user mode. A timeout, `cancel` or `session.end` kills the command's process group; on Windows these and an allowed `signal` end the command's Job Object, which the shell joins before it runs and which holds every process it starts (not one WMI, a service or the task scheduler starts for it); only when Windows makes no job does the node end the processes it saw below the shell (polled), best effort |
| `settings` | `nerve:settings/1` | state `document`; action `set` (`write`, with `if_version`); present only for a center with `settings = write` (§5.2) |
| `audit` | `nerve:audit/1` | event `decision` (needs `sub`) |

0.0.1: the profile column is sent as the plain name (`node`, `fs`, `exec`, `settings`, `audit`).

Profiles for the desktop add-on (computer use, notifications, audio) are defined with it, later.

### 4.8 How a center uses descriptors

- On `welcome` it describes at `summary` (0.0.1: at `full`, spec/protocol.md §4.2), caches by id and `rev`, and subscribes to what its UI needs (`audit/*`).
- It builds tools for harnesses from actions (§6): name, description from `summary`, input schema from `params`, a `node` argument when several nodes offer the same profile.
- It keeps only summaries in a harness's context; full schemas are fetched when a tool is first called or listed in detail.
- It uses `effect` for its own rules (§5.5; 0.0.1: it has none, and `effect` sets `readOnlyHint`) and `exposure` to tell a harness which capabilities are open or off for it.
- It does not interpret a profile it does not know: such capabilities are still offered from their schemas.

## 5. Permissions

### 5.1 Where policy lives

**The node is the authority** for everything that runs on it. Every invoke is decided by the node's policy for the calling center entry, whatever the center says. The center may later hold a second, separate policy for its own side: which harness sessions may reach which nodes, and which effects it refuses before it even sends the call (§5.5; 0.0.1: the center holds no policy of its own). The center can make a call stricter; it can never make the node more permissive, except by changing node settings where the owner gave it write rights (§5.2).

Node policy per center entry:

- `mode`: `allowlist` (the default: default deny, a call runs only when an allow rule lets it through), `folder` (full access inside the granted folders and below; commands only in folders flagged `x`; shell under Landlock) or `user` (full access as the user, protections still on). Folder and User are the full-access modes. Sudo is not a mode; it is a separate switch below. Folder and User have no time limit by default: once set they stay until the owner changes them. A limit is opt-in (`until`, a time; `nerve-node mode set user --for HOURS`): when it runs out, the center falls back to `allowlist`, the default deny mode, not to `folder`.
- `folders`: a path and `access`, three independent flags `r` (read), `w` (write) and `x` (run commands from the folder), in any combination: `access = "rx"`, `""` for none. `r` and `w` decide the `fs` actions (a write needs `w` and no `r`, a read `r` and no `w`); `x` decides where a command may run and which programs the sandbox lets it start. The deepest folder that holds a path decides for it. They count in Folder mode. On Linux each flag has its own Landlock set; a `w` folder is writable but not readable or listable, and Landlock cannot run a file it may not read, so an `x` folder also lets a command read its files by name (it still cannot list the folder; node-local §2, Modes).
- `caps.<cap>[.<action>] = "on" | "off" | "hidden"`: switches per capability and action, derived from the descriptor.
- `allow` and `deny` rules for every action, as globs over the call's target: the command line of `exec.run`, the path of an `fs` action, `<cap>.<action>` for any other (node-local §2). A rule adds only; the four buttons of the center's audit view write them (allow, allow as wildcard, deny, deny as wildcard), and they can be written by hand. Allow rules count in default deny only; in Folder and User mode they change nothing. Deny rules count in every mode, and a matching deny wins over everything.
- protected paths (built in plus `extra`, minus the ones the owner released). The built-in list covers keys, credentials, shell start-up and, on each platform, the system files that open the machine (`/etc/shadow`, `/etc/ssh`; on Windows `%ProgramData%\ssh`, the registry hives, the all-users Startup folder and Windows PowerShell's home with the all-users profiles). On Windows it also holds `%ProgramFiles%\PowerShell` and `%ProgramFiles(x86)%\PowerShell`, PowerShell 7's home as the MSI and winget install it, but not a PowerShell 7 unpacked from the zip, installed as a .NET tool or into a folder of the user's choice. Protected paths apply to the file actions and to the working directory of a command, not to what a command reads; in User mode a command runs as the user without a sandbox (issue #22).
- the sudo switch, one per node, not per center entry (Linux): `off` or `on`. Off, the agent cannot run `sudo`, even if the sudo allow list names the command, because the node has no sudo password. On, the agent may run `sudo <command>` only for commands the sudo allow list (`sudo_allow`, separate from the normal allow list) names, in every mode; deny rules still apply to it. The password is entered when the switch is turned on and kept in the node's memory only (`secret_storage` at rest is not done in 0.0.1); the agent never sees it and it is scrubbed from every outgoing frame. Turning the switch on sends the password once from the client that sets it (CLI on the node, or a center with `write`, §5.2) to the node, sealed to a fresh X25519 key that the node signs with its pairing key, with nonce and timestamp against replay (spec/protocol.md §7.4.1, §11); a center relays only the ciphertext and keeps no copy. The node checks the password against the real system password with a non-destructive `sudo` check it runs itself (for example `sudo -S -v`, output discarded), and refuses to switch on if it is wrong (`invalid_args`, the message says the password is wrong): a wrong password would give the agent nothing, so the switch never shows `on` without a working password. Switching off needs no password and drops the stored one.
- the `settings` grant (§5.2).

The node and the center allow only through rules, and the default is deny. A decision is allowed or forbidden, nothing else: a call that no rule allows is refused at once (§5.4).

The descriptor's `exposure` for this center is computed from these (exposure reports, policy decides). Per-call refusals are `forbidden`; nothing waits for a person.

This policy per center entry is the whole permission model of 0.0.1. Rights bound to a token instead of a center entry (scopes) are not planned; they stay as optional backlog work (§11).

### 5.2 What the center may change

Only what the node owner granted, per center entry, on the node:

| `settings` grant | The center may | Default |
|---|---|---|
| `off` | nothing; `nerve:settings/1` is hidden, the center's UI shows no settings for this node | yes |
| `write` | read and change every setting of its own center entry, widening included (User mode, folders, capabilities on), and `pause` the node, and turn the node's sudo switch on or off (the one machine-level setting a center may touch; turning it on needs the node's sudo password, which the center passes on once and does not keep and which the node verifies, so only someone who knows it can enable sudo; turning it off needs no password) | |

A node is fully configurable without any center having `write`: every setting is reachable through the node's local interface (§7.2).

`settings.set` takes the whole document and `if_version`; a stale version is `conflict`. Each changed setting is audited on the node with old and new value and "by center <name>". A change to a client-only item (§5.3) is refused as a whole. Remote writes never touch another center's entry or the machine settings, except the sudo switch above. Because `write` can widen the rules up to User mode, a compromised center with `write` is as strong as User mode on that node; `nerve-node center grant` should say so (0.0.1: it does not yet).

### 5.3 Client-only items

Decided and executed on the node only. They are not in any document a center reads (or listed as `device_only` where the center benefits from knowing the value) and no protocol message changes them, `write` grant or not:

1. Pairing and unpairing, the node keys, the center list.
2. The `settings` grant itself, per center entry.
3. `panic` and `unlock` (a center with `write` may pause; only the node unlocks).
4. The machine settings: `machine.shell`, `machine.allow_root`, `machine.sudo_path`, `machine.secret_storage`, the sandbox backend and confinement fallbacks.
5. The sudo password: it is never in a document a center reads and never returned by any message. It is kept in the node's memory only (`secret_storage` at rest is not done in 0.0.1) and scrubbed from every outgoing frame. The only way a center takes part is turning the sudo switch on with the password, which the node verifies and the center does not keep (§5.1, §5.2; open point in §11), or turning it off.
6. Key and secret storage (keyring or file).
7. Proxy settings and proxy credentials.
8. Updates: channel, key, when to update (the node never updates on a center's request).
9. Exposure of `sense` capabilities: a center can switch them off, never on. None is built in for 0.0.1; the rule is fixed now so that later providers inherit it.
10. The local audit log and its retention.
11. Releasing a protected path: a center may add to `protected.extra` but not remove from it or change `protected.allow`, and it may neither add a folder at or inside a protected entry the old folders did not release already nor widen the access of a folder there. Such a folder is judged by the access the owner's folders give that place (the deepest of them), and the spellings of one place are compared by path, not as text, so neither another spelling nor a folder inside the owner's one gives it a flag the owner did not.

### 5.4 Decisions and refusals

Every invoke from center C, session S is decided by the node's policy for C, and the answer is **allowed** or **forbidden**. There is no third outcome: nothing is held for a person to answer.

1. The policy looks for what allows the call: in default deny an allow rule, in Folder and User mode the mode itself (folders, the user's reach), for a sudo command the sudo allow list. Finding none, the node refuses at once with `forbidden`. A rule that denies (a `deny` rule, a protected path) wins over any rule that allows.
2. The `message` of the refusal says what is missing and what to do next. The harness shows it to the model; the owner adds the rule and the model tries again.
3. Every decision, allowed and refused, is audited on the node with center and session, and reaches a subscribed center as an `audit/decision` event.
4. Rules are added on the node (`nerve-node rule add allow|deny|sudo`, `folder`, `cap set`, `config add`) or, for a center with `settings = write`, through the center (the four audit tab buttons, §11 item 9a).

Later, the center decides the same way for its own rules (§5.5): it refuses a call before sending it, and never allows what the node would not. In 0.0.1 it has no such rules.

### 5.5 Center-side policy

- **Not in 0.0.1: session grants and center rules.** Every harness session sees every paired node that is not disabled, and the center sends every call on to the node, whose policy decides (spec/harness.md §6). Per-session grants and per-effect rules at the center come later (§11).
- **Full access is never a default**: the node starts every center entry in default deny (mode `allowlist`, no rule). Nothing a center or harness does changes that unless the owner allows it directly, or through a `write` grant the owner gave.

## 6. Harness integration

### 6.1 Harness interface

The integration form is MCP, and only MCP in 0.0.1 (decided). The center's MCP server surface (§6.3) is this interface as seen by an MCP client; Beneath the MCP surface the center keeps the harness role of the message layer, reached over a local binding: a unix socket (Linux, macOS) or named pipe (Windows) owned by the center's user, or a loopback WebSocket for harnesses in other environments. The same JSON-RPC message layer, role `harness`. Auth: a harness token (`--harness-token`, or made in the web UI), sent in `hello` together with the features the client implements (`tools`). A harness on another host than the center reaches it over HTTP MCP with TLS and a token. 0.0.1: only the MCP surface exists (spec/harness.md); the message-layer methods below are the design behind it.

Methods the center offers to a harness:

| Method | Purpose |
|---|---|
| `nodes.list` | Nodes granted to this harness, online state, `summary` descriptors |
| `tools.list {session}` | Tools generated from descriptors for the nodes granted to the session (§6.2) |
| `describe {node, cap}` | Full detail for one capability |
| `invoke {node, cap, action, args, session}` | Run an action; the center adds `ctx`, applies its own policy, forwards to the node |
| `session.grant {session, nodes}` (later), `session.end {session}` | Grants per harness session (later, §5.5); `end` reaches every node used |
| event `nodes.changed` | So the client can refresh tools |

The reverse direction (a harness offering sessions, prompts and replies for a chat window or voice) is not in 0.0.1. It comes with the desktop add-on (§11).

### 6.2 Tools from descriptors

- One tool per action: name `<cap>_<action>`, description from the capability and action summaries, input schema from `params`.
- Capabilities with the same profile on several nodes become one tool with a required `node` argument (an enum of granted nodes that have it). Capabilities without a profile, or with differing schemas, get the node name as prefix: `<node>_<cap>_<action>`. `_` is the only separator, so node, capability and action names use letters, digits and `-` and never `_` (a descriptor with a `_` in a capability or action name is refused). Tool names stay within `^[a-zA-Z0-9_-]{1,64}$`.
- Results: JSON as text, blobs as content where the harness supports it, otherwise saved by the center and referenced by a short-lived handle the harness can read.
- Every tool result is marked as content from a device, not instructions.
- Tool lists change with descriptors; the center notifies (`nodes.changed`).
- A node the owner disabled in the center is left out of the tool list, and the center refuses a call to it before anything reaches the node (`unavailable`, "the node X is disabled in the center"). The `nodes` tool still lists it, marked as disabled. The link and the node are untouched.

### 6.3 MCP server surface (0.0.1)

The center exposes the protocol as an MCP server. Any MCP-capable harness connects to it (it starts the center over stdio, or reaches it over HTTP with a harness token) and needs no code of its own. It is part of `nerve-center`, not a separate process, and maps §6.2 onto MCP `tools/list`, `tools/call` and `tools/list_changed`. The transport is a stdio launch of the center or an HTTP endpoint (`--mcp stdio|http`, spec/harness.md §3). It is the lowest common denominator, with known limits:

- one session per MCP connection (the surface cannot see the harness's chats);
- a call that no rule allows is refused at once with `forbidden` and a message the model can pass on;
- the center refuses nothing of its own in 0.0.1; every refusal comes from the node's policy.

### 6.4 What an MCP client must do

Nothing Nerve-specific beyond MCP itself:

1. Connect to the center's MCP server with a harness token.
2. Offer the tools to the model and refresh them on `tools/list_changed`.
3. Treat tool results as content from a device, not as instructions, and pass a `forbidden` message on to the model.

A harness carries no Nerve security logic: the node decides, the center routes. The MCP server surface is the baseline and passes the harness conformance part with the limits of §6.3.

## 7. Center web UI and node local interface

### 7.1 Center web UI

Served by `nerve-center` itself (assets built into the binary, no extra runtime or package), on `127.0.0.1:<port>` by default. Exposing it beyond loopback needs a harness token, which logs in, and then serves it over TLS (spec/harness.md §7); remote use is also possible through an SSH tunnel or a reverse proxy. Three areas:

- **Node overview**: every paired node with online state, last seen, `going_away` reason, platform, the descriptor summary and per-capability exposure as this center sees it, sessions using the node, and "Add node" (pairing code and link), rename, disable or enable (a disabled node stays paired and connected but is hidden from the agent: no tools, no calls), remove.
- **Statistics**: per node and in total, counts and timings only, never content: online time, link drops and reconnects, calls per capability and action, errors by code, calls allowed and refused, call latency. Kept in the center's state file, with a retention the center's config sets.
- **Settings**: only for nodes whose center entry gives this center `settings = write`. It renders the node's settings document (`nerve:settings/1`), validates against the published schema, sends whole documents with `if_version` and shows the node's refusal reasons. Nodes without `write` show no settings page. The center's own settings (name, harness tokens, statistics retention, pairing code lifetime) are a separate page.

0.0.1: the center has no CLI for this; everything is in the web UI.

### 7.2 Node local interface

The node's control socket (unix socket in the user's state folder, mode 0600, peer credentials checked; named pipe with an owner-only ACL on Windows; 0.0.1: no named pipe, see below). It is the node's only way in besides its center links. It offers the settings API (§8.3), status, pairing, `panic`/`unlock` (0.0.1: its methods are in spec/node-local.md §5).

In 0.0.1 its only client is `nerve-node` itself (the CLI). Nodes get no web UI. Later clients, on the same socket, with no change to the node link:

- the Slint setup GUI (pairing confirmation, settings, status, audit tab with the four rule buttons for its own node);
- the Nerve Desktop add-on, which attaches as a capability provider: its capabilities are merged into the node's descriptor with `provider: "nerve-desktop"`, the node applies its own policy per center to every invoke before forwarding it, and nothing of the desktop add-on talks to a center directly.

Commands the node runs for a center cannot change the node's settings through this socket (process-ancestry check on Linux). 0.0.1: Windows has no socket and no sandbox; the CLI signs node.toml itself, so a command the node runs for a center can change the policy, and the change applies at the next start (spec/node-local.md §5).

## 8. Installation and configuration

### 8.1 Center

- Package: one binary, Linux (x86_64, aarch64) and Windows; macOS later.
- 0.0.1: a harness starts it as an MCP server; there are no subcommands, every setting is a flag or a variable (spec/harness.md §1). The first start makes the TLS key, the self-signed certificate and the center id. Behind a reverse proxy, `--public-url` is the proxy's address. Everything else is in the web UI (§7.1).

### 8.2 Node

- Package: one binary, Linux and Windows. Headless; everything through the CLI in 0.0.1.
- `nerve-node install` (user service), `nerve-node setup --create-user` (servers: dedicated user, system unit with `Delegate=yes`, folder grants printed as `setfacl` lines); not done in 0.0.1, see below.
- Terminal, noun then verb like docker: `center add|rm|ls|pause|resume|grant settings`, `folder add|set|rm|ls`, `mode set allowlist|folder|user [--for HOURS]`, `rule add|rm allow|deny|sudo <command> [--wildcard]`, `rule ls [allow|deny|sudo]` (no list shows all three), `cap set|ls`, `sudo on|off|status` (`on` asks for the sudo password; the node verifies it and refuses a wrong one; `off` asks for none), `proxy set|rm|ls`, `config get|set|unset|add|remove|accept`, and on their own `run`, `status`, `audit [--denied] [--follow]`, `panic`, `unlock`, `install`, `setup`, `update`, `uninstall`. Folder rights are written like chmod: `folder add <path> +r +w +x` (at least one right is required), `folder set <path> =rw -w +x` (changes apply left to right). Every per-center command takes `--center <name>` and refuses to guess when there are several.
- In 0.0.1 the commands `install`, `setup`, `update` and `uninstall` exist but only answer "not done in 0.0.1"; the node is started by hand until they land.
- Pairing is confirmed in the terminal; a `nerve://` link handler and dialogs come with the Slint setup GUI later.

### 8.3 One source of truth

- Every CLI command that changes a setting (the list is in §8.2) is one of these writers; none edits the file on its own.
- Each daemon owns exactly one config file (`~/.config/nerve/node.toml`, `~/.config/nerve/center.toml`; `%APPDATA%\nerve\…` on Windows), described by a published JSON Schema. 0.0.1: the center keeps no config file, only `state.json` in its state folder (spec/harness.md §8).
- Every writer goes through the daemon's settings API on its control socket: the CLI, (later) the setup GUI and the desktop add-on, and (through `nerve:settings/1`) a center with `write`. The API takes a whole document with `if_version`, validates it against the schema and the rules (client-only items), writes the file atomically, applies it at once, audits each change with old and new value and notifies listeners. No component writes the file directly; while no daemon runs, the CLI writes it through the same store.
- The daemon keeps the config in memory and reads the file only at start-up and when the owner asks (`SIGHUP`, `reload` on the socket). Every file the node writes carries an HMAC over its content in its first line, keyed by a secret in the node's state folder (`config.key`, 0600). A file without a matching MAC, a hand edit included, was not written through the owner's path: it is refused and audited, and the old settings stay (at start-up the node does not start). The owner takes such a file after looking at it with `nerve-node config accept` (node-local §1). The check holds while `config.key` does: a process that can delete or read it (a `user` mode command can) can have another file taken at the next start (node-local §1).
- On Linux, the node's config and state folders are its own (0.0.1: on Windows see §7.2): no call of a center reaches them, whatever its rules, folders or released paths say, and a confined command's Landlock rules leave them out even when a granted folder holds them (node-local §3).
- The settings document a center reads and the config file are the same structure, minus the client-only sections. There is no second format.

Node config layout: spec/node-local.md §2, the full file with every key.

Simpler than 0.0.x: no `profile` setting, no `token_storage` (no token), no pi tool switches (capability switches instead), no `portal_policy` (per-center grants), one file per daemon, one settings API.

## 9. Versioning and release

- Every package starts at **0.0.1**: `nerve-center` and `nerve-node`, one version for both (one workspace). `nerve-desktop` starts at its own 0.0.1 when it exists, and states the protocol versions it speaks.
- Protocol version `"0"` for all of 0.0.x and 0.x: exact match, no promise between pre-releases; `hello` lists the versions a side speaks, the center picks, a mismatch closes with `unsupported_version`. Protocol `"1"` comes with 1.0.0; from then minor additions only add, and receivers of node-side data ignore what they do not know (D2).
- Profiles are versioned on their own (`nerve:fs/1`); a breaking change is a new major profile, offered side by side.
- **No compatibility with Pithagoras-Sync.** No reading of its config, token, keyring entries or folders; no `pithagoras-sync://` links; no `/sync/v1/*` endpoints; no `proto: 1`. A machine moving over uninstalls the old client (`pithagoras-sync uninstall --purge`) and pairs fresh. No transition code is written.
- Releases: signed manifest (minisign), immutable tags, prereleases without a manifest, per-target binaries with sha256; one release key for the repo. Nodes update only on the owner's command (`nerve-node update`), never on a center's request.
- Each release runs the conformance suite against the released center and node.

## 10. Removed and renamed from the old design

| Old (Pithagoras-Sync 0.0.x, portal) | New | Why |
|---|---|---|
| Portal `server/src/sync/hub.ts`, `protocol.ts`, `store.ts`, `pair.ts`, `grants.ts`, `tools.ts` as the center | `nerve-center` daemon | The center exists once, harness-neutral; no portal in the design |
| Portal REST routes `/devices`, `/devices/pair`, `/devices/:id/policy`, `/sessions/:id/devices` | Center terminal and web UI; harness interface | Product API of one harness, not protocol |
| `/sync/v1/pair`, `/sync/v1/connect` | `/nerve/v0/pair`, `/nerve/v0/connect` | New name, versioned with the protocol |
| `pithagoras-sync://pair?portal=…&code=…&spki=…` | `nerve://pair?center=…&code=…&pin=…` | Naming |
| Binary `pithagoras-sync` (rebrand branch `nerve-protocol`) | `nerve-node`, `nerve-center` | Two deliverables in 0.0.1 |
| Folders, keyring attributes, unit and task names, env vars `PITHAGORAS_SYNC_*`, `User-Agent: pithagoras-sync` | `nerve` folders, `nerve-node`/`nerve-center` units, `NERVE_*` | Naming; no migration (§9) |
| `connector_token` (bearer, sha256 on the portal) | Per-center Ed25519 node key, challenge signature | No copyable secret |
| `Sync-Instance` header and copied-token detection (PR #30) | One-link rule with the node key (§3.4) | The key proves identity; a second live holder is a copy |
| `overlay_token` from pairing | Removed | The later desktop add-on attaches to the node locally; no second credential |
| `hello` notification without answer, `proto: 1`, `capabilities: [names]` | `challenge`/`hello`/`welcome`, protocol version `"0"`, descriptor | Version pick, auth, limits, self-description |
| `device.info` | Descriptor + state of `exec`, `settings` | Self-describing |
| `device.probe` (`pithagoras-probe-*` temp file, same-machine check) | Removed | Portal-specific; a center does not need to know whether it shares a host |
| `fs.*`, `exec.start`, `exec.signal`, `exec.exit` methods | `invoke` on `nerve:fs/1`, `nerve:exec/1` | Generic capability model |
| The portal's per-chat `ctx` and pi tool labels | `ctx {session}` | "Chat" and pi tool names are harness vocabulary |
| `policy.tools.read|write|edit|bash|grep|find|ls` | `caps.<cap>.<action>` switches | Derived from the descriptor, not from one harness's tools |
| `portal_policy = off|read|write` | Per-center `settings = off|write` | Per trust domain |
| Modes Ask, Folders, Full and the methods around them | Modes Allowlist (default deny), Folder and User; sudo is a separate per-node switch (§5.1) with its own allow list, not a mode; a call is allowed by a rule or a mode, or `forbidden` | Nothing waits for a person; rules decide, default deny |
| `policy.get`, `policy.set`, `policy.changed` | `nerve:settings/1` | Generic; same document as the config file |
| `audit` notification | `nerve:audit/1` event, subscribed | A center that wants it asks |
| `grant.end` | `session.end` | Harness-neutral name |
| JSON-RPC error codes -32001…-32009 with `data.reason` | JSON-RPC code + string code in `data.code` | One code table for all capabilities |
| 9-byte frame, kinds ExecOutput, FileData, FileUpload | 10-byte frame, kinds blob, reliable stream (media reserved) | Generic, with a last-chunk flag |
| Close codes 1000 paused, 4001 revoked, 4002 replaced, 4003 version | `bye {reason}` + matching close | Readable reasons, one table |
| `mcp.list`, `mcp.call`, `mcp.changed`, `crates/mcp` and signed pins in the syncer (PR #27) | Removed from the node; computer use is a later desktop add-on feature | Computer use belongs where the desktop is |
| Native screenshot tool in the syncer (#13) | Dropped; screenshots come later from the desktop add-on's computer-use install | One way to see the screen |
| `mcp_tools` field, `mcp` in `hello` | Descriptor | Self-describing |
| Pithagoras-specific Devices tab, chat cards | Center web UI | Any harness |
| 0.0.x transition code (old paths, old scheme, migrations) | None | Fresh start, no compatibility |
| `profile = headless|desktop`, `token_storage` | Gone; no token | Fewer settings |
| GUI installer and `zenity`/`kdialog` dialogs as the client's GUI | CLI in 0.0.1; Slint setup GUI later | Headless first |

Kept in substance (re-implemented, not copied): the policy engine's folders, protected paths and command rules; Landlock, cgroup scope, exec shim, Job Object, dedicated user; strict parsing of center input; the sudo password on the node with scrubbing (now behind a per-node switch); backoff and liveness numbers; limits; strict pairing-link parsing; signed updates.

## 11. Decided and later

### Decided

1. **One repo**, `Piggidragon/Nerve-Protocol`: spec, conformance suite, center, node. All Rust (§2.5).
2. **Center**: one Rust daemon with a web UI it serves itself: node overview, statistics, and settings only for nodes that gave it `write` (§7.1).
3. **Node**: Rust, headless, configured through its CLI and fully configurable without center write rights (`settings = off` by default). No web UI on nodes (§7.2, §8.2).
4. **The node is the only component that talks to a center.** Local add-ons (setup GUI, desktop) attach to the node through its local interface (§7.2).
5. **Several centers per node** in 0.0.1, each a separate trust domain (§3.7).
6. **Permissions**: the node's policy per center entry is the only authority; no scopes (§5.1, D9).
7. **Decisions**: allowed or forbidden only. The node and the center allow only through rules, default deny; a call no rule allows is refused at once. Modes: Allowlist (default, default deny), Folder and User; Folder and User give full access in their area, deny rules narrow it; sudo is a per-node switch with its own allow list, not a mode (§5.1, §5.4).
8. **No resume** in 0.0.1: a dropped link ends its calls (§3.5).
9. **No media streams** in 0.0.1; voice belongs to the desktop add-on (§4.6).
9a. **Audit in 0.0.1**: the center web UI has an audit tab for all its nodes. Every entry with a known target (a command, a path, another action) gets four buttons: Allow, Allow as wildcard, Deny and Deny as wildcard. Each only adds a rule, to the allow list (the sudo allow list for a sudo command) or the deny list. The buttons write to the node only where the center has write right (§5.2); without it they do nothing and the entry says so. The center cuts each target to 512 characters as the node's log does (spec/node-local.md §6), keeps at most 500 decisions and 1 MiB of them in memory, oldest dropped first, and offers no button for a cut target. The node has no UI in 0.0.1; its own audit is `nerve-node audit` in the CLI.
10. **Capability model**: #31 rewritten fresh in Nerve-Protocol, keeping the self-describing descriptor, actions/events/state/streams, profiles, effect classes and conformance levels (§4.1, §4.2).
11. **Harness integration is MCP only.** The center exposes the protocol as an MCP server (§6.3), part of 0.0.1, and any MCP-capable harness plugs it in as is. Native harness plugins are a backlog item for the communities (see Later). We provide the spec, the conformance suite and the MCP server surface. No portal in the design (§1, §6).
12. **Fresh start** at 0.0.1, no compatibility with Pithagoras-Sync (§9).

### Later

| Feature | Version | Notes |
|---|---|---|
| Resume after a dropped link | later | Reconnect and continue running commands and event streams where they stopped: 30 s grace period on the node plus event replay by `seq` (§3.5) |
| Node as proxy (jump node → node) | later | Transport binding below the message layer, end-to-end TLS and signature, CONNECT only to centers the jump node is paired with (§3.6) |
| Node setup GUI in Slint | later | Client of the node's local interface: pairing confirmation and `nerve://` handler, settings, status, audit tab with the four rule buttons for its own node (§7.2) |
| Permission modes Folder and User (layer 1) | first, version open | Default deny after setup (mode Allowlist, with allow rules). Folder: full access below one path, explicit denies. User: full access as the user; as root a warning and one confirmation. Sudo is not a mode: a per-node sudo switch (password entered when turned on) plus the sudo allow list |
| Action checker on the server (layer 2) | later version | Small local decision model plus a command filter: `rm` default deny, `rm -rf /*` hard deny. Saved allow rules apply automatically |
| Harness plugins (native integration instead of MCP) | backlog | Written and owned by the harness communities, not by us. 0.0.1 knows only the MCP form (§6) |
| Capability provider attach on the local interface | later, with Nerve Desktop | Provider capabilities merged into the node's descriptor under the node's policy (§7.2); conformance part "provider" |
| Media streams and conformance level Media | later, with Nerve Desktop | Frame kind 3 (§4.6) |
| Harness session interface (sessions, prompts, replies, harness config) | later, with Nerve Desktop | Needed by the desktop chat window and voice (§6.1) |
| Nerve Desktop add-on (`Piggidragon/Nerve-Desktop`) | later | Extension of the node: chat window and config, STT/TTS and voice-to-voice, optional computer-use MCP install. Talks only to the local node |
| Session grants and center rules per effect | later | Which harness session may use which nodes, and effects the center refuses before it sends a call (§5.5) |
| Scopes per token | backlog, not planned | Optional future work: rights bound to a token instead of the center entry. The node policy per center entry is the current model |

### Open points

- **MCP server surface details**: transport (stdio launch or loopback HTTP), how sessions map to MCP connections, and what the first two MCP clients tested need. Settled in its issue (0.0.1: spec/harness.md §3 and §5).
- **Sudo password in transit when a center enables sudo.** Decided: end-to-end encrypted to the node. The password is sealed to a fresh X25519 key that the node signs with its pairing key (spec/protocol.md §7.4.1) and carries a nonce and timestamp against replay; the center only relays the ciphertext and never reads it. The node decrypts and verifies it with a non-destructive `sudo -S -v` and refuses a wrong one. A center with `write` may switch sudo on and off; the agent never sees the password (§5.1, §5.2). Known limit: the center's web UI serves the password form, so a tampered center UI could capture the password before it is encrypted. This is accepted for 0.0.1 and does not weaken the node-side guarantees.
