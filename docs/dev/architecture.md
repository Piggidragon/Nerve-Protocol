# Architecture

Nerve lets an agent harness use computers it does not run on. The harness
reaches a **center**. Each computer runs a **node**. The center turns what the
nodes can do into tools for the harness and routes the harness's calls to the
nodes. Each node decides every call by the rules its owner set.

```
   harness A ── MCP ──┐
   harness B ── MCP ──┤
                      ▼
               ┌──────────────┐
 browser ──────│ nerve-center │  pairing, links, tools, statistics, web UI
               └──────▲───────┘
                      │ node link (WebSocket over TLS), dialled by the nodes
        ┌─────────────┴─────────────┐
   ┌────┴─────┐               ┌─────┴────┐
   │ node 1   │               │ node 2   │   fs, exec, settings, audit
   └──────────┘               └──────────┘
```

## Parts

| Part | Is | Holds |
|---|---|---|
| Center | `nerve-center`, one daemon | Its TLS key and certificate, its id and name, the paired nodes (id, name, public key, last descriptor), pairing codes, hashed harness tokens, sessions, statistics |
| Node | `nerve-node`, one daemon and a CLI | One pairing per center, the policy per center, the machine settings, the built-in capabilities, the sandbox, the sudo password while sudo is on |
| Harness | Any MCP client | Nothing of Nerve. It only speaks MCP |

The node is the only part that talks to a center. The CLI talks to the node
through its control socket.

## Design rules

1. **The node is the authority.** The node's policy for the calling center
   decides every call, whatever the center says. The center can make a call
   stricter. It cannot make the node more permissive, except by changing
   settings where the owner gave it the settings grant.
2. **The node dials.** A node never listens for centers. Nodes behind NAT, on
   laptops and in closed networks work without opening a port.
3. **A center is a trust domain.** A node pairs with any number of centers and
   keeps their policy, sessions, audit entries and settings apart. A center
   cannot learn whether another center exists.
4. **Default deny.** A new pairing allows nothing. A decision is allowed or
   forbidden. Nothing waits for a person to answer.
5. **MCP is the only harness interface.** No harness names, tool names,
   session formats or hooks appear in the protocol, the center or the node.
6. **The center is a gate and a router.** It has no agent loop, no model, no
   memory and no chat history. It stores no file contents, command output or
   node secrets. It does not relay messages between nodes, call one node from
   another or install software on a node.
7. **Data from a node is data.** File contents, command output and tool
   results are untrusted content at the center and in the harness. The center
   marks every tool result as device content.
8. **No web UI on nodes.** A node is configured on the machine, or by a center
   whose owner gave it the settings grant.

## What the node keeps

| Where | What |
|---|---|
| Config folder | `node.toml`, signed. `keys/<name>.key`, one Ed25519 key per center, mode 0600 |
| State folder | `audit.jsonl`, `log.jsonl`, `run/ctl.sock`, `config.key` (the key of the config's MAC) |

No call of any center reaches these two folders. See
[settings and config](settings-and-config.md). The center keeps `tls.pem`,
`state.json` and `log.jsonl` in its state folder ([logging](logging.md)).

## Repo layout

| Path | Contains |
|---|---|
| `docs/dev/spec/` | The protocol, the node's local rules, the harness side, the conformance suite |
| `schemas/` | JSON Schemas of the descriptor and the pair request |
| `crates/nerve-proto` | Wire types and codecs, no I/O |
| `crates/nerve-transport` | TLS with pinning, `CONNECT` proxies, WebSocket, the node's Ed25519 identity, the sealed sudo password, a small HTTP/1.1 server, local control sockets |
| `crates/nerve-policy` | The node's config, the decision engine, rules, protected paths, settings, the audit log |
| `crates/nerve-sandbox` | Confinement for commands: Landlock on Linux, an AppContainer on Windows |
| `crates/nerve-node` | The `nerve-node` binary: daemon and CLI |
| `crates/nerve-center` | The `nerve-center` binary: links, MCP server, web UI |
| `crates/nerve-conformance` | The conformance suite, an echo node and a fake center |

A wire change, its spec text and both ends change together.

## Read next

- [Identity and pairing](identity-and-pairing.md)
- [The node link](node-link.md)
- [Capabilities](capabilities.md)
- [The MCP surface](mcp-surface.md)
- [The policy engine](policy-engine.md)
- [Settings and config](settings-and-config.md)
