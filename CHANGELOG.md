# Changelog

## 0.0.1

First release of the rewrite. Nothing is compatible with Pithagoras-Sync.

- Protocol `"0"`: pairing with one-time codes and a pinned center
  certificate, a signed node link over WebSocket, JSON-RPC 2.0 messages,
  binary frames for blobs, the capability descriptor and the built-in
  profiles `node`, `fs`, `exec`, `settings` and `audit`
  (`spec/protocol.md`).
- `nerve-node`: the node daemon and its headless CLI. Policy per center:
  default deny, the modes folder and user, capability switches, protected and
  denied paths and allow and deny rules with wildcards. A call that no rule
  allows is refused at once; there are no approvals. The settings grant, panic and unlock, and a
  local audit log (`spec/node-local.md`).
- `nerve-center`: the center, run by a harness as an MCP server. It pairs nodes,
  keeps their links and offers their capabilities as MCP tools. Its web UI
  has a login page (with `--ui-password`) and shows nodes, the audit log,
  statistics and the settings of nodes that granted write access
  (`spec/harness.md`).
- Conformance suite with a center part and a node part; the harness part is a
  skeleton (`spec/conformance.md`).
