# Changelog

## 0.0.1

First release of the rewrite. Nothing is compatible with Pithagoras-Sync.

- Protocol `"0"`: pairing with one-time codes and a pinned center
  certificate, a signed node link over WebSocket, JSON-RPC 2.0 messages,
  binary frames for blobs, the capability descriptor and the built-in
  profiles `node`, `fs`, `exec`, `approvals`, `settings` and `audit`
  (`spec/protocol.md`).
- `nerve-node`: the node daemon and its headless CLI. Policy per center with
  the modes ask, folders and full, capability switches, protected and denied
  paths, command rules, approvals (answered at the center, locally, or both),
  the settings grant, panic and unlock, and a local audit log
  (`spec/node-local.md`).
- `nerve-mcp`: the center, run by a harness as an MCP server. It pairs nodes,
  keeps their links and offers their capabilities as MCP tools. Its web UI
  has a login page (with `--ui-password`) and shows nodes, pending approvals,
  statistics and the settings of nodes that granted write access
  (`spec/harness.md`).
- Conformance suite with a center part and a node part; the plugin part is a
  skeleton (`spec/conformance.md`).
