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
  allows is refused at once. The settings grant, panic and unlock, and a
  local audit log (`spec/node-local.md`).
- The sudo switch per node, off by default: off, no command runs with sudo
  even when a rule permits it; on, a sudo command runs only when a permit rule
  names it. `nerve-node sudo on|off|status`, or a center with the settings
  grant `write`, which relays the password sealed end to end (X25519, HKDF,
  AES-GCM) without being able to read it. The node checks the password with
  `sudo -v`, keeps it in memory only and scrubs it from every frame and the
  audit log. Every other command runs with `no_new_privs`. Linux only.
- `nerve-center`: the center, run by a harness as an MCP server. It pairs nodes,
  keeps their links and offers their capabilities as MCP tools. Its web UI
  has a login page (the harness token logs in; `--ui-no-login` on loopback
  turns it off) and shows nodes, the audit log,
  statistics, a help page with the node's commands and the settings of nodes
  that granted write access (`spec/harness.md`).
- Conformance suite with a center part and a node part (pairing, link,
  descriptor, fs, exec permit rules, audit and the sudo switch); the harness
  part is a skeleton (`spec/conformance.md`).
