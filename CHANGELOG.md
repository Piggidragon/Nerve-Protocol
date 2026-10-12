# Changelog

## 0.0.1

First release of the rewrite. Nothing is compatible with Pithagoras-Sync.

- Protocol `"0"`: pairing with one-time codes and a pinned center
  certificate, a signed node link over WebSocket, JSON-RPC 2.0 messages,
  binary frames for blobs, the capability descriptor and the built-in
  profiles `node`, `fs`, `exec`, `settings` and `audit`
  (`spec/protocol.md`).
- `nerve-node`: the node daemon and its headless CLI. Policy per center:
  default deny, the modes allowlist (the default), folder and user, capability
  switches, protected paths, and allow and deny rules with wildcards for every
  action. Folder and user give full access in their area, deny rules narrow it,
  allow rules count in allowlist mode only. A call that no rule allows is
  refused at once. The settings grant, panic and unlock, and a local audit log
  (`spec/node-local.md`).
- Folder and user mode have no time limit unless the owner sets one
  (`mode set user --for N`); when a limit runs out the center falls back to
  allowlist.
- Folder access is three independent flags, read, write and execute, in any
  combination (`access = "rx"`), and the `nerve-node` CLI is noun then verb
  (`center add`, `folder add <path> +r +x`, `folder set <path> -w`,
  `rule add allow`, `mode set`), with the Help page of the center grouped by what a
  person wants to do, one card per noun.
- The node's config and state folders are its own: no call of a center
  reaches them and no Landlock rule of a command covers them, whatever the
  policy says. The node keeps its config in memory, signs `node.toml` with an
  HMAC on every write, rereads it only when the owner asks, and refuses and
  audits a file changed outside the owner's path (`nerve-node config accept`
  takes it after a look).
- The sudo switch per node, off by default: off, no command runs with sudo
  even when the sudo allow list names it; on, a sudo command runs only when
  that list names it, in every mode. `nerve-node sudo on|off|status`, or a
  center with the settings grant `write`, which relays the password sealed end to end (X25519, HKDF,
  AES-GCM) without being able to read it. The node checks the password with
  `sudo -v`, keeps it in memory only and scrubs it from every frame and the
  audit log. Every other command runs with `no_new_privs`. Linux only.
- Proxy header values, and a user name and password in the proxy URL, live in
  the system keyring; `node.toml` keeps only the URL and the header names, and
  a file that still holds values is refused with a hint to run
  `nerve-node proxy set` again.
- `nerve-center`: the center, run by a harness as an MCP server. It pairs nodes,
  keeps their links and offers their capabilities as MCP tools. Its web UI
  has a login page (the harness token logs in; `--ui-no-login` on loopback
  turns it off) and shows nodes, the audit log (four rule buttons per entry),
  statistics, a help page with the node's commands and the settings of nodes
  that granted write access (`spec/harness.md`).
- Conformance suite with a center part and a node part (pairing, link,
  descriptor, fs, exec, allow and deny rules, audit and the sudo switch); the
  harness part is a skeleton (`spec/conformance.md`).
- MCP tool names are `<cap>_<action>`, or `<node>_<cap>_<action>` when the node
  is part of the name, with one `_` as the only separator; node, capability
  and action names use letters, digits and `-`, and the center ignores a
  descriptor whose names have a `_` (`spec/harness.md`).
