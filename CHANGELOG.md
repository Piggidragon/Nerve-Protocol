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
- In default deny the center gets tools only for the `fs` and `exec` actions
  an allow rule covers (and `exec.run` when the sudo list has an entry); the
  node sends a new descriptor when a rule is added or removed.
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
- A node can be disabled in the center (web UI, `POST /api/nodes/disable`): it
  stays paired and connected, but the agent is offered none of its tools and
  calls to it are refused.
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
- The owner sets how long a pairing code is valid, 1 to 1440 minutes (24 hours), in Settings, Center; 10 minutes unless changed, and a code keeps the lifetime it was made with.
- `exec.signal` is decided by the policy and audited like every other action, so a deny rule refuses it.
- The sudo password goes to sudo only after its prompt; a command sudo runs without asking (NOPASSWD, root) never finds it on its stdin.
- `fs.read` and `fs.write` open their path without following a symlink (Unix), so a symlink swapped in after the policy check fails the call.
- A pairing code pairs one node also when several requests send it at the same moment.
- A center with the settings grant `write` can add protected paths to `protected.extra` but not remove the owner's.
- The node's audit log logs at most 512 characters of a target and moves to `audit.jsonl.1` at 10 MiB, keeping one old file.
- Ending an MCP session (stdio closed, `DELETE /mcp`, the web UI) stops the commands it started: the node acts on `session.end` like on `cancel`, and an MCP `notifications/cancelled` cancels the call on its node.
- On Windows, command output that is not UTF-8 is decoded from the console code page Windows PowerShell wrote it in, so umlauts no longer come back as replacement characters, and the `exec.run` text names the shell (Windows PowerShell 5.1: chain with `;`, not `&`).
- On Windows each command runs in a Job Object of its own: a cancel, a timeout, `exec.signal`, the session's end or the node's own end ends every process the command started, however deep (not one WMI, a service or the task scheduler starts for it); folder mode still runs no command there.
