# Changelog

## 0.0.1

- Pair a node with a center using a one-time code; the node pins the center's certificate and the two talk over a signed link.
- `nerve-node` runs on a machine and offers files (`fs`) and commands (`exec`) to the center, with a headless CLI to manage it.
- `nerve-center` runs as an MCP server for an agent harness and offers every paired node's capabilities as MCP tools.
- Policy modes per center: default deny, allowlist (the default), folder and user. Folder and user give full access in their area; allowlist allows only what a rule names.
- Allow and deny rules with wildcards for every action, and protected paths that stay closed in every mode.
- Folder access is set per folder as read, write and execute, in any combination.
- Commands run with sudo only if the owner turns sudo on for the node. The password is kept in memory and never logged.
- The node keeps a local audit log of every decision, and can be locked with panic and unlock.
- A web UI for the center shows nodes, the audit log (with one-click rules), statistics and help, and lets you disable a node.
