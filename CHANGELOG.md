# Changelog

## 0.0.2

- Install the node as a service with `install`, `update` and `uninstall`, on Linux (systemd) and on Windows. The service runs as its own `nerve` user; config, keys and state are kept out of the commands' reach.
- Commands run as the account that installed the node, or as one you choose in `setup`. `setup --create-user` makes a new account with its own home folder.
- User mode, folder mode and sudo run their commands as that account. Folder mode on Linux is limited to the folders you gave.
- A node started as root, or as administrator on Windows, is refused unless `machine.allow_root` is set, and warns when it runs.
- Download and install in two steps: `sudo ./nerve-node-x86_64-linux install`.

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
- The web UI has a Log page for the center's own log (written to `log.jsonl`), with levels, filters and download.
- Statistics can be shown per machine, picked from a searchable list; the default is overall.
