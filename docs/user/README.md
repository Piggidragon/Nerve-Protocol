# Nerve user guide

Nerve lets an agent harness use your machines: read and write files and run
commands. On each machine you decide what is allowed. Everything else is
refused.

Two programs make it work:

| Program | Runs on | Job |
|---|---|---|
| `nerve-center` | the machine where the harness runs | Pairs machines, keeps their links, gives the harness their tools over MCP, serves the web UI |
| `nerve-node` | every machine the agent may use | Links to a center and decides each call by the rules you set |

The node always dials the center. A machine behind NAT or a firewall needs no
open port.

## Start here

1. [Install](install.md) the programs.
2. [Run the center](center.md) and [connect a harness](harness.md).
3. [Pair a machine](pairing.md).
4. Allow something with a [mode](modes.md) or a [rule](rules.md). Until you do,
   every call is refused.

## All pages

| Page | Covers |
|---|---|
| [install.md](install.md) | Download, check, install, where files live |
| [center.md](center.md) | Start the center, its flags and ports |
| [harness.md](harness.md) | Connect an MCP harness, the tools it gets |
| [pairing.md](pairing.md) | Pair a machine, start the node, unpair |
| [modes.md](modes.md) | `allowlist`, `folder` and `user` mode, folders and their rights |
| [rules.md](rules.md) | Allow and deny rules, wildcards, switching capabilities off |
| [protected-paths.md](protected-paths.md) | The files that stay closed in every mode |
| [sudo.md](sudo.md) | The sudo switch |
| [settings-grant.md](settings-grant.md) | Let a center change a machine's settings |
| [config.md](config.md) | Read and change `node.toml` by name |
| [audit.md](audit.md) | See what was allowed and refused |
| [logs.md](logs.md) | The log of the center and the node: levels, what is in it, where it is |
| [stop.md](stop.md) | Panic, pause, disable, remove |
| [proxy.md](proxy.md) | Reach the center through an HTTP proxy |
| [web-ui.md](web-ui.md) | The center's web UI |
| [platforms.md](platforms.md) | What differs on Linux and Windows |
| [troubleshooting.md](troubleshooting.md) | Messages and what to do |
| [commands.md](commands.md) | Every `nerve-node` command in one table |
