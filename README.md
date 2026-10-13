# Nerve Protocol

Nerve lets an agent harness use its owner's machines: read and write files and
run commands. On each machine the owner decides what is allowed. Everything
else is refused.

Two programs:

| Program | Job |
|---|---|
| `nerve-center` | The center. A harness starts it as an MCP server. It pairs machines, keeps their links, gives the harness their tools and serves a web UI |
| `nerve-node` | The node. A daemon on each machine, plus a CLI for pairing, rules and the audit log |

## Quick install

On a Linux machine the agent may use, install the node as a service (use
`nerve-node-aarch64-linux` on ARM):

```sh
curl -LO https://github.com/Piggidragon/Nerve-Protocol/releases/latest/download/nerve-node-x86_64-linux
chmod +x nerve-node-x86_64-linux
sudo ./nerve-node-x86_64-linux install
sudo nerve-node setup
```

`install` puts the program at `/usr/local/bin/nerve-node` and starts it as a
service under a user of its own ([service](docs/user/service.md)). The center
is `nerve-center-x86_64-linux` (or `-aarch64-linux`, `-x86_64-windows.exe`)
from the same release.

## Quick start

Get the programs from
[Releases](https://github.com/Piggidragon/Nerve-Protocol/releases).

1. Add the center to the harness's MCP configuration:

   ```json
   {"mcpServers": {"nerve": {"command": "nerve-center"}}}
   ```

2. Open `http://127.0.0.1:7480`, press **Pair a machine**, and run the command
   it shows on the machine:

   ```sh
   nerve-node center add 'nerve://pair?center=...&code=...&pin=...'
   nerve-node run
   ```

3. A new pairing allows nothing. Allow what you want:

   ```sh
   nerve-node rule add allow 'git status'
   ```

## Documentation

| For | Where |
|---|---|
| Running Nerve: install, pairing, rules and modes, the web UI, troubleshooting | [docs/user/](docs/user/README.md) |
| Building, changing and releasing Nerve: architecture, policy engine, checks | [docs/dev/](docs/dev/README.md) |
| The protocol and the conformance suite | [docs/dev/spec/](docs/dev/spec/README.md), [schemas/](schemas), [crates/nerve-conformance](crates/nerve-conformance) |
