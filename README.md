# Nerve Protocol

Nerve lets an agent harness use its owner's machines: read and write files and
run commands. On each machine the owner decides what is allowed; everything
else is refused.

Two programs:

- **`nerve-center`**, the center. A harness starts it as an MCP server; it pairs
  nodes, keeps their links and offers their capabilities as MCP tools. Its web
  UI (loopback, port 7480 by default) shows nodes, the audit log,
  statistics and pairing links, lets you rename, disable or remove a machine,
  and lists the node's commands on a help page.
- **`nerve-node`**, the node. A daemon on each machine plus a headless CLI for
  pairing, policy and the audit log.

The protocol is in [`spec/`](spec/README.md), JSON Schemas in `schemas/`, the
conformance suite in `crates/nerve-conformance`.

## Build

If you're searching for pre-build binaries that work straight out of the box head to [Releases](https://github.com/Piggidragon/Nerve-Protocol/releases).

Rust 1.88 or newer.

```sh
cargo build --release
# target/release/nerve-center and target/release/nerve-node
```

Checks:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Static Linux binaries and the Windows cross-build: [`docs/building.md`](docs/building.md).

## Run

1. Add the center to the harness's MCP configuration:

   ```json
    {
      "mcpServers": {
        "nerve": {
          "command": "nerve-center",
          "env": {
            "NERVE_NAME": "lab"
          }
        }
      }
    }
   ```

   Nodes reach it on port 7443 (TLS with a self-signed certificate that the
   pairing link pins). `nerve-center --help` and [`spec/harness.md`](spec/harness.md)
   list every setting, including MCP over HTTP (`--mcp http`).

2. Open the web UI at `http://127.0.0.1:7480` and make a pairing link (its
   code is valid for 10 minutes; Settings, Center changes that).

   Login:

   - The UI logs in with the harness token (`NERVE_HARNESS_TOKEN`, or one made
     in its settings).
   - A center without a token yet is open to this machine.
   - Beyond loopback (`--ui 0.0.0.0:7480`) a token is required.
   - On loopback, `--ui-no-login` turns the login off.

3. On the machine, as a normal user:

   ```sh
   nerve-node center add 'nerve://pair?center=...&code=...&pin=...'
   nerve-node run      # stays in the foreground; run other commands in another shell
   ```

A new center starts in `allowlist` mode with no rule, so every call is refused
until you allow something. Rules, folders, modes, sudo, deny rules, panic, the
audit log and the Windows and Landlock notes are in
[`docs/policy.md`](docs/policy.md). `nerve-node --help` lists every command;
[`spec/node-local.md`](spec/node-local.md) explains the policy.
