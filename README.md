# Nerve Protocol

Nerve lets an agent harness reach the machines of its owner: read and write
files, run commands, with the owner deciding on each machine what is allowed
and what asks first. Version 0.0.1 is the first pre-release of the rewrite.

Two programs:

- **`nerve-mcp`**, the center. A harness starts it as an MCP server; it pairs
  nodes, keeps their links and offers their capabilities as MCP tools. Its web
  UI (loopback, port 7480 by default) shows nodes, pending approvals,
  statistics and pairing links.
- **`nerve-node`**, the node. A daemon on each machine plus a headless CLI for
  pairing, policy, approvals and the audit log.

The protocol is in [`spec/`](spec/README.md), JSON Schemas in `schemas/`, the
conformance suite in `crates/nerve-conformance`.

## Build

Rust 1.88 or newer.

```sh
cargo build --release
# target/release/nerve-mcp and target/release/nerve-node
```

Checks:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Static Linux binaries (needs the musl target and clang):

```sh
CC_x86_64_unknown_linux_musl=clang cargo build --release --target x86_64-unknown-linux-musl
```

Windows binaries from Linux with `cargo-xwin` (the static C runtime avoids a
missing `vcruntime140.dll`):

```sh
CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-C target-feature=+crt-static" \
  cargo xwin build --release --target x86_64-pc-windows-msvc
```

## Run

1. Add the center to the harness's MCP configuration:

   ```json
   {"mcpServers": {"nerve": {"command": "nerve-mcp", "env": {"NERVE_NAME": "lab"}}}}
   ```

   Nodes reach it on port 7443 (TLS with a self-signed certificate that the
   pairing link pins). `nerve-mcp --help` and [`spec/harness.md`](spec/harness.md)
   list every setting, including MCP over HTTP (`--mcp http`).

2. Open the web UI at `http://127.0.0.1:7480` and make a pairing link.

3. On the machine, as a normal user:

   ```sh
   nerve-node pair 'nerve://pair?center=...&code=...&pin=...'
   nerve-node run
   ```

   A new center starts in `ask` mode: every read, write and command asks.
   Answer in the web UI or on the machine:

   ```sh
   nerve-node approvals              # open questions
   nerve-node approve <id>           # or: deny <id>
   nerve-node mode folders           # allow inside the folders you add
   nerve-node folder add ~/proj --rw --execute
   nerve-node allow 'git status'     # a command that never asks
   nerve-node audit                  # what was asked, allowed and denied
   nerve-node panic                  # end every link; `unlock` undoes it
   ```

   `nerve-node --help` lists every command; [`spec/node-local.md`](spec/node-local.md)
   explains the policy.

## Not in 0.0.1

Service install, `setup --create-user`, sudo rules and updates
(`nerve-node install|setup|sudo|update|uninstall` say so); cgroup limits and
the Windows job object; the Windows control socket (the CLI edits `node.toml`
directly there); streams (`stream.open` answers `unavailable`); the harness
part of the conformance suite.

Harnesses integrate through MCP only; native plugins are a backlog item.

Open points, not decided: approvals through MCP elicitation (0.0.1
keeps them in the node's queue), and the mode names (p04).
