# Nerve Protocol

Nerve lets an agent harness reach the machines of its owner: read and write
files, run commands, with the owner deciding on each machine what is allowed
and what is allowed at all: everything else is refused.

Two programs:

- **`nerve-center`**, the center. A harness starts it as an MCP server; it pairs
  nodes, keeps their links and offers their capabilities as MCP tools. Its web
  UI (loopback, port 7480 by default) shows nodes, the audit log,
  statistics and pairing links, and lists the node's commands on a help page.
- **`nerve-node`**, the node. A daemon on each machine plus a headless CLI for
  pairing, policy and the audit log.

The protocol is in [`spec/`](spec/README.md), JSON Schemas in `schemas/`, the
conformance suite in `crates/nerve-conformance`.

## Build

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
   {"mcpServers": {"nerve": {"command": "nerve-center", "env": {"NERVE_NAME": "lab"}}}}
   ```

   Nodes reach it on port 7443 (TLS with a self-signed certificate that the
   pairing link pins). `nerve-center --help` and [`spec/harness.md`](spec/harness.md)
   list every setting, including MCP over HTTP (`--mcp http`).

2. Open the web UI at `http://127.0.0.1:7480` and make a pairing link. The UI
   logs in with the harness token (`NERVE_HARNESS_TOKEN`, or one made in its
   settings); a center without a token yet is open to this machine. Beyond
   loopback (`--ui 0.0.0.0:7480`) a token is required; on loopback
   `--ui-no-login` turns the login off.

3. On the machine, as a normal user:

   ```sh
   nerve-node center add 'nerve://pair?center=...&code=...&pin=...'
   nerve-node run
   ```

   A new center starts in `allowlist` mode (default deny) with no rule, so
   every call is refused at once: nothing waits for an answer. Either allow
   what you want, or give it full access and deny what you do not want:

   ```sh
   nerve-node rule add allow 'git status'     # allowlist mode: this command may run
   nerve-node rule add allow 'git status' --wildcard   # ... and `git` with anything after
   nerve-node config add center.home.policy.allow 'fs.read:~/notes/*'   # a path
   nerve-node mode set folder        # or: full access in the folders below
   nerve-node folder add ~/proj +r +w +x   # read, write, run commands; any mix
   nerve-node folder set ~/proj -w   # chmod style: =rwx, +x, -w, left to right
   nerve-node mode set user          # or: full access as the user (--for N: only for N hours)
   nerve-node rule add deny 'rm *' --wildcard # in every mode: never, and wins over allow
   nerve-node rule ls allow          # what is on a list (also deny, sudo; no list shows all; rm takes one off)
   nerve-node audit                  # what was allowed and refused
   nerve-node panic                  # end every link; `unlock` undoes it
   ```

   Allow rules count in `allowlist` mode only; deny rules count in every mode.

   Sudo is a switch per machine, off by default. While it is off, no command
   runs with sudo, whatever the rules say. Switched on (the node checks the
   password with `sudo -v` and keeps it in memory only), a sudo command runs
   only when the sudo allow list names it, in every mode:

   ```sh
   nerve-node rule add sudo 'sudo apt update'   # a sudo command goes on its own list
   nerve-node sudo on                # asks for the password
   nerve-node sudo off               # drops it
   ```

   A center the machine granted settings write may switch it as well; the
   password then travels sealed from the browser to the node.

   `nerve-node --help` lists every command; [`spec/node-local.md`](spec/node-local.md)
   explains the policy.

Harnesses integrate through MCP.
