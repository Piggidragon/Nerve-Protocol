# Building and checks

## Build

Needs Rust 1.88 or newer.

```sh
cargo build --release
# target/release/nerve-center and target/release/nerve-node
```

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The release workflow runs the same three with `--locked --workspace` before it
builds anything ([releasing](releasing.md)).

`cargo test` runs the unit tests, the integration tests and the
[conformance suite](../../spec/conformance.md). The end-to-end tests, which
start the real `nerve-center` and `nerve-node`, run on Unix. To run only the
suite:

```sh
cargo test -p nerve-conformance
```

## Static Linux binaries

Needs the musl target and clang:

```sh
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=clang cargo build --release --target x86_64-unknown-linux-musl
```

The programs are in `target/x86_64-unknown-linux-musl/release/`. For ARM, use
the target `aarch64-unknown-linux-musl` and the variable
`CC_aarch64_unknown_linux_musl`.

## Windows binaries from Linux

Use `cargo-xwin`. The static C runtime avoids a missing `vcruntime140.dll`:

```sh
rustup target add x86_64-pc-windows-msvc
CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-C target-feature=+crt-static" \
  cargo xwin build --release --target x86_64-pc-windows-msvc
```

The programs are in `target/x86_64-pc-windows-msvc/release/`.
