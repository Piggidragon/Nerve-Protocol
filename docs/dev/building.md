# Building and checks

## Build

Needs Rust 1.88 or newer (`rust-version` in `Cargo.toml`). Only 1.99.0, the
toolchain of CI and the release, is tested; nothing checks 1.88.

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

The `CI` workflow (`.github/workflows/ci.yml`) runs on every pull request and on
every push to `main`. Its Linux job and its Windows job each run fmt, clippy and
`cargo test --workspace`, so the tests that are compiled only on Windows (grants,
the integrity level, the service steps, the job object, Windows paths) run on
a Windows runner. Most of the AppContainer and grant end-to-end tests are
skipped there for now, because they fail on the hosted runner (issues
[#105](https://github.com/Piggidragon/Nerve-Protocol/issues/105) and
[#106](https://github.com/Piggidragon/Nerve-Protocol/issues/106)): run them by
hand on the Windows test machine. The same job skips
`a_cancel_ends_a_chain_of_processes_that_hand_over_and_exit`, a timing flake
([#107](https://github.com/Piggidragon/Nerve-Protocol/issues/107)). Both use the toolchain of the release
and a cargo cache keyed by `Cargo.lock`, so a change to the lock file builds
once from scratch.

A test that needs more than a hosted runner has (the node installed as a
service, an administrator account, a virtual disk, the system keyring) is
`#[ignore = "<reason>"]`: every run lists it as ignored with its reason, and it
is run by hand on a Windows test machine with `cargo test -- --ignored`. The
Windows job also skips by name the tests that fail on Windows today; the comment
in the workflow says which and why, and the skip goes when the test is fixed.

`cargo test` runs the unit tests, the integration tests and the
[conformance suite](spec/conformance.md). The end-to-end tests, which
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
