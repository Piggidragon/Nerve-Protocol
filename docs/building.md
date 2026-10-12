# Building

The normal build and the checks are in the [README](../README.md#build). This
page covers the static Linux build and the Windows cross-build. The release
workflow builds both ([`releasing.md`](releasing.md)).

## Static Linux binaries

Needs the musl target and clang:

```sh
CC_x86_64_unknown_linux_musl=clang cargo build --release --target x86_64-unknown-linux-musl
```

## Windows binaries from Linux

Use `cargo-xwin`. The static C runtime avoids a missing `vcruntime140.dll`:

```sh
CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-C target-feature=+crt-static" \
  cargo xwin build --release --target x86_64-pc-windows-msvc
```
