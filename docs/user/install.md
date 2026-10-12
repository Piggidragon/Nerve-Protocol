# Install

Put `nerve-center` on the machine where your agent harness runs. Put
`nerve-node` on every machine the agent may use. They can share a machine.

## Download

Get the programs from
[Releases](https://github.com/Piggidragon/Nerve-Protocol/releases). Each
release has six programs and a `SHA256SUMS` file.

| System | Files |
|---|---|
| Linux, x86_64 | `nerve-center-x86_64-linux`, `nerve-node-x86_64-linux` |
| Linux, ARM 64-bit | `nerve-center-aarch64-linux`, `nerve-node-aarch64-linux` |
| Windows, x86_64 | `nerve-center-x86_64-windows.exe`, `nerve-node-x86_64-windows.exe` |

The Linux programs are static and need no libraries. The Windows programs
need no Visual C++ runtime. The programs are not signed, so check them
against `SHA256SUMS`.

## Install on Linux

```sh
sha256sum --check --ignore-missing SHA256SUMS
install -m 0755 nerve-center-x86_64-linux ~/.local/bin/nerve-center
install -m 0755 nerve-node-x86_64-linux ~/.local/bin/nerve-node
nerve-node --version
```

Use the `aarch64` files on an ARM machine. `~/.local/bin` must be on your
`PATH`.

## Install on Windows

In PowerShell, compare each hash with its line in `SHA256SUMS`:

```powershell
(Get-FileHash .\nerve-node-x86_64-windows.exe).Hash
```

Then rename the files to `nerve-center.exe` and `nerve-node.exe` and put them
in a folder on your `PATH`.

## Build from source

See [building](../dev/building.md).

## Where files live

| What | Linux | Windows | Change with |
|---|---|---|---|
| Node: `node.toml`, one key per center | `~/.config/nerve` | `%USERPROFILE%\.config\nerve` | `--config-dir`, `NERVE_CONFIG_DIR` |
| Node: audit log, control socket, config key | `~/.local/state/nerve` | `%USERPROFILE%\.local\state\nerve` | `--state-dir`, `NERVE_STATE_DIR` |
| Center: identity, paired machines, statistics | `$XDG_STATE_HOME/nerve-center`, else `~/.local/state/nerve-center` | `%LOCALAPPDATA%\nerve-center` | `--state-dir`, `NERVE_STATE_DIR` |

Both programs read `NERVE_STATE_DIR`. On a machine that runs both, set it per
program or use the flags. Do not set it for the whole machine.

The node keeps its own folders closed. No center can read them, whatever the
rules say.

## Next

[Run the center](center.md).
