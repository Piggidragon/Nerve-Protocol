# Changelog

## Unreleased

### Capability providers

- A program on the machine that the owner names in `providers.allowed`, such as a desktop app, can attach to the node's control socket and add capabilities of its own. The node lists them to every center with `provider: <name>`, decides and audits every call to them by that center's policy, forwards only the allowed ones, and drops them when the program exits. Linux only for now; the conformance suite has a provider part ([#16](https://github.com/Piggidragon/Nerve-Protocol/issues/16)).
- In `folder` mode an action that names no path, which is what a provider adds, runs only where the owner set it `on`.
- A 0.0.3 node refuses a `node.toml` that holds `providers`. Before you go back to 0.0.3, remove it with `nerve-node config unset providers`.

## 0.0.3

### Upgrading from 0.0.2

- A 0.0.2 `nerve-node` CLI talking to a 0.0.3 node on Linux is refused for everything except `status`, because it sends no control-socket token ([#83](https://github.com/Piggidragon/Nerve-Protocol/pull/83)). `update` of 0.0.2 still works, as it asks only `status`. After it, run the CLI from the 0.0.3 program too.
- A 0.0.2 node refuses a `node.toml` that holds `places` under a pairing's `policy`, which 0.0.3 writes with `folder add` ([#88](https://github.com/Piggidragon/Nerve-Protocol/pull/88)). Before you go back to 0.0.2, remove the key with `nerve-node config unset center.<name>.policy.places` for each pairing.

### Folder mode on Windows

- Commands in folder mode now run in an AppContainer of their own, so a command only reaches the folders you gave it, on a node you run yourself; the installed Windows service still runs no command in folder mode ([#39](https://github.com/Piggidragon/Nerve-Protocol/issues/39), [#45](https://github.com/Piggidragon/Nerve-Protocol/pull/45)). `docs/user/modes.md` also lists what the AppContainer does not stop ([#86](https://github.com/Piggidragon/Nerve-Protocol/pull/86)).
- PowerShell `cd`, `chdir`, `sl` and `pushd` work with whole paths in the container, not only inside the `Work:` drive ([#85](https://github.com/Piggidragon/Nerve-Protocol/pull/85)).
- `folder add`, `folder set` and `folder rm` reach a running node at once, through a control pipe that a command cannot use ([#53](https://github.com/Piggidragon/Nerve-Protocol/issues/53), [#93](https://github.com/Piggidragon/Nerve-Protocol/pull/93)).
- A large folder is walked only where the grant changes, so applying the same grant again is much faster ([#54](https://github.com/Piggidragon/Nerve-Protocol/issues/54), [#95](https://github.com/Piggidragon/Nerve-Protocol/pull/95)).
- The keyring refusal text for folder mode names the AppContainer and the Credential Manager, not Landlock ([#91](https://github.com/Piggidragon/Nerve-Protocol/issues/91), [#102](https://github.com/Piggidragon/Nerve-Protocol/pull/102)).

### Folder mode on Linux

- A folder a command replaced by a link is no longer followed ([#74](https://github.com/Piggidragon/Nerve-Protocol/issues/74), [#80](https://github.com/Piggidragon/Nerve-Protocol/pull/80)).
- On Windows and Linux, a recorded folder stays at the place it was added, so a junction or link made later does not move it ([#77](https://github.com/Piggidragon/Nerve-Protocol/issues/77), [#88](https://github.com/Piggidragon/Nerve-Protocol/pull/88)).
- `folder set` and `folder rm` name the stored folder when the node cannot look into the path you typed ([#98](https://github.com/Piggidragon/Nerve-Protocol/issues/98), [#103](https://github.com/Piggidragon/Nerve-Protocol/pull/103)).

### Control socket and config

- A sandboxed command can no longer read the node config over the control socket; the socket answers only requests that carry the owner's token, and refuses every request that comes from below a command the node runs ([#70](https://github.com/Piggidragon/Nerve-Protocol/issues/70), [#83](https://github.com/Piggidragon/Nerve-Protocol/pull/83)).
- A busy control socket is no longer taken for a stopped node, and `panic` and `unlock` no longer report a change the node did not get ([#69](https://github.com/Piggidragon/Nerve-Protocol/issues/69), [#79](https://github.com/Piggidragon/Nerve-Protocol/pull/79)).
- The keys lock is free again right after it is released, even when a command was forked in the meantime ([#73](https://github.com/Piggidragon/Nerve-Protocol/issues/73), [#79](https://github.com/Piggidragon/Nerve-Protocol/pull/79)).
- `rule add` refuses the `fs:...` and `exec:...` forms, and `rule rm` removes entries that older runs made by mistake ([#78](https://github.com/Piggidragon/Nerve-Protocol/issues/78), [#79](https://github.com/Piggidragon/Nerve-Protocol/pull/79)).
- `machine.secret_storage = "keyring"` keeps the node's own keys in the system keyring, opt-in ([#46](https://github.com/Piggidragon/Nerve-Protocol/issues/46), [#47](https://github.com/Piggidragon/Nerve-Protocol/pull/47)).

### Sudo and install

- On Windows, sudo runs the command account with its elevated token ([#60](https://github.com/Piggidragon/Nerve-Protocol/issues/60), [#75](https://github.com/Piggidragon/Nerve-Protocol/pull/75)).
- `install` and `setup` warn when the account that runs the commands can become root without a password ([#97](https://github.com/Piggidragon/Nerve-Protocol/issues/97), [#104](https://github.com/Piggidragon/Nerve-Protocol/pull/104)).
- The installed Windows node writes start, stop and failures to the Event Log ([#65](https://github.com/Piggidragon/Nerve-Protocol/issues/65), [#71](https://github.com/Piggidragon/Nerve-Protocol/pull/71)).
- On the installed Windows node, a proxy with header values or a URL password is refused, because the node cannot read them ([#68](https://github.com/Piggidragon/Nerve-Protocol/issues/68), [#81](https://github.com/Piggidragon/Nerve-Protocol/pull/81)).
- `uninstall` removes a node's profiles even when its state folder is already gone ([#55](https://github.com/Piggidragon/Nerve-Protocol/issues/55), [#84](https://github.com/Piggidragon/Nerve-Protocol/pull/84)).

### CI

- Pull requests run `cargo fmt`, `clippy` and the tests on Linux and on Windows ([#58](https://github.com/Piggidragon/Nerve-Protocol/issues/58), [#100](https://github.com/Piggidragon/Nerve-Protocol/pull/100)).
- The keyring places test runs on Unix only, and the Windows test build works again ([#96](https://github.com/Piggidragon/Nerve-Protocol/issues/96), [#101](https://github.com/Piggidragon/Nerve-Protocol/pull/101)).

## 0.0.2

- Install the node as a service with `install`, `update` and `uninstall`, on Linux (systemd) and on Windows. The service runs as its own `nerve` user; config, keys and state are kept out of the commands' reach.
- Commands run as the account that installed the node, or as one you choose in `setup`. `setup --create-user` makes a new account with its own home folder.
- User mode, folder mode and sudo run their commands as that account. Folder mode on Linux is limited to the folders you gave.
- A node started as root, or as administrator on Windows, is refused unless `machine.allow_root` is set, and warns when it runs.
- Download and install in two steps: `sudo ./nerve-node-x86_64-linux install`.
