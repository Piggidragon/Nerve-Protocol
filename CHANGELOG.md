# Changelog

## Unreleased

### The desktop app

- `nerve-node-desktop` is the node with a window, for Linux x86_64 (GNOME or KDE Plasma, Wayland or X11; glibc 2.35 or newer) and Windows x86_64 ([#10](https://github.com/Piggidragon/Nerve-Protocol/issues/10)). It is one program: started with arguments it is `nerve-node`, started without any it opens the window. The window runs the CLI for every action, so it has the CLI's checks and audit records. See `docs/user/desktop.md`.
- Its pages: overview (the node's state, panic and unlock, and the service's start, stop and restart); centers with pairing (also from a `nerve://` link), pause, resume and key rotation; permissions (mode, folders, rules, capability switches, sudo); audit; log; settings (config, proxy, relay, backup and restore); help; and the About dialog. A first-run setup names the node and pairs its first center. Light and dark follow the system, or the choice saved in the app.
- The audit page has allow, allow as wildcard, deny and deny as wildcard on each entry, which write the same rule as `nerve-node rule add --action` ([#23](https://github.com/Piggidragon/Nerve-Protocol/issues/23)).
- The downloaded file installs itself: the program, the node as a service under its own user (as `nerve-node install`), the menu or Start menu entry with its icon, and the `nerve://` handler, after the system's question for the rights (pkexec, UAC). Started again, it offers to open, update or uninstall Nerve. Settings update it (from the latest release, checked against `SHA256SUMS`, or a file) and uninstall it, keeping or deleting the node's data. On Windows it is in **Apps & features**, whose **Uninstall** opens the app's uninstall.
- A node installed with `nerve-node` is taken over: the service runs the desktop app's program, and `nerve-node` (`nerve-node.exe` on Windows) becomes a link to it, so the terminal command keeps working. Uninstall removes the link.
- The release has `nerve-node-desktop-x86_64-linux` and `nerve-node-desktop-x86_64-windows.exe`, with their checksums in `SHA256SUMS`.
- The `NOTICE` file holds the licence of the Lucide icons, which the app and the center's web UI use. The app is built with Slint under its Royalty-free license 2.0.

### Commands

- `--json` on the read commands (`status`, `center ls`, `folder ls`, `rule ls`, `cap ls`, `config get`, `proxy ls`, `relay ls`, `sudo status`, `service status`, `audit`, `log`), and `{"messages": [...]}` or `{"error": ...}` from every other command (`docs/user/commands.md`).
- No command waits for typing when stdin is no terminal: passwords and passphrases come from the first line of stdin or `--passphrase-file`, and `center add` needs `--yes`. `proxy set --password-stdin --headers-stdin` takes the proxy's password and headers from stdin.
- `rule add` and `rule rm` take `--action`, the rule of an audit entry. `audit --last N` shows the newest entries only.
- `nerve-node log [--last N] [--follow]` shows the node's log.
- `nerve-node service start|stop|restart|status` controls the installed service; `status` needs no root.
- `cap ls --json` lists the switchable capabilities (`known`).
- Commands run through `pkexec` take the user who ran it as the account of the commands at `install`, as with `sudo`.
- On Windows, the text `status` asks the running service through the control pipe, as `status --json` does.

## 0.0.5

### The action checker

- The center checks each call before the machine gets it, and can refuse it ([#17](https://github.com/Piggidragon/Nerve-Protocol/issues/17)). In this order: a blocklist of dangerous commands and paths, the allow rules saved in the center, an optional decision model, then the machine's own policy as before. A block anywhere wins: a center allow rule only skips the model, never a blocklist entry or the machine's rules. The refusal comes back to the agent as `forbidden` and says what refused it and where the owner changes that. Set it up on the new **Action checker** page of the web UI; the details are in `docs/user/action-checker.md`.
- The blocklist is on by default. It catches an agent's mistakes (`rm -rf ~`, `mkfs`, `dd` to a disk, a force-push to `main`, their Windows equivalents), not command lines written to get past it; against those the machine's own policy counts. A download piped into a shell (`curl … | sh`, `irm … | iex`) is refused by default too, also a tool's official install one-liner. Entries can be added, removed, switched off and reset to the defaults. The built-in entries come with the program, so a later release's changes to them reach the center; what you switched off or removed stays.
- Block entries and allow rules are for every machine or one, an entry for every machine can be switched off for one, and each machine sets the blocklist and the model to follow the center, on or off.
- The decision model is off by default. It is a System One endpoint (`/v1/systemone`, with an optional bearer token), or a local model the center installs with one click: a pinned llama.cpp build and LiquidAI d1-3B (LFM Open License v1.0, the default) or Kev-4B (Apache-2.0), each checked against its pinned SHA-256 and run on loopback, on the CPU or the GPU (Vulkan). A model that cannot be reached or answer in time refuses the call (fail closed) unless the owner switches that to allow-and-log.
- Taint marks a session once a call of it returned content, so the model can be given only the calls of such sessions. Every decision of the checker is on the Audit page and in the center's log.
- The center now keeps `checker-model.token` (the endpoint's token) and the `checker/` folder (the local build and model, 1.7 or 3.0 GB) in its state folder. Neither is in a backup: after a restore on another machine, enter the token again and install the local model again; until then a model that is on refuses the calls it sees.
- A center that ran 0.0.4 starts with the blocklist on and its default entries, so a call that 0.0.4 passed to the machine may now be refused. Switch the blocklist, or one entry, off on the Action checker page, for every machine or under **Per machine**. Nodes need no update: the checker runs on the center only.
- A 0.0.4 center reads a 0.0.5 `state.json`, but leaves the checker's settings out the next time it writes the state (after a call or a change), so they are gone. Before you go back to 0.0.4, note your own entries, allow rules and model settings: 0.0.5 starts from the defaults again. Delete the `checker/` folder in the state folder to free its space; 0.0.4 does not use it or the token.

## 0.0.4

### Limits per command

- On Linux every command runs in a cgroup of its own, held to its memory, CPU and processes. The owner sets the defaults and the most a call may ask for in `[limits.command]` of `node.toml`; `exec.run` takes `memory_mb`, `cpu_percent` and `processes` up to that most. A command past its memory is killed, and its result (`killed: "memory"`) and the audit log say why. `nerve-node status` shows the limits and whether the node holds them ([#119](https://github.com/Piggidragon/Nerve-Protocol/issues/119)).
- When a command ends, everything in its cgroup ends too, also a process it moved out of its process group.
- The installed unit gets `Delegate=cpu memory pids`. After `update`, run `sudo nerve-node install` once more to write it; until then commands run without these limits. A node you start yourself has them under `systemd-run --user --scope -p Delegate=yes nerve-node run`.
- A 0.0.3 node refuses a `node.toml` that sets `[limits.command]`. Before you go back to 0.0.3, remove it with `nerve-node config unset limits.command`.

### Backup, restore and moving

- `nerve-node backup <file>` and `nerve-node restore <file>`, and the same for `nerve-center`, write the config and keys (the center's certificate, key and state) to one file that a passphrase protects (PBKDF2-HMAC-SHA256 and ChaCha20-Poly1305, at least 12 characters), and put them back on the same machine or another, so a node or a center can be moved without pairing again ([#122](https://github.com/Piggidragon/Nerve-Protocol/issues/122)).
- Keys in the system keyring, and a proxy's header values, go into a backup only with `--include-keyring`. A restore never goes under a running node or center, refuses a backup of another node or center unless you add `--replace`, keeps every pin as saved, except a newer one here from a key rotation (or set by hand since), which stays, and a center's old pin whose time ended here, which does not come back, and sets the sudo switch off. These are two of `nerve-center`'s subcommands now; a harness still starts it without one.

### The center as a service

- On Linux with systemd, `sudo nerve-center install` installs the center as a service that starts with the machine, under a user of its own (`nerve-center`) with its own state folder (`/var/lib/nerve-center`), with MCP over HTTP and no privilege. Its settings are in `/etc/nerve-center/center.env`, which `install` writes once with a new harness token, so the web UI asks for a login from the start. `update` replaces the program with the latest release, checked against `SHA256SUMS`, or with `--from <file>`, and puts the old one back when the new one does not start. `uninstall` removes the service, the user and the program; `--purge` also the folders ([#123](https://github.com/Piggidragon/Nerve-Protocol/issues/123)).
- The released node's `install` and `uninstall` no longer fail on the control socket, or on a link, in its state folder: the static Linux programs opened such an entry instead of only giving it to the node's user.

### Capability providers

- A program on the machine that the owner names in `providers.allowed`, such as a desktop app, can attach to the node's control socket and add capabilities of its own. The node lists them to every center with `provider: <name>`, decides and audits every call to them by that center's policy, forwards only the allowed ones, and drops them when the program exits. Linux only for now; the conformance suite has a provider part ([#16](https://github.com/Piggidragon/Nerve-Protocol/issues/16)).
- In `folder` mode an action that names no path, which is what a provider adds, runs only where the owner set it `on`.
- A center with the settings grant can no longer allow, or turn on, a capability or an action the node does not offer now: it may sense once a provider offers it, so only the owner does that.
- A 0.0.3 node refuses a `node.toml` that holds `providers`. Before you go back to 0.0.3, remove it with `nerve-node config unset providers`.

### Run-time limit for commands

- Every command has a time limit now. A call without `timeout_ms` gets `limits.default_timeout_secs` (10 minutes), and a `timeout_ms` above `limits.max_timeout_secs` (1 hour) is cut to it. A command past its limit is killed and the call fails with `timeout`, as before; the message says which limit it was. Before, a command without `timeout_ms` ran until it ended or its session did. The agent sees both numbers in the description of `exec_run` and in its `timeout_ms` parameter, and machines with other limits are separate tools. Only the owner sets them, for example `nerve-node config set limits.max_timeout_secs 86400` for jobs that run a day; a center cannot, also with the settings grant ([#120](https://github.com/Piggidragon/Nerve-Protocol/issues/120)).
- A 0.0.3 node refuses a `node.toml` that holds either key. Before you go back to 0.0.3, remove them with `nerve-node config unset limits.default_timeout_secs` and `limits.max_timeout_secs`. A file in which you set neither reads on 0.0.3, as the defaults are not written.

### Key rotation

- A machine's key for a center, and the center's own TLS key, can be replaced without pairing again ([#121](https://github.com/Piggidragon/Nerve-Protocol/issues/121)). `nerve-node center rotate-key` sends the machine's new key to the center over the link, signed with the old one; in the center's web UI, Settings, **Rotate key** makes a new center key that the linked machines learn, signed with the old one. The old key stays valid for 7 days, or until its owner ends that (`--end-grace`, **Serve the new key now**). The machine keeps its id. Each rotation is in the node's audit log and the center's log.
- The protocol gets additive features (`hello.features`, `welcome.features`, spec §1.1) and the feature `rotate` (spec §4.10). A node or center older than 0.0.4 keeps working with a newer one, but cannot rotate; a node older than 0.0.4 has to pair again after its center's key was rotated.
- A 0.0.3 node refuses a `node.toml` that holds `public_key` or `key_rotations` under a pairing, which a rotation of the machine's key writes, and cannot use the rotated key anyway: such a pairing has to be paired again on 0.0.3.
- A 0.0.3 node refuses a `node.toml` that holds `pin_rotations` or `old_pin` under a pairing. A rotation of the center's key writes both (`old_pin` for up to 7 days; the running node drops it once that time is over), and so does setting a center's pin by hand with `config set center.<name>.pin`, which writes `pin_rotations`. Such a pairing works on 0.0.3 with the new pin once the center serves its new key (after its 7 days, or **Serve the new key now**); until then 0.0.3 cannot link with it. So go back only after that, and before you do, remove them with `nerve-node config unset center.<name>.pin_rotations` and `nerve-node config unset center.<name>.old_pin`.

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
