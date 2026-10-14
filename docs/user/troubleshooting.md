# Troubleshooting

Start with `nerve-node status`, `nerve-node center ls` and
`nerve-node audit --denied` on the machine. The refusal in the audit log is
the same text the agent saw.

For a link that drops, a pairing that fails or an error, open the center's
[log](logs.md), in the web UI under **Log** or in `log.jsonl`, and the node's
`log.jsonl` on the machine. Raise the level to `debug` for more.

## A call is refused

The agent sees `error forbidden: …` or `error disabled: …`. Every refusal
names its reason.

| Message | Cause | Fix |
|---|---|---|
| `no allow rule matches …` | `allowlist` mode and no rule covers it | [Add a rule](rules.md) or choose a [mode](modes.md) |
| `… chains commands or holds an expression …` | A wildcard rule does not cover commands with `;`, `&`, `\|`, `$`, quotes and the like | Add an exact rule for the whole line, or use `folder` mode |
| `outside the folders that allow reading` or `… writing` | `folder` mode, and no folder grants `r` or `w` there | `nerve-node folder add <path> +r +w` |
| `the working directory is not in a folder that allows running` | `folder` mode, and no folder with `x` holds the working directory | `nerve-node folder set <path> +x` |
| `commands cannot be confined on this machine` | `folder` mode on a machine without Landlock, or on the installed Windows service | Use `allowlist` or `user` mode. See [platforms](platforms.md) |
| `commands cannot be confined on this machine while the node's keys are in the system keyring: …` | `folder` mode with `machine.secret_storage = "keyring"`, where a command could reach the keyring: Linux below Landlock ABI 9 with commands running as root or as the node's own user, and the Windows node you run yourself. The node logs `folder mode runs no command: …` and `status` says so | `nerve-node config set machine.secret_storage file`, as the message says. See [keys](config.md#where-the-node-keeps-its-keys) |
| `... keeps a grant for this center's commands that its folders no longer give` | Windows: the node could not take a removed folder's grant off, or a granted folder was moved or renamed and the node could not take its entry off where it is now (the message names its old path) | Check that you may change that folder's permissions. For a moved or renamed folder, the node's log names the reason, often hard links: see the row on hard links below (a built Rust project needs `cargo clean`). The node tries again before each command |
| `the node cannot tell which folders carry grants for the commands` | Windows: the record of the folder grants (`grants.json` in the state folder) cannot be read, so no `folder` command runs | See the reason. If the file is damaged: `icacls <folder>` lists a folder's grants as `S-1-15-2-…` entries, `icacls <folder> /remove *S-1-15-2-…` takes one off. Once none is left, delete the file |
| `the node puts no grant on it, since …` | Windows: a folder granted inside another folder with `w` is now a junction or link to elsewhere, a file with a second name, or has permissions that do not inherit ([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)) | Put a plain folder there again (remove the junction; `icacls <path> /reset` makes its permissions inherit), or take the folder off the pairing. The node grants it at its next sync |
| `folder … left out of the command's sandbox: it was added at its own place and its path leads to … now` | The folder was added with `folder add`, and a link or junction now stands in its path (a command with `w` on the folder above may have put it there). The node keeps the folder out until the path leads to the place you added again ([modes](modes.md#a-folder-keeps-the-place-you-added)) | Look at the link (`ls -l`, `dir /AL`). If you did not mean it, remove it. If the new place is the one you want, `nerve-node folder rm <path>` (the path `folder ls` shows; the one you gave to `folder add` too, except on the installed node when it went through a link) and `folder add` the place the path leads to now |
| `the node does not change the permissions of …, since … below it has … names (hard links)`, or `… below it has … names (hard links), and the change would reach them all; it stopped there` | Windows: a file below a folder the commands may write in has a second name, and the change of the folder's permissions would reach it under every name ([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)) | `fsutil hardlink list <file>` shows its names. Links between names in `target` folders of the same folder, under the same grants, pass where no pairing has `w` without `r` on that folder or one above or inside it, except in a sync after a granted folder was moved or renamed: a built Rust project you renamed or moved needs `cargo clean` first. Others do not pass. Build tools make such links: pnpm's `node_modules` to its store, uv's `.venv` to its cache, a local `git clone`. Remove them (delete `node_modules` or `.venv`) or keep them out of the folder (pnpm `package-import-method=copy`, `UV_LINK_MODE=copy`, `git clone --no-hardlinks`) ([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)). A refused removal stops the pairing's commands until then. The node tries again before each command |
| `the config is saved, but the folder grants do not follow it` | Windows: a folder's permissions could not be changed | See the reason. The node tries again when it starts and before each command |
| `… is protected (…)` | The path is [protected](protected-paths.md) | Grant a folder at it, with the right it needs |
| `… is denied (…)` | A deny rule matches | `nerve-node rule rm deny …` |
| `… belongs to the node itself; no rule or mode reaches it` | The call touched the node's config or state folder | Nothing opens these |
| `sudo is off on this node` | A `sudo` command, and the switch is off | [Turn sudo on](sudo.md) |
| `a sudo command runs only when the sudo allow list names it` | The sudo list lacks it | `nerve-node rule add sudo '<command>'` |
| `a wildcard sudo entry does not cover a line with …` | A wildcard sudo entry covers no expression character (`@ { } % ' " # , \`), no invisible character (named as `U+…`) and no word that starts another command, such as `start`, `sh` or `powershell` | `nerve-node rule add sudo` with the whole line, without `--wildcard`. Quote the line for your shell: `"sudo choco install 'abc'"` keeps its `'` |
| `disabled: exec.run is off` | `cap set` switched it off or hid it | `nerve-node cap set exec.run on` |
| `the command line is … bytes, longer than …` | A command over 64 KiB | Use a shorter command |
| `unavailable` | The machine is offline | Check the link, below |
| `connection_lost` | The link dropped during the call | Run it again |
| `busy` | Too many commands or calls at once (`limits.max_running`, 16 by default) | Wait, or raise the limit |

The agent sees only the tools a machine could allow. If it sees only `nodes`,
nothing is allowed yet.

## Pairing fails

| Message | Cause | Fix |
|---|---|---|
| `the pairing code is unknown, used, expired or out of tries` | Wrong, old or used code | Make a new link in the web UI |
| `another node already has this name` | Two machines have the same name | `nerve-node config set node.name <other>`, then pair again |
| `this center is paired already as …` | The machine already has a pairing with this center | Use it, or `nerve-node center rm` it first |
| `a center named … is paired already` | You already use this local name | Pass `--name <other>` |
| A link or TLS error | The address in the link does not reach the center, or the center's certificate changed | Check `--public-url` and the port. Make a new link |

## The link is down

`nerve-node center ls` shows flags:

| Flag | Meaning | Fix |
|---|---|---|
| `[paused]` | You or the center paused the link | `nerve-node center resume` |
| `[revoked]` | The center removed this machine | `nerve-node center rm`, then pair again |
| `[unknown]` | The center does not know this machine any more | `nerve-node center rm`, then pair again |

Without a flag, the node is dialling. The wait grows from 1 to 60 seconds. If
`nerve-node status` says `LOCKED (panic)`, run `nerve-node unlock`.

Through a [relay](relay.md), `status` names what the relay answered:

| Message | Cause | Fix |
|---|---|---|
| `the proxy refused the tunnel to …: 400 …` | The node speaks plain HTTP to the relay, which speaks TLS only | `proxy set 'https://…' --pin <pin>`, the line `relay add` showed |
| `TLS with the proxy …: its certificate does not carry the pinned key` | The pin in `proxy set` is not the relay's, or the relay made a new certificate | On the relay, `nerve-node relay ls` shows the pin |
| `the proxy refused the tunnel to …: 407 …` | The relay does not know the name and token in `proxy set` | On the relay, `nerve-node relay ls`; make a new token with `relay rm` and `relay add` |
| `the proxy refused the tunnel to …: 403 …` | The center's address is not one the relay is paired with over https, or not one the relay's owner picked for this node | Pair with the URL the relay uses for that center; on the relay, `relay ls` shows the node's centers |
| `the proxy refused the tunnel to …: 503 …` | The relay is off, locked, or carries as many tunnels as it may | On the relay, `nerve-node relay ls` and `status` |
| `the proxy refused the tunnel to …: 502 …` | The relay cannot reach the center | Check the relay's own link |

If `status` says `daemon: not running`, start `nerve-node run`. On Windows
`status` does not ask the node yet: it says `daemon: not known (no control
socket on Windows); a change takes effect at the next start of the node`
whether the node runs or not, so look at the service (`Get-Service nerve-node`)
or the [log](logs.md) instead. (Folder changes do reach a running node at once,
over the [control pipe](platforms.md#the-control-pipe).) On a node
[installed as a service](service.md), start the service instead:
`sudo systemctl start nerve-node`, on Windows `Start-Service nerve-node`. A
node started there by hand lacks the privileges the service has, so it
cannot switch to the account commands run as and runs no command at all.

## The node will not start

| Message | Fix |
|---|---|
| `refusing to run as root; set machine.allow_root = true to allow it` | Run as a normal user (on Windows: not elevated), or set `machine.allow_root` |
| `node.toml is refused: its MAC does not match …` | Look at the file, then `nerve-node config accept`. See [config](config.md) |
| `machine.secret_storage is "keyring", but the system keyring cannot be reached …` | The keys are in a keyring that does not answer. Start it, or run `nerve-node setup`, which offers to install one on a Linux without a desktop. See [keys](config.md#where-the-node-keeps-its-keys) |
| `… this running node found no keyring and does not look again until it is restarted …` | The node asked for a keyring before one answered. Restart the node, then change the setting again. `setup` restarts the installed node itself after it installed a keyring |
| `… keeps the node's keys in the system keyring (machine.secret_storage = "keyring"), but … So the node does not start` (also from `install`) | The keys may not be in the keyring here: the installed node on Windows, or a Linux kernel with a Landlock ABI below 9. Run the `config set machine.secret_storage file` command the message names, as it says, then start the node. See [Windows](service.md#windows) and [keys](config.md#an-older-linux-kernel) |
| `machine.secret_storage cannot be "keyring" here: …` (from `config set`) | The same reasons. Keep the keys in files |

A node installed as a service says why in its [log](logs.md):
`journalctl -u nerve-node` on Linux. On Windows the Event Viewer has an error
from the source `nerve-node` under **Windows Logs > Application**, and
`C:\ProgramData\Nerve\state\log.jsonl` has the rest
([Windows Event Log](logs.md#the-windows-event-log)).

## The center will not start

| Message | Cause | Fix |
|---|---|---|
| `another nerve-center already runs the center in …` | Another center uses this state folder, and this one is not `--mcp stdio` | Use another `--state-dir`, or stop the other center |
| `the web UI at … is beyond loopback and logs in with a harness token, but there is none` | `--ui` is not on loopback | Set `--harness-token`, or use `--ui 127.0.0.1:7480` |
| `… always needs a login; drop --ui-no-login …` | `--ui-no-login` with a UI beyond loopback | Drop `--ui-no-login` |
| The MCP endpoint refuses every client | No harness token yet | Set `--harness-token`, or make one in the web UI |

## Output is cut

A command returns at most 1 MiB of stdout and 1 MiB of stderr. The result has
`truncated: true`. A file read returns at most 2 MiB. A write takes at most
3 MiB.

## The CLI refuses a change

These come from `nerve-node` commands that talk to the running node, not from an
agent's call.

| Message | Cause | Fix |
|---|---|---|
| `refused: this request comes from a command the node runs for a center` | The request came from below a command the node started for a center, for example from a command that ran `nerve-node` itself. The node refuses every request from there, the reading ones too | Run the command in your own terminal, not through an agent |
| `refused: this request does not carry the control socket's token …` | Linux: the request has no token: the `nerve-node` is the 0.0.2 one, or the CLI cannot read `run/ctl.token` in the node's state folder (it runs as an account that may not) | Run the 0.0.3 program, as the account that owns the node's state (the node's own user for the [installed node](service.md)). See [platforms](platforms.md) |
| `<path>: … A command may have put a link there: look at it …` | `folder add` refused the path: it crosses a link inside a folder with `w`, a link to nothing,, a place that changed while it was looked at, or a path that is not absolute (on Windows, not on a drive). The text before the link advice says which | Look at the link (`ls -l`, `dir /AL`), add the place you mean by its own path, or remove the link ([modes](modes.md#a-folder-keeps-the-place-you-added)) |
| `<path> is not a folder of this center; this account cannot look into it, so if it is a link, use the path … folder ls shows for the folder` | `folder rm` or `folder set` was given a path the CLI cannot look into (the installed node's CLI and your home), and the folder was stored where a link led | Give the path `nerve-node folder ls` shows; the message names the folders that could be it |
| `note: … is stored as given and not recorded …` (from `folder add`, not an error) | The folder was stored, but neither the CLI nor a running node could tell where its path leads, so the place is not recorded | Start the node and `folder add` the folder again ([modes](modes.md#a-folder-keeps-the-place-you-added)) |
| `the node does not take connections now; try again` | Linux: the node runs, but its control socket is busy or its queue is full | Try again. For `panic` see [stop](stop.md) |
| `the node did not answer in time; try again` | Linux: the node took the connection and did not answer it within 90 seconds | Try again; if it keeps failing, look in the node's [log](logs.md) |

## A change did not apply

If a command says `takes effect at the next start of the node`, no node was
running to take it. Start `nerve-node run`. On Windows a running node takes
only folder changes at once; every other change it takes at its next start.

### Restart the node, then change the folder again (Windows)

`folder add`, `set` or `rm` says `node.toml holds changes the running node
takes at its next start`: an earlier command changed something else, which
waits in the file for the next start. The node saves its whole config with a
folder change and would undo that change, so it refuses. Restart the node
(`Restart-Service nerve-node` for the installed node) and run the folder
command again.

### The control pipe is not the node's (Windows)

`folder add`, `set` or `rm` says `the control pipe is not the node's`: another
process made a pipe of the node's name before the node started, and the node
runs without its pipe (its log says `the control pipe … is taken`). The CLI
sends that pipe nothing. Find the process with Sysinternals
`handle.exe -a nerve-node-`, end it, and restart the node. With the node
stopped, folder changes go to `node.toml` as every other change does.
