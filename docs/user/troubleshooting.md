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
| `commands cannot be confined on this machine` | `folder` mode on a machine without Landlock, or on Windows | Use `allowlist` or `user` mode. See [platforms](platforms.md) |
| `… is protected (…)` | The path is [protected](protected-paths.md) | Grant a folder at it, with the right it needs |
| `… is denied (…)` | A deny rule matches | `nerve-node rule rm deny …` |
| `… belongs to the node itself; no rule or mode reaches it` | The call touched the node's config or state folder | Nothing opens these |
| `sudo is off on this node` | A `sudo` command, and the switch is off | [Turn sudo on](sudo.md) |
| `a sudo command runs only when the sudo allow list names it` | The sudo list lacks it | `nerve-node rule add sudo '<command>'` |
| `a wildcard sudo entry does not cover a line with …` | A wildcard sudo entry covers no expression character (`@ { } % ' " # , \`) and no word that starts another command, such as `start`, `sh` or `powershell` | `nerve-node rule add sudo '<whole line>'`, without `--wildcard` |
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

If `status` says `daemon: not running`, start `nerve-node run`. On a node
[installed as a service](service.md), start the service instead:
`sudo systemctl start nerve-node`, on Windows `Start-Service nerve-node`. A
node started there by hand lacks the privileges the service has, so it
cannot switch to the account commands run as and runs no command at all.

## The node will not start

| Message | Fix |
|---|---|
| `refusing to run as root; set machine.allow_root = true to allow it` | Run as a normal user (on Windows: not elevated), or set `machine.allow_root` |
| `node.toml is refused: its MAC does not match …` | Look at the file, then `nerve-node config accept`. See [config](config.md) |

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

## A change did not apply

If a command says `takes effect at the next start of the node`, no node was
running to take it. Start `nerve-node run`. On Windows a running node always
takes changes at its next start.
