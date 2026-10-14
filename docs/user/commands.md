# `nerve-node` commands

Run them as a normal user on the machine, or with `sudo` when the node is
[installed as a service](service.md) (on Windows, in a terminal opened with
"Run as administrator"). `nerve-node --help` and
`nerve-node <command> --help` list the same. The center's web UI has a Help
page with them too.

Every command takes `--config-dir` and `--state-dir`
([where files live](install.md#where-files-live)). A command that works on
one center takes `--center <name>`. You need it only when more than one
center is paired.

## Pair and connect

| Command | Does | Page |
|---|---|---|
| `center add '<link>' [--name N] [--yes]` | Pair with a center | [pairing](pairing.md) |
| `center rm` | Unpair and delete the key | [pairing](pairing.md#unpair) |
| `center ls` | List centers, their mode and grant | [pairing](pairing.md) |
| `center pause`, `center resume` | Stop or restart the link to a center | [stop](stop.md#pause) |
| `center grant settings write\|off` | Let a center change settings | [settings grant](settings-grant.md) |
| `proxy set <url> [--header 'N: v']`, `proxy ls`, `proxy rm` | Dial centers through a proxy | [proxy](proxy.md) |
| `relay set <ip:port>`, `relay off` | Let other nodes reach this node's centers through it | [relay](relay.md) |
| `relay add <name>`, `relay rm <name>`, `relay ls` | Give a node a relay token, take it away, see who is connected | [relay](relay.md) |

## What a center may do

| Command | Does | Page |
|---|---|---|
| `mode set allowlist\|folder\|user [--for HOURS]` | Choose the mode | [modes](modes.md) |
| `folder add <path> +r +w +x` | Grant a folder | [modes](modes.md#folders) |
| `folder set <path> -w` | Change a folder's rights | [modes](modes.md#folders) |
| `folder rm <path>`, `folder ls` | Remove or list folders | [modes](modes.md#folders) |
| `rule add allow\|deny\|sudo '<command>' [--wildcard]` | Add a command rule | [rules](rules.md) |
| `rule rm allow\|deny\|sudo '<command>' [--wildcard]` | Remove a command rule | [rules](rules.md#list-and-remove-rules) |
| `rule ls [allow\|deny\|sudo]` | List rules | [rules](rules.md#list-and-remove-rules) |
| `cap set <cap> on\|off\|hidden`, `cap ls` | Switch a capability or action | [rules](rules.md#switch-a-capability-off) |
| `sudo on`, `sudo off`, `sudo status` | The sudo switch | [sudo](sudo.md) |
| `config get\|set\|unset\|add\|remove <key> [value]` | Read or change any setting | [config](config.md) |
| `config accept` | Take a `node.toml` you edited by hand | [config](config.md#do-not-edit-the-file-by-hand) |

## Run and watch

| Command | Does | Page |
|---|---|---|
| `run` | Run the node in the foreground | [pairing](pairing.md) |
| `status` | Show whether it runs, the links and the confinement | [troubleshooting](troubleshooting.md) |
| `audit [--denied] [--follow]` | Show what was allowed and refused | [audit](audit.md) |
| `panic`, `unlock` | Stop everything, then allow it again | [stop](stop.md#panic) |

## Install and set up

| Command | Does | Page |
|---|---|---|
| `install` | Install the node as a service under its own user (Linux as root, Windows as administrator) | [service](service.md#install) |
| `setup` | Name the node, choose the account commands run as, choose where the keys are, pair the first center, choose its mode | [service](service.md#setup) |
| `setup --create-user <name>` | Make an account only the node uses, and run commands as it (Linux, installed node) | [service](service.md#setup) |
| `update [--from FILE]` | Put the latest release in place and restart the service | [service](service.md#update) |
| `uninstall [--purge]` | Remove the service, its user and the program | [service](service.md#uninstall) |
