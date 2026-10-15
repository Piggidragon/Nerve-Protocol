# Run the center

The harness starts `nerve-center` itself, like any MCP server. The center has
no subcommands. Every setting is a flag or an environment variable.

## Add it to the harness

```json
{
  "mcpServers": {
    "nerve": {
      "command": "nerve-center",
      "env": {
        "NERVE_NAME": "lab"
      }
    }
  }
}
```

The center then listens on:

| Port | For | Flag |
|---|---|---|
| 7443 | nodes | `--listen` |
| 7480 | the [web UI](web-ui.md), on this machine only | `--ui` |

Open `http://127.0.0.1:7480` to [pair a machine](pairing.md).

## Settings

| Flag | Variable | Default | Meaning |
|---|---|---|---|
| `--name` | `NERVE_NAME` | `nerve-center` | Name shown to nodes and in the web UI |
| `--state-dir` | `NERVE_STATE_DIR` | see [install](install.md#where-files-live) | Identity, paired machines, statistics |
| `--listen` | `NERVE_LISTEN` | `0.0.0.0:7443` | Where nodes connect |
| `--public-url` | `NERVE_PUBLIC_URL` | `https://<host name>:<port>` | The address written into pairing links |
| `--plain-loopback` | `NERVE_PLAIN_LOOPBACK` | off | Plain HTTP for nodes; only with a loopback `--listen` |
| `--ui` | `NERVE_UI` | `127.0.0.1:7480` | Web UI address, or `off` |
| `--ui-no-login` | `NERVE_UI_NO_LOGIN` | off | No login for the web UI; refused beyond loopback |
| `--mcp` | `NERVE_MCP` | `stdio` | `stdio`, `http` or `none` |
| `--mcp-listen` | `NERVE_MCP_LISTEN` | `127.0.0.1:7481` | Address of the HTTP MCP endpoint |
| `--harness-token` | `NERVE_HARNESS_TOKEN` | none | A [harness token](harness.md#tokens) |
| `--log` | `NERVE_LOG` | the level set in the web UI, `info` at first | `error`, `warn`, `info` or `debug`; wins over the stored level for this run. The [log](logs.md) goes to stderr and to `log.jsonl` |

`nerve-center --help` prints the same list.

Set `--public-url` when nodes reach the center under another name than its
host name, such as a DNS name or a forwarded port.

## TLS

Nodes connect over TLS. The center makes a self-signed certificate on its
first start. The pairing link carries the certificate's pin, so a node
trusts exactly that certificate.

The web UI and the HTTP MCP endpoint use plain HTTP on loopback. On any other
address they use TLS with the same certificate. `--plain-loopback` turns TLS
off for nodes too, but only for a loopback `--listen`.

## Rotate the key

In the web UI, Settings, **Center key**, press **Rotate key**. The center makes
a new key and shows its pin once. It tells every machine that is linked, and
every machine that links in the next 7 days, signed with the old key; each
machine then trusts the new key too. The center keeps serving the old key for
those 7 days, then switches to the new one. **Serve the new key now** switches
at once.

- A machine that does not link during the 7 days, or runs a `nerve-node` older
  than 0.0.4, does not learn the new key. After the switch it cannot connect
  and has to be [paired again](pairing.md).
- New pairing links carry the pin of the key the center serves.
- The switch also changes the certificate of the web UI and the HTTP MCP
  endpoint when they use TLS. A browser asks to trust it again.
- The center's [log](logs.md) says when the key was rotated and when the new
  one is served. The keys are `tls.pem` and, during the 7 days, `tls.next.pem`
  in the state folder.

## Run it without a harness

The default `--mcp stdio` ends when the harness closes its input. To keep a
center running on its own, pick another mode:

```sh
nerve-center --mcp http --harness-token "$TOKEN"   # MCP over HTTP
nerve-center --mcp none                            # nodes and web UI only
```

## One center per state folder

The first `nerve-center` on a state folder runs the center. A second one with
`--mcp stdio` finds it and attaches, so several harnesses on one machine share
one center, each with its own session. The first one keeps running until the
attached harnesses have ended too.

A second one with `--mcp http` or `--mcp none` refuses to start. On Windows a
second instance cannot attach and fails.

## What the center keeps

In the state folder:

| File | Holds |
|---|---|
| `tls.pem` | The center's key and certificate |
| `state.json` | Center id and name, paired machines with their public keys and last descriptions, hashed harness tokens, daily statistics |
| `log.jsonl` | The [log](logs.md): links, pairing, changes, refused and failed calls, errors. `log.jsonl.1` is the older half |

It never stores file contents, command output, arguments or secrets.
