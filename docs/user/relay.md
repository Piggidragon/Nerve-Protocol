# Reach the center through another node

A machine in a closed network may reach no center, while another machine
that runs a node reaches both that network and the center. That node can be
the first one's **relay** (a jump node): the first node dials its center
through it.

```
 relayed node ── CONNECT ──> relay (jump node) ── TCP ──> center
             └──────────── TLS, pinned, end to end ────────┘
```

The relay carries bytes only. The relayed node's link is TLS to the center,
checked against the center's pin, and signed with the relayed node's own key,
as without a relay. The relay can cut a node off, but it cannot read the link
or change it: a changed byte breaks the TLS link, and the center never gets a
message from it.

What the relayed node allows is its own business: its rules, folders and
mode decide every call, as on any node. The relay's rules play no part, and
no call runs on the relay for a node it carries.

## On the relay

Turn the relay on and give the other node a token:

```sh
nerve-node relay set 0.0.0.0:7490
nerve-node relay add lab-pc
```

`relay add` shows the token once, and the line to run on the other node:

```
relay node lab-pc added; its token, shown only now:
  0123456789abcdefghijklmnopqrstuvwxyz0123456
on lab-pc, run:
  nerve-node proxy set 'http://lab-pc:0123…@<address of this machine>:7490'
```

The relay keeps only a hash of the token in `node.toml`. If you lose the
token, take it away and make a new one: `nerve-node relay rm lab-pc`, then
`relay add lab-pc` again.

The relay is off until you turn it on. A center cannot turn it on, change
it or see it, settings grant or not.

## On the relayed node

Run the line `relay add` showed, with the relay's address in place of
`<address of this machine>`, then pair as usual:

```sh
nerve-node proxy set 'http://lab-pc:<token>@relay.example:7490'
nerve-node center add 'nerve://pair?center=...&code=...&pin=...'
```

The pairing goes through the relay too. The center's URL in the pairing link
must be the one the relay is paired with, the same host name or address and
port, or the relay refuses the tunnel. The center must be reached over
`https`.

The token is the proxy's password, so it goes into the system keyring like
every proxy password ([proxy](proxy.md#a-proxy-that-wants-a-login)). A Linux
machine without a desktop session has no Secret Service, and `proxy set` with
a password refuses there ([proxy](proxy.md#when-the-proxy-fails)). The node
installed as a service on Windows takes no proxy password, so it cannot be a
relayed node; it can be a relay.

## Where a tunnel may go

The relay tunnels only to the centers it is paired with itself, over
`https`, and not to one that removed it (`bye revoked`) or no longer knows
it. Nothing else of the relay's machine or network can be reached through
it: no other port, no center on its own loopback. A paused center is still
reached: pausing stops the relay's own link, not the links it carries.

If the relay itself reaches its centers through a proxy or another relay, it
dials through that one too. Each relay in such a chain follows the same
rules.

## Limits

```sh
nerve-node relay set 0.0.0.0:7490 --max-links 16 --max-links-per-node 4
```

`--max-links` is the number of tunnels at once over all relayed nodes, 16
unless you set it. `--max-links-per-node` is the number per node, 4 unless
you set it; a node needs one per center it is paired with. A tunnel that
carries nothing for 90 seconds is closed (a live link sends something every
20 seconds).

## Who is connected

```sh
nerve-node relay ls
```

```
relay on 0.0.0.0:7490: listening on 0.0.0.0:7490
at most 16 tunnels, 4 per node
node lab-pc
tunnel lab-pc from 10.0.0.7:51544 to center home for 2 h 5 min
```

`nerve-node status` shows the relay in one line. The node's [log](logs.md)
has a line for every tunnel that opens, closes or is refused, with the
node's name and address.

## Cut a node off

Each of these ends the tunnels it concerns at once:

| Command | Ends |
|---|---|
| `nerve-node relay rm lab-pc` | The tunnels of `lab-pc`; its token no longer works |
| `nerve-node center rm --center home` | The tunnels to `home` |
| `nerve-node relay off` | Every tunnel; the relay stops listening and keeps its nodes |
| `nerve-node panic` | Every tunnel, and the relay does not listen until `unlock` |

## On Windows

Windows has no control socket, so a `relay` change is in `node.toml` and
takes effect at the next start of the node (`Restart-Service nerve-node` for
the installed node). `relay ls` shows the relay's settings but not who is
connected; that is in the node's log. Windows Firewall must let other
machines reach the relay's port.

## What to know

- The token travels in the `CONNECT` request in plain HTTP between the
  relayed node and the relay, so whoever can read that network can read it.
  With it they reach only the relay's centers' node port, where a node still
  needs a pairing of its own. Use the relay on a network you trust, and take
  a token away with `relay rm` if you think it leaked.
- The relay sees who connects, when, to which center and how much they
  send, but none of what they send.
