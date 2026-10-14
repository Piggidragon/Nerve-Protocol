# Reach the center through another node

A machine in a closed network may reach no center, while another machine
that runs a node reaches both that network and the center. That node can be
the first one's **relay** (a jump node): the first node dials its center
through it.

```
 relayed node ── TLS to the relay, pinned ──> relay (jump node) ── TCP ──> center
             └──────────── TLS to the center, pinned, end to end ────────┘
```

The relay carries bytes only. The relayed node's link is TLS to the center,
checked against the center's pin, and signed with the relayed node's own key,
as without a relay. The relay can cut a node off, but it cannot read the link
or change it: a changed byte breaks the TLS link, and the center never gets a
message from it.

The way to the relay is TLS too, with a certificate of the relay's own that
the relayed node pins. So nobody on the network between the two sees the
relayed node's token or where it goes. The relay speaks nothing else: a
node that tries plain HTTP is told so and gets no tunnel.

What the relayed node allows is its own business: its rules, folders and
mode decide every call, as on any node. The relay's rules play no part, and
no call runs on the relay for a node it carries.

## On the relay

Turn the relay on and give the other node a token:

```sh
nerve-node relay set 0.0.0.0:7490
nerve-node relay add lab-pc
```

`relay set` makes the relay's certificate the first time and shows its pin.
`relay add` shows the token once, and the line to run on the other node:

```
relay node lab-pc added; its token, shown only now:
  0123456789abcdefghijklmnopqrstuvwxyz0123456
it may reach every https center of this node
on lab-pc, run:
  nerve-node proxy set 'https://lab-pc:0123…@<address of this machine>:7490' --pin q1Q3tvgE…
```

The relay keeps only a hash of the token in `node.toml`. If you lose the
token, take it away and make a new one: `nerve-node relay rm lab-pc`, then
`relay add lab-pc` again.

The certificate's key is kept with the node's own keys, where
`machine.secret_storage` says: a file in the config folder by default, or
the system keyring ([config](config.md)). `relay set` keeps the same
certificate when you change the address. If its key is lost, `relay set`
makes a new one and says so; the relayed nodes then need the new pin.

The relay is off until you turn it on. A center cannot turn it on, change
it or see it, settings grant or not.

## Limit a node to some centers

Without `--center`, a relayed node may reach every https center of the relay
(see [below](#where-a-tunnel-may-go)). To let it reach only some:

```sh
nerve-node relay add lab-pc --center home
nerve-node relay set-centers lab-pc --center home --center work
nerve-node relay set-centers lab-pc              # every center again
```

A tunnel to a center off the list is refused with the same answer as one to
a center the relay does not have, so the node learns nothing of the others.
`set-centers` ends the node's tunnels to a center it takes away. `relay ls`
shows each node's list.

## On the relayed node

Run the line `relay add` showed, with the relay's address in place of
`<address of this machine>`, then pair as usual:

```sh
nerve-node proxy set 'https://lab-pc:<token>@relay.example:7490' --pin <pin>
nerve-node center add 'nerve://pair?center=...&code=...&pin=...'
```

The pairing goes through the relay too. The center's URL in the pairing link
must be the one the relay is paired with, the same host name or address and
port, or the relay refuses the tunnel. The center must be reached over
`https`.

The token is kept with the node's own keys, where `machine.secret_storage`
says: a file in the config folder by default (only the node's user can read
it, as its center keys), or the system keyring. It moves with the other keys
when you change that setting. On a Linux machine without a desktop session
there is no Secret Service: with `machine.secret_storage = "keyring"`,
`proxy set` refuses with the keyring's error and changes nothing, as storing
any key of the node does, and a node whose keys are there does not start.
Keep the keys in files there (the default), or install a keyring
(`nerve-node setup` can). The node installed as a service on Windows keeps
its keys in files, so it can be a relayed node.

## Where a tunnel may go

The relay tunnels only to the centers it is paired with itself, over
`https`, and not to one that removed it (`bye revoked`) or no longer knows
it, and only to the ones on the node's list when it has one. Nothing else of
the relay's machine or network can be reached through it: no other port,
and no `http` center on its own loopback. An `https` center the relay is
paired with at `127.0.0.1`, `[::1]` or `localhost` (a center on the relay's
own machine) is reached. A center paired at a name is not reached on the
relay's own machine: if the name resolves to a loopback address there, the
tunnel is refused. A paused center is still reached: pausing stops the
relay's own link, not the links it carries.

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
20 seconds). At most 4 connections from one address may wait for the relay's
answer at once, so one machine cannot keep everyone else out.

## Who is connected

```sh
nerve-node relay ls
```

```
relay on 0.0.0.0:7490: listening on 0.0.0.0:7490
at most 16 tunnels, 4 per node
pin q1Q3tvgEmVkvsjsZTEOBtG9Rb12pM9iyCOVCTVwjz4A
node lab-pc: the centers home
tunnel lab-pc from 10.0.0.7:51544 to center home for 2 h 5 min
```

`nerve-node status` shows the relay in one line. Every tunnel is one entry
in the [audit log](audit.md) when it ends: the node, its address, the
center, when it started and ended, why it ended and how much it carried;
never a token. The node's [log](logs.md) also has a line for every tunnel
that opens or closes, and for each refusal of a node with its token.
Connections without a valid token are counted and told in one line a
minute.

## Cut a node off

Each of these ends the tunnels it concerns at once:

| Command | Ends |
|---|---|
| `nerve-node relay rm lab-pc` | The tunnels of `lab-pc`; its token no longer works |
| `nerve-node relay set-centers lab-pc --center work` | The tunnels of `lab-pc` to its other centers |
| `nerve-node center rm --center home` | The tunnels to `home` |
| `nerve-node relay off` | Every tunnel; the relay stops listening and keeps its nodes |
| `nerve-node panic` | Every tunnel, and the relay does not listen until `unlock` |

## On Windows

Windows has no control socket, so a `relay` change is in `node.toml` and
takes effect at the next start of the node (`Restart-Service nerve-node` for
the installed node). Until then the running node keeps the tunnels it
carries: `relay rm` and `relay off` say so, and you restart the node to cut
them now. `relay ls` asks the running node who is connected. Windows
Firewall must let other machines reach the relay's port.

## What to know

- The relay sees who connects, when, to which center and how much they
  send, but none of what they send.
- Whoever holds a token reaches only the relay's centers' node port (those
  on the node's list), where a node still needs a pairing of its own. Take a
  token away with `relay rm` if you think it leaked.
