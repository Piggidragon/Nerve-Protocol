# Capability providers

A program on the machine, such as a desktop app, can add capabilities of its
own to the node: a lamp it switches, a window it shows. It attaches to the
running node as a **provider**, and every center then sees its capabilities
next to `fs` and `exec`. The program never talks to a center. The node decides
every call to it by that center's mode and rules, as it does for files and
commands, and writes it to the [audit log](audit.md).

Providers work on Linux, with a node you run yourself. The installed node's
control socket belongs to the user `nerve`, so a program of yours cannot
attach there yet. Windows takes no provider yet.

## Allow a program

No program may attach until you name it, with a name of your choice and the
full path of its executable:

```sh
nerve-node config add providers.allowed '{ name = "desk", exe = "/usr/lib/nerve-desktop/nerve-desktop" }'
```

The node checks that the program that attaches under that name runs that very
file. A center cannot change the list. To let a program go, remove its entry:

```sh
nerve-node config remove providers.allowed '{ name = "desk", exe = "/usr/lib/nerve-desktop/nerve-desktop" }'
```

Its capabilities leave at once. `nerve-node status` lists the providers that
are attached:

```
provider desk attached: lamp
```

The check tells programs apart, not users: another program of your user can
still make the allowed one attach for it. Allow only programs you trust.

## Allow its capabilities

A provider's capability is decided like any other ([modes](modes.md),
[rules](rules.md)):

| Mode | A provider's action runs when |
|---|---|
| `allowlist` | an allow rule names it: `nerve-node config add center.<name>.policy.allow 'lamp.on'`, or `'lamp'` for all its actions |
| `folder` | you set it on: `nerve-node cap set lamp on` (it lies in no folder) |
| `user` | always, except one that senses or acts on the world, which needs `on` |

Deny rules and `off` and `hidden` work as for `fs` and `exec`. A center with
the [settings grant](settings-grant.md) can allow a provider's action itself
while the provider is attached, except one that senses (a camera, a
microphone): only you turn those on, and only you take away an `off` switch
or a deny rule that keeps one off. While no provider offers a capability
or one of its actions, only you can allow it or turn it on, as the node
cannot tell yet what it does. An entry a center wrote while the capability
did not sense stays when a new version of the program makes it sense: after
such an update, check `nerve-node rule ls allow` and `nerve-node cap ls`.

When the program exits, its capabilities leave the centers' tool lists, and a
call that was waiting for it fails with `unavailable`.

How a program attaches is in the
[spec](../dev/spec/node-local.md#7-capability-providers).
