# Settings and config

The node has one config file and one way to change it. Details:
[spec/node-local.md](spec/node-local.md) §1, §2, §5 and §6.

## One file, one store

- The node's config is `node.toml` in the config folder. It is the same
  structure as the settings document a center reads, minus the client-only
  items below. There is no second format.
- The center has no config file. Its settings are flags and variables, plus the
  web UI's settings stored in `state.json`.
- Every writer goes through the same settings store: the CLI, and a center with
  the settings grant (through the `settings` capability). No component writes
  the file on its own.
- A write takes the whole document and its `version`. A stale version is
  `conflict`. The store validates the document against the config rules, writes
  the file atomically, applies it at once and audits each changed setting with
  its old and new value and who changed it.
- While the daemon runs, the CLI changes settings through the control socket.
  Without a daemon, the CLI uses the same store on the file.
- The daemon keeps the config in memory. It reads the file at start-up and when
  the owner asks (`SIGHUP`, or `reload` on the socket). It never rereads it on
  a timer.

## The signature

Every file the node writes starts with `# mac hmac-sha256 <hex> …`, an HMAC
over the rest. The key is `config.key` in the state folder (mode 0600), or an
entry in the system keyring with `machine.secret_storage = "keyring"`
([spec §1](spec/node-local.md#where-the-keys-are)). It is
not beside `node.toml`, so whatever can read the config folder does not hold
the key.

A file with a missing or wrong MAC was changed outside the owner's path. The
node refuses it and audits that:

- At start-up the node does not start.
- On a reload the old config stays.

The owner looks at the file, then runs `nerve-node config accept`. The node
signs it. A file without a MAC line (and no key) is taken
once and signed.

A file the node signed earlier passes the MAC, so the MAC alone does not stop
someone who can write the config folder from putting an older one back. The
node keeps the highest version it has saved or taken in `config.version` in
the state folder, and refuses a signed file below it the same way: at
start-up it does not start, on a reload (which also refuses a file below the
one in force) the old config stays. `config accept` takes such a file under a
new version above every one before. Details:
[spec §1](spec/node-local.md#who-writes-nodetoml).

The check holds while `config.key` and `config.version` do. A process that can
read or delete the key can make the node take another file at its next start.
A `user` mode command is such a process, because it runs as the user without a
sandbox. In `folder` mode, Landlock keeps commands out of the state folder.

## Client-only items

A center never changes these, grant or not. They are not in any document a
center reads, or the node refuses the whole change and names the field.

1. Pairing and unpairing, the node keys, the list of centers.
2. The settings grant itself.
3. `panic` and `unlock`. A center with the grant may pause. Only the owner
   unpauses or unlocks.
4. Machine settings: `machine.shell`, `machine.allow_root`,
   `machine.sudo_path`, `machine.secret_storage`, `machine.user`.
5. The sudo password. The node never returns it. A center only passes it on,
   sealed, when it switches sudo on.
6. The proxy and its credentials, and the relay for other nodes with its
   tokens.
7. The local audit log.
8. Releasing a protected path: a center may add to `protected.extra`, not
   remove from it or change `protected.allow`, and its folders may not widen
   access at a protected place ([policy engine](policy-engine.md#protected-paths)).
9. Turning a `sense` action on, by `caps` or an allow rule, or by taking away
   an `off` or `hidden` entry or a deny rule that keeps it off; and doing so
   for a capability no attached provider offers now, or for an action an
   offered capability does not have now, which may sense once it comes. A
   center can switch these off, never on, so it cannot take away its own deny
   rule for such a capability either.
10. The programs that may attach as capability providers,
    `providers.allowed` ([node-local §7](spec/node-local.md#7-capability-providers)).

One item is in the document a center reads and is still the owner's: the
record of the folders' real places, `policy.places`
([policy engine](policy-engine.md#protected-paths)). The node does not refuse
a write that differs there; it keeps the record as it was. The center adds no
entry and changes none, and an entry goes only with its folder.

Because the grant lets a center widen its rules up to `user` mode, a center
with the grant is as strong as `user` mode on that machine.

## The node's own folders

On Linux the config and state folders are the node's own. No call of a center
reaches them, whatever its rules, folders or released paths say. A confined
command's Landlock rules leave them out, even when a granted folder holds them.

## Control socket

`<state>/run/ctl.sock`, in a 0700 folder, mode 0600. Only its own user or root
may talk to it, and only a request that carries the token the node wrote to
`<state>/run/ctl.token` at its start: the CLI reads it, a `folder` mode command
cannot, as the state folder is out of its rules. A request without the token
gets an answer only to `status`, and only `{"running": true}`. The token is as
safe as the sandbox: while the commands run as the node's own user, any other
program of that user that runs commands on request over a socket (the user's
systemd session, a tmux or screen server) runs them outside it, and reads the
token too. Only `machine.user` keeps that out, with an account that only the
node uses and that gets root in no way without a password: not root, not in
`docker`, `lxd`, `incus-admin`, `libvirt` or `disk`, no `NOPASSWD` sudo, and
nobody works as it and uses `sudo` or `su` from it, as a command can leave
`no_new_privs` and the sandbox through the account's own user manager or a
tmux server, and type into the panes of a person who works as the account
([the account commands run
as](../user/service.md#the-account-commands-run-as)). `install` takes the
account that ran `sudo`, which is none of these; `setup --create-user` makes
one. And not for a [sudo](../user/sudo.md) command, which runs as root
whatever the account.
A command without a sandbox (`allowlist`, `user`, sudo) reads the token as
well. It is the node's
only way in besides its center links. The client sends one JSON object per line,
`{"method", "params", "token"}`, and gets `{"ok": value}` or
`{"error": "text"}`. A streaming method answers with several `{"item": value}`
lines. Every connection carries one request, except a provider's, which stays
after `hello` and carries its calls.

| Method | Does |
|---|---|
| `status` | Daemon and links |
| `config.read` | Read `node.toml` and its `version` |
| `config.write` | Replace it when `if_version` matches |
| `config.accept` | Take a refused `node.toml` as it is |
| `reload` | Reread `node.toml` (only a file the node signed) |
| `sudo.status`, `sudo.on`, `sudo.off` | The sudo switch |
| `folder.add` | `folder add`, judged by the node as the account commands run as; it stores and records the real place |
| `owner.check` | Nothing; the CLI asks it before `install`, `setup`, `update` and `uninstall` |
| `hello` | A capability provider attaches; its connection stays ([node-local §7](spec/node-local.md#7-capability-providers)) |

Every method is refused from a process that runs below a command the node
started for a center, the reading ones too. That catches the processes that
stay below the command: one that leaves the tree (`( … & )`, `setsid -f`)
is not caught, so for a command without a sandbox the socket is no boundary,
as the node's files are none. For a `folder` mode command the token also
holds, as far as the sandbox does.

Windows has no control socket. It has a control pipe with the same lines,
which serves `status`, `folder.add`, `folder.set` and `folder.rm` only
([node-local.md §5](spec/node-local.md#5-control-socket)). For every other
change the CLI signs `node.toml` itself, and the change applies at the next
start.

## The log level

`log.level` (`error`, `warn`, `info`, `debug`; `info` unless set) is a machine
setting of the owner: it is not in the document a center reads or writes. The
daemon applies it within a second of any change ([logging](logging.md)).

## The audit log

`audit.jsonl` in the state folder holds one JSON line per event: settings
changes, calls allowed or forbidden, and what happened to the config file. It
holds targets, never file contents or output. See
[the user guide](../user/audit.md) for sizes and rotation. It is not the log: [logging](logging.md).
