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
- On a reload the old config stays. A reload also refuses a signed file that
  is older than the one in force.

The owner looks at the file, then runs `nerve-node config accept`. The node
signs it. A file from before the node kept a MAC (no key, no MAC line) is taken
once and signed.

The check holds while `config.key` does. A process that can read or delete it
can make the node take another file at its next start. A `user` mode command is
such a process, because it runs as the user without a sandbox. In `folder`
mode, Landlock keeps commands out of the state folder.

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
6. The proxy and its credentials.
7. The local audit log.
8. Releasing a protected path: a center may add to `protected.extra`, not
   remove from it or change `protected.allow`, and its folders may not widen
   access at a protected place ([policy engine](policy-engine.md#protected-paths)).
9. Turning a `sense` action on. A center can switch these off, never on.

Because the grant lets a center widen its rules up to `user` mode, a center
with the grant is as strong as `user` mode on that machine.

## The node's own folders

On Linux the config and state folders are the node's own. No call of a center
reaches them, whatever its rules, folders or released paths say. A confined
command's Landlock rules leave them out, even when a granted folder holds them.

## Control socket

`<state>/run/ctl.sock`, in a 0700 folder, mode 0600. Only its own user or root
may talk to it. It is the node's only way in besides its center links. The
client sends one JSON object per line, `{"method", "params"}`, and gets
`{"ok": value}` or `{"error": "text"}`. A streaming method answers with several
`{"item": value}` lines.

| Method | Does |
|---|---|
| `status` | Daemon and links |
| `config.read` | Read `node.toml` and its `version` |
| `config.write` | Replace it when `if_version` matches |
| `config.accept` | Take a refused `node.toml` as it is |
| `reload` | Reread `node.toml` (only a file the node signed) |
| `sudo.status`, `sudo.on`, `sudo.off` | The sudo switch |
| `owner.check` | Nothing; the CLI asks it before `install`, `setup`, `update` and `uninstall` |

`config.write`, `config.accept`, `reload`, `sudo.on`, `sudo.off` and
`owner.check` are refused from a process that runs below a command the node
started for a center. On Linux an agent cannot change its own policy through
the socket, nor install, set up, update or remove the node.

Windows has no control socket and no sandbox. The CLI signs `node.toml` itself,
so a command the node runs for a center can change the policy. The change
applies at the next start.

## The log level

`log.level` (`error`, `warn`, `info`, `debug`; `info` unless set) is a machine
setting of the owner: it is not in the document a center reads or writes. The
daemon applies it within a second of any change ([logging](logging.md)).

## The audit log

`audit.jsonl` in the state folder holds one JSON line per event: settings
changes, calls allowed or forbidden, and what happened to the config file. It
holds targets, never file contents or output. See
[the user guide](../user/audit.md) for sizes and rotation. It is not the log: [logging](logging.md).
