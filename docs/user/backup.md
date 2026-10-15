# Back up, restore and move

`nerve-node backup` and `nerve-center backup` write what a machine would lose
to one file, protected with a passphrase. `restore` puts it back: on the same
machine after a mishap, or on another one when you move the node or the
center.

The file holds private keys. It is encrypted, so it can lie on a stick or in a
cloud folder, but only as safely as its passphrase. A passphrase has at least
12 characters. Nobody, you included, can open the file without it.

## The node

```sh
nerve-node backup ~/nerve-node.bak
```

It asks for the passphrase twice. The file is private to you (mode 0600; on
Windows it gets the permissions of its folder). It refuses to replace a file
that exists; `--overwrite` does.

| In the backup | Not in it |
|---|---|
| `node.toml` as the node reads it: pairings with their `url`, `pin`, `center_id` and `node_id`, modes, folders, rules, relay and proxy settings | The key of the config's MAC: a node that restores makes its own |
| The node key of every center, the relay's TLS key, the password of an `https://` proxy (the keys in `keys/`) | The sudo password. It is not stored anywhere, so a node restores with `sudo` off. On Windows the restore also deletes `sudo.dpapi`, which holds that password only while the switch is on |
| The proxy's header values | The audit log, the [log](logs.md), the control socket |
| | On Windows, `sudo.dpapi` and `command-account.dpapi`: DPAPI ties them to the machine |

The node can run while you back it up.

| Option | Does |
|---|---|
| `--include-keyring` | Also take the keys that are in the system keyring ([below](#keys-in-the-keyring)) |
| `--overwrite` | Replace the file when it exists |
| `--passphrase-file <file>` | Read the passphrase from the first line of a file instead of asking. On Linux the file must not be readable by others; Windows does not check, so keep the file in a folder only you can read. Without a terminal, one line of stdin is the passphrase |

### Keys in the keyring

With `machine.secret_storage = "keyring"` the node keeps its keys in the system
keyring ([keys](config.md#where-the-node-keeps-its-keys)), and so does it keep
the header values of a proxy whatever that setting says. These leave the
keyring only if you agree:

```sh
nerve-node backup ~/nerve-node.bak --include-keyring
```

Without `--include-keyring` the backup holds the config and the keys that are
in files, and says which it left out. A node restored from such a backup has
pairings without keys (below).

### Restore

Stop the node first. A restore never goes under a running node: it refuses
when a node holds the folders (`keys.lock`), and holds the lock itself while
it works. On the [installed service](service.md) stop the service
(`sudo systemctl stop nerve-node`, on Windows `Stop-Service nerve-node`).

```sh
nerve-node restore ~/nerve-node.bak
nerve-node run
```

On a node that has config here already:

- **The same node** (it shares a pairing with the backup, or has none): the
  restore replaces `node.toml` and the keys. Keys of pairings the backup does
  not have are deleted, and the config goes back in time to the backup's: its
  version is set above everything this node had saved, so the node does not
  take it for an older file put back
  ([an older file put back](config.md#an-older-file-put-back)).
- **Another node**, or a `node.toml` here that the node cannot read: the
  restore refuses. `--replace` says you mean it.

| Option | Does |
|---|---|
| `--replace` | Restore over a node that is not the one the backup is of |
| `--secret-storage file\|keyring` | Keep the keys here in files or in the keyring, whatever the backup's config says. Needed when the backup was made on a machine with a keyring and this one has none |
| `--passphrase-file <file>` | Read the passphrase from the first line of a file instead of asking. On Linux the file must not be readable by others; Windows does not check |

If the backup has no key for a pairing, `restore` says so and names the
pairing. When this machine still holds a key that fits the pairing, in the
files or in the keyring (a restore on the same machine), it stays, and it
goes where the restored node keeps its keys: a restore with `--secret-storage`
takes it over from the other place before that place is emptied. Otherwise
that center cannot connect: run `nerve-node center rm --center <name>`, then
`nerve-node center add` with a new link. The relay's TLS key and the proxy's
password are treated the same way, and `restore` says when one is missing
(the proxy's header values, which are in the keyring, are never moved).

A restore that fails half way puts the keys back as they were and writes
nothing. If the machine dies in the middle of it, run it again.

Restore only a backup you made yourself. It is the whole `node.toml`, with
everything the file can set: the programs allowed to attach as providers, the
`sudo` program, the account commands run as, the folders and rules of every
center. The passphrase proves that whoever made the file knew it, not that the
file is yours.

## The center

```sh
nerve-center backup ~/nerve-center.bak
nerve-center restore ~/nerve-center.bak
```

The backup holds `tls.pem` (the center's certificate and private key) and
`state.json` (its id and name, the paired nodes with their public keys, the
hashes of the harness tokens, the statistics). Not the [log](logs.md).

Back up while it runs; the statistics may be a few seconds behind. Restore
only when no center runs on the state folder (`--state-dir`): stop the harness
that started it. Both take `--state-dir`, `--overwrite` (backup) or
`--replace` (restore), and `--passphrase-file` like the node's.

A center that has another id than the backup is refused without `--replace`:
replacing it means every node paired with it must pair again.

## What a restore does to the pins

A pin is the hash of a certificate's public key. Nodes hold the pin of their
center, a relayed node holds the pin of its relay, and a node behind an
`https://` proxy holds the proxy's.

- **A restored node keeps every pin in its `node.toml`** exactly as saved. It
  does not learn them again. It also keeps the node key of each center, so the
  center knows it by the same node id and needs no pairing: the pairing is
  what the node had at the time of the backup.
- **A restored center brings back its certificate**, so the pin that its nodes
  hold fits again. This is what saves the pairing when `tls.pem` was lost and
  the center made a new certificate (all its nodes refuse a center with a new
  pin).
- **A restored relay keeps its TLS key**, so the nodes that use it still fit
  its pin. If the relay's key is not in the backup (it was in the keyring and
  you left it there), the relay does not listen until `nerve-node relay set
  <address>` makes a new key and pin, and every node behind it needs the new
  pin (`proxy set --pin`).
- **A pairing that ended after the backup does not come back.** If you ran
  `center rm` on the node, or removed the node in the center, the other side
  forgot the key. The restored node dials with it and is told the center does
  not know it; pair it again.
- **Do not run the old node and the restored one together.** They have the
  same key, and a center keeps one live link per node: the second one is
  refused with an alert.

## Moving

**A node to another machine.**

1. On the old machine: `nerve-node backup file` (with `--include-keyring` if
   the keys are in the keyring), then stop the node.
2. Copy the file, install `nerve-node` on the new machine
   ([install](install.md)), and `nerve-node restore file`.
3. Check what belongs to the machine and not to the node: the folders in
   `center.<name>.policy.folders`, the account commands run as
   (`machine.user`), the paths of providers, and the address of the relay.
   `nerve-node config get` shows each.
4. `nerve-node sudo on` if you used the sudo switch, then `nerve-node run`.

The centers see the same node id from a new address. Their link rule keeps one
live link per node, so stop the old node before the new one connects.

**A center to another machine.**

1. `nerve-center backup file` on the old machine, stop it.
2. `nerve-center restore file` on the new machine, with `--state-dir` if you
   use one.
3. Start it with the `--public-url` the nodes can reach. If the nodes reach
   the center under another address than before, change it on each node:
   `nerve-node config set center.<name>.url 'https://new.example:7443'`. The
   pin stays, so no node pairs again.

## On a node installed as a service

The command runs as the user `nerve` after `sudo` (see [service](service.md)),
so it writes and reads the backup, and the file `--passphrase-file` names, as
`nerve`. Name a backup in a folder `nerve` can use, such as
`/var/lib/nerve/state/nerve.bak`, and copy it from there as root. Typing the
passphrase needs no file.

## Messages

| Message | Cause |
|---|---|
| `cannot open the backup: the passphrase is wrong, or the file was changed` | The two cannot be told apart |
| `a nerve-node runs on these folders` | Stop the node, then restore |
| `a nerve-center runs on …` | Stop the center, then restore |
| `… are not the same node` or `… not the same center` | The backup is of another one. `--replace` if you mean it |
| `… is the backup of a center, not of a node` | Use the other program's `restore` |
| `… made by a newer program` | Update this program first |
