# Pair a machine

Pairing links a machine to a center. Do it once per machine and center.

## Steps

1. Open the center's web UI (`http://127.0.0.1:7480`). On Overview, press
   **Pair a machine**. It shows a command, the center's address, a code and a
   certificate pin.
2. On the machine, as a normal user, run the command it shows:

   ```sh
   nerve-node center add 'nerve://pair?center=https%3A%2F%2Flab.example%3A7443&code=k3v7x9q2m1ab&pin=...'
   ```

   Keep the quotes. The link has `&` in it.

   The node shows the center's address and what the center may do at first,
   then asks you to confirm. Nothing is stored before you say yes.

3. Start the node. It stays in the foreground, so run later commands in
   another shell:

   ```sh
   nerve-node run
   ```

4. Check the link:

   ```sh
   nerve-node status
   ```

   The machine shows as online in the web UI.

The new pairing starts closed: mode `allowlist`, no rule, and the center may
not change settings. Every call is refused until you allow something
([modes](modes.md), [rules](rules.md)).

## The code

- It is valid for 10 minutes and for one machine. Change the time in Settings,
  Center (1 to 1440 minutes).
- It allows 10 tries in all. After that make a new one.
- A wrong code counts against every open code.

## Options of `center add`

| Option | Does |
|---|---|
| `--name <name>` | The name you use for this center on the machine. Default: the center's own name. Letters, digits, `-` and `_` |
| `--yes` | Skip the question |

## Machine names

A machine's name comes from its host name. It has 1 to 32 characters of `a-z`,
`0-9` and `-`. To choose it, run `nerve-node config set node.name <name>`
before `center add`. Later, the web UI can rename a machine (Rename). That name
stays in the center.

## Several centers

A node can pair with any number of centers. Each one is separate: its own key,
rules, folders and audit entries. A center cannot tell whether other centers
exist.

Every command that works on one center takes `--center <name>`. With more than
one center the command refuses to guess:

```sh
nerve-node mode set folder --center lab
nerve-node center ls
```

## Unpair

| From | How | Effect |
|---|---|---|
| The machine | `nerve-node center rm --center lab` | Tells the center if the link is up, forgets the center and deletes its key |
| The center | Overview, **Remove** on the machine | Ends the link. The node stops dialling that center and shows it as `revoked` until you run `center rm` |

To pair again, remove the old pairing on both sides, then make a new link.

## Drops

The node dials the center. When a link drops, running commands on it end. The
node dials again: it waits 1 second, then doubles the wait up to 60 seconds.

A machine whose key was copied to another machine is caught: a center keeps
one live link per machine. If a second link arrives while the first still
answers, the center refuses it and shows an alert.

## Keep it running

`nerve-node run` runs in the foreground. The node has no built-in service
install: `install`, `setup`, `update` and `uninstall` only say that they are
not done. Run `nerve-node run` under your own service manager.
