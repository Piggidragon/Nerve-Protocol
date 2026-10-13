# The policy engine

The node decides every call. The engine is `crates/nerve-policy/src/decide.rs`.
The exact rules are in [spec/node-local.md](spec/node-local.md) §2 to §4.
For how it looks to an owner, see the user guide ([modes](../user/modes.md),
[rules](../user/rules.md)).

## One policy per pairing

A pairing is a **center entry**. Its policy holds:

| Field | Meaning |
|---|---|
| `mode` | `allowlist` (default), `folder` or `user` |
| `until` | Optional end of `folder` or `user` mode. Then the entry is back in `allowlist` |
| `folders` | A path and `access`: three independent flags `r`, `w`, `x` |
| `caps` | `on`, `off` or `hidden`, per capability or action |
| `allow`, `deny` | Rules for every action |
| `sudo_allow` | Rules for `sudo` commands |
| `protected` | Extra protected paths, and the owner's releases |

The entry also holds the settings grant (`off` or `write`) and the `paused`
flag. The sudo switch and the limits belong to the machine, not to an entry.

## The answer

A decision is **allowed** or **forbidden**. There is no third outcome. A call
that no rule and no mode allows is refused at once. Nothing is held for a
person.

The refusal names what is missing, so the model can pass it on and the owner
can add the rule. Every decision, allowed or refused, goes to the audit log
with the center and the session. A center that subscribed gets it as an
`audit/decision` event.

## Order

A `locked` node (after `panic`) runs nothing. A paused, revoked or unknown
center is not dialled. For a call that arrives, the engine goes through these
steps in order.

| # | Step | Result |
|---|---|---|
| 1 | The command line is over 64 KiB | `forbidden` |
| 2 | The call touches the node's own folders: any path of an `fs` call, a working directory, a path a command line names plainly | `forbidden`. No rule, mode, folder or release lifts this |
| 3 | The capability or action is `off` or `hidden` | `disabled` |
| 4 | A `sudo` command and the sudo switch is off | `forbidden` |
| 5 | A deny rule matches | `forbidden`, in every mode |
| 6 | The mode decides. A `sudo` command: the sudo list. `allowlist`: an allow rule for every target. `folder`: the folders' flags. `user`: allowed | Allowed or `forbidden` |
| 7 | A protected path is touched | `forbidden`, whatever allowed the call |

The order only narrows. Step 6 is the only one that allows, and steps 1 to 5 and
7 can only refuse.

## Rules

A rule is `<scope>` or `<scope>:<pattern>`. The pattern is a glob over the
call's target: the whole command line, the resolved path, or `<cap>.<action>`.

- A rule matches the whole target. `exec.run:rm *` refuses `rm -rf x`. It does
  not see `rm` inside `git status; rm -rf x` or in `/bin/rm`.
- In `allowlist` mode a **wildcard** allow rule covers plain commands only.
  Commands run unconfined there, so a wildcard must not cover `git x; rm -rf ~`
  or PowerShell's `echo @{a=<command>}`. A line with shell control characters,
  expression characters or a word that starts another shell or runs text as
  code is covered only by an allow rule that names the whole line.
- A `sudo` command must be one simple command. Control characters are refused.
  A wildcard sudo entry covers plain lines only, as a wildcard allow rule
  does; any other line needs an entry that names it whole.

## Modes

- **`allowlist`.** Default deny. Only allow rules count.
- **`folder`.** The folders' flags decide. Reads need `r`, writes need `w`,
  commands need `x` on their working directory. The deepest folder that holds
  a path decides. Commands are confined where the platform can confine them.
- **`user`.** Everything the user could do, protected paths aside. Commands are
  not confined.

`folder` and `user` mode give full access in their area, and deny rules narrow
it. Allow rules are not looked at there.

## Protected paths

Protected paths apply to the file actions and to a command's working directory,
not to what a command reads. They hold keys, credentials, shell start-up files
and, per platform, system files that open the machine.

- A folder at or inside a protected entry releases it, for the access the call
  needs there: `r` for a read, `w` for a write, `x` for a command. This holds in
  every mode.
- A center may add to `protected.extra`. It may not remove from it, change
  `protected.allow`, or add a folder at or inside a protected entry that the
  owner's folders did not release already.
- Places are compared by path, not as text, so another spelling of the same
  place gives nothing. A folder that is, or passes through, a link into a
  protected entry is refused unless the owner's folders release the place it
  leads to.
- A folder that holds a protected entry gives a command none of it. Landlock
  cannot deny inside a rule, so the sandbox takes the folder's other entries,
  level by level, down to the protected one.
- A folder spelled so that it matches nothing (a `..` segment, and on Windows an
  8.3 short name or a name that ends in a dot or a space) is refused.

## The sandbox

On Linux, `folder` mode runs commands under Landlock:

| Access | Allowed |
|---|---|
| Read | The system folders and the `r` folders |
| Write | The `w` folders and a few devices (`/dev/null`) |
| Run programs | The system folders and the `x` folders |

Landlock restricts the process that applies it. Doing that between `fork` and
`exec` in the multi-threaded node is not safe. So the node starts a small
single-threaded shim per command, `nerve-node __exec-shim`, which applies the
rules and runs the command.

- Landlock cannot run a file it may not read. The rule of an `x` folder carries
  the right to read files by name, but not to list.
- The node's own folders are in none of the sets.
- A `sudo` command runs without Landlock, which would stop sudo from gaining
  privileges. Every other command runs with `no_new_privs`.
- Without Landlock (`confinement none`), `folder` mode refuses every command.

On Windows, each command runs in a Job Object that ends all its processes with
it. A Job Object limits no file access, so `folder` mode runs no command there.

## The sudo switch

The switch is per node, not per entry, and it is never on without a working
password.

- Off, no `sudo` command runs, even if the sudo list names it.
- On, a `sudo` command runs only if the sudo list names it, in every mode.
- On Linux the password is checked with `sudo -S -k -v` and kept in memory
  only. A restart turns the switch off.
- On Windows the password is the one of the account commands run as. The
  node checks it with a batch logon that must hold the Administrators group,
  keeps it with DPAPI in the config folder (so a restart keeps the switch
  on), and starts each sudo command with that logon's full token.
- A center with the settings grant can switch it. The password then travels
  sealed from the owner's browser to the node. The node makes a one-shot offer
  with a fresh X25519 key and signs it with its pairing key. The browser derives
  a key with HKDF-SHA256 and seals the password with AES-256-GCM. The center
  only relays the ciphertext. The node opens an offer once, within 60
  seconds. The exact steps are in
  [spec/protocol.md](spec/protocol.md) §7.4.1.
- A tampered center web UI could capture the password before it is sealed,
  because the center serves the form. The node-side guarantees hold anyway.

## What a center is shown

The descriptor follows the same policy ([capabilities](capabilities.md)). A
tool exists only for an action a call could get through.
