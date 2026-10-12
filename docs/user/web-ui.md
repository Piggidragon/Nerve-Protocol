# The web UI

`nerve-center` serves a web UI at `http://127.0.0.1:7480` (`--ui`). Its pages,
scripts and styles are built into the program. It loads nothing from another
host.

## Log in

The UI logs in with a [harness token](harness.md#tokens), the same secret the
HTTP endpoint takes.

| Where the UI listens | Login |
|---|---|
| Loopback, no token yet | None. This lets you make the first token |
| Loopback, a token exists | On. `--ui-no-login` turns it off |
| Any other address (`--ui 0.0.0.0:7480`) | Always on, and the UI uses TLS. The center refuses to start without a token or with `--ui-no-login` |

- A browser without a session goes to `/login` and posts the token once.
- The session lasts 12 hours. **Sign out** ends it.
- Five wrong tokens in a minute lock the login for the rest of that minute.
- Deleting a token ends the sessions that used it.
- Lost the token? Start the center once with `--ui-no-login` on loopback and
  make a new one.

To reach a UI that listens on loopback from another machine, use an SSH tunnel:

```sh
ssh -L 7480:127.0.0.1:7480 user@center-host
```

## Pages

### Overview

- **Machines.** Each paired machine with its state (online, offline,
  disabled), platform, a short summary and what it offers. Buttons: Rename,
  Disable or Enable, Remove.
- **Pair a machine.** Makes a [pairing](pairing.md) command, address, code and
  pin.
- **Sessions.** The harnesses connected now. **End** stops one session.
- Alerts, for example a machine whose key is in use twice.

A disabled machine stays paired and connected. The agent gets none of its tools
and calls to it are refused.

### Statistics

For all machines and for each one: time online, links, drops, calls, failed
calls, then calls per action with the average and the longest time, and errors
by code. Only counts and times are kept, never content. They are kept for the
number of days set in Settings.

### Audit

The latest decisions about calls, newest first: machine, action, target and
whether it was allowed or refused, with its reason.

Each entry with a known target has four buttons:

| Button | Adds |
|---|---|
| Allow | A rule for exactly this command, path or action |
| Allow as wildcard | A rule for the program and anything after it, the folder and everything below it, or the whole capability |
| Deny | The exact deny rule |
| Deny as wildcard | The wide deny rule |

A sudo command goes on the sudo list when you press Allow. A button adds the
rule on the machine, so it works only if the machine gave the center the
[settings grant](settings-grant.md). Otherwise the buttons are off and the
entry says why. A target that was cut to its start gets no buttons.

### Help

Lists the commands of `nerve-node` with what each does. The center reads the
list from the node's own command definition, so it matches `nerve-node --help`
of the same build.

### Settings

- **Center.** Its name, how many days to keep statistics, and how long a
  pairing code is valid (1 to 1440 minutes, 10 by default).
- **Harness tokens.** Make a token with a label. It is shown once. Delete one
  to stop it.
- **Machines.** For each online machine that gave the center the settings
  grant: its settings as JSON, with **Reload** and **Save**, and the sudo
  switch. A save sends the whole document with its version. If the version is
  stale, the machine refuses it. Reload and try again. A machine without the
  grant says it keeps its settings to itself.
