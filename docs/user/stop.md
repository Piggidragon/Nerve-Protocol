# Stop access

From the quickest to the most thorough.

| You want | Do | Effect |
|---|---|---|
| Stop one agent session | Web UI, Overview, Sessions, **End** | The session's running commands stop |
| Hide a machine from the agent | Web UI, Overview, **Disable** on the machine | The machine stays paired and connected. The agent gets none of its tools, and calls to it are refused. **Enable** undoes it |
| Stop one center on a machine | `nerve-node center pause --center lab` | The node drops the link and does not dial it again |
| Stop every center on a machine | `nerve-node panic` | Every link ends. Nothing runs until `unlock` |
| End a pairing | `nerve-node center rm --center lab`, or **Remove** in the web UI | The pairing and its key are gone |

## Panic

```sh
nerve-node panic       # end every link; nothing runs
nerve-node status      # shows LOCKED (panic)
nerve-node unlock      # work again
```

`panic` locks the node in `node.toml`. The lock stays after a restart until you
run `unlock`. Only you can unlock. A center can never unlock.

If `panic` says the node does not take connections now, or that the config
keeps changing, the lock was not set. Try again; if it keeps failing, stop the
node itself (`systemctl stop nerve-node`, or Ctrl-C for a node you started).

## Pause

```sh
nerve-node center pause --center lab
nerve-node center resume --center lab
```

A center with the [settings grant](settings-grant.md) can pause its own link.
Only you can resume it.

## What ends a command

A command stops when its call ends: on its timeout, when the caller cancels,
when its session ends, or when the link drops. Every command has a timeout:
its `timeout_ms`, or the node's default, and never more than the node's maximum
([how long a command may run](config.md#how-long-a-command-may-run)). On Linux the node kills the
command's whole process group. On Windows it ends the command's Job Object.

On Windows a timeout, and `exec_signal` with `term` or `int`, first ask the
command to end: its console programs get Ctrl+C and its windows a close
request. What has not ended 3 seconds later is ended with the Job Object.
`kill`, a cancel, the end of a session and a dropped link end it at once.
