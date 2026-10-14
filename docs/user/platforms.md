# Linux and Windows

Both programs run on Linux (x86_64, aarch64) and Windows (x86_64). The node
behaves the same except where this page says so.

| | Linux | Windows |
|---|---|---|
| Shell for commands | `/bin/sh -c` | Windows PowerShell 5.1 (`powershell.exe -NoProfile -Command`) |
| `folder` mode runs commands | Yes, confined by Landlock | Yes, confined by an AppContainer; not yet on the [installed service](service.md#windows) |
| `allowlist` and `user` mode run commands | Yes | Yes, in a Job Object, not confined to folders |
| Sudo switch | Yes | On the [installed service](service.md#windows), with the administrator token of the account commands run as ([sudo on Windows](sudo.md#sudo-on-windows)) |
| Control socket | Yes | A control pipe that takes folder changes only |
| Install as a service | Yes, with systemd | Yes |
| Config folder | `~/.config/nerve` | `%USERPROFILE%\.config\nerve` |

## Linux

- `folder` mode needs Landlock in the kernel. With the node running,
  `nerve-node status` shows `confinement landlock v…`, or `confinement none`
  when it is missing. With `none`, `folder` mode refuses every command.
- Commands run with `no_new_privs`, so setuid programs cannot gain privileges.
  Only a command on the [sudo list](sudo.md) runs without it.
- When a call ends, the node kills the command's whole process group.
- A node that runs as root is refused unless `machine.allow_root` is set
  ([root and administrator](#root-and-administrator)).

## Windows

- Commands run in Windows PowerShell 5.1. `;` chains commands. `&` does not.
- Each command runs in a Job Object. The shell starts suspended, joins the job
  and only then runs, so every process it starts is in the job. Ending the job
  ends all of them. The job closes with the node, so a node that dies leaves no
  command running.
- A process that another program starts for the command, such as WMI, a
  service or the task scheduler, belongs to that program and is not in the job.
- A Job Object does not limit file access. It is not a sandbox. In `folder`
  mode the command also runs in an AppContainer, which is. See
  [modes](modes.md#what-a-command-can-reach-in-folder-mode-windows), and for
  what the container does not stop,
  [the list there](modes.md#what-the-appcontainer-does-not-stop).
- Output that is not UTF-8 is read in the console code page.
- A [sudo](sudo.md#sudo-on-windows) command runs with the elevated token of
  the account commands run as, which must be an administrator. Every other
  command of that account runs with the token UAC filtered. UAC is no
  security boundary, so those commands can get the administrator rights back
  as well.
- Paths in rules and over the wire look like `/c/Users/x`.
- A node that runs elevated (as an administrator) is refused unless
  `machine.allow_root` is set ([root and administrator](#root-and-administrator)).

### Root and administrator

A node with full rights hands those rights to every command a center runs:
root on Linux, an elevated administrator token on Windows. On Linux a root
node can run the commands as the account `machine.user` names instead; on
Windows an elevated node cannot start a command as another account, so
commands run with the node's own token (`machine.user` there is for the
[installed service](service.md#windows)). So on both platforms it is refused
at start unless you allow it:

```
nerve-node config set machine.allow_root true
```

The refusal is the same message on both: `refusing to run as root; set
machine.allow_root = true to allow it`.

On Windows the node counts as elevated when its token is elevated: a
PowerShell started with "Run as administrator", a scheduled task that runs
with highest privileges, an account such as SYSTEM, or an administrator's
session over SSH, which Windows OpenSSH gives the full, elevated token. An
administrator at the desktop whose PowerShell was not started elevated (a
UAC-filtered session) is a normal user to the node, and needs no setting.

When the node runs with full rights because you allowed it, it says so with a
warning at start: in the stderr output and in the node's log file. The
center's Log page shows the center's own log and does not carry it. Commands
from a center then run with full rights on the machine (on Linux unless
`machine.user` names another account for them), and you are responsible for
what they do. On Windows, in `folder` mode, their AppContainer still holds
them to their folders.

### The control pipe

A running node on Windows takes `folder add`, `folder set` and `folder rm`
from the CLI at once, over a named pipe, and brings the folders' permission
entries in line before it answers. Only the administrators (in a terminal
opened with "Run as administrator"), SYSTEM and the node's own account can
open the pipe, and the node refuses every request from a process of a
command it runs. The pipe takes no other change yet: for those the CLI
writes the signed `node.toml` itself, and the node takes them at its next
start. Until then the node refuses folder changes, which would undo them:
restart it first ([troubleshooting](troubleshooting.md#restart-the-node-then-change-the-folder-again-windows)).
A command that the node runs for a center can change the node's own policy
where it can write that file.

Allow commands on Windows only for centers you would also give the
[settings grant](settings-grant.md), or [install the node as a
service](service.md#windows): its commands run as another account, which
cannot open the node's folders.

### Windows protected paths

See [protected paths](protected-paths.md) for the Windows list. A folder that
is spelled so that it matches nothing is refused: a `..` part, an 8.3 short
name such as `NODE-S~1`, or a name that ends in a dot or a space. Use the full
name.
