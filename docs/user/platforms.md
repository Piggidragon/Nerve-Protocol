# Linux and Windows

Both programs run on Linux (x86_64, aarch64) and Windows (x86_64). The node
behaves the same except where this page says so.

| | Linux | Windows |
|---|---|---|
| Shell for commands | `/bin/sh -c` | Windows PowerShell 5.1 (`powershell.exe -NoProfile -Command`) |
| `folder` mode runs commands | Yes, confined by Landlock | Yes, confined by an AppContainer |
| `allowlist` and `user` mode run commands | Yes | Yes, in a Job Object, not confined to folders |
| Sudo switch | Yes | No |
| Control socket | Yes | No |
| Config folder | `~/.config/nerve` | `%USERPROFILE%\.config\nerve` |

## Linux

- `folder` mode needs Landlock in the kernel. With the node running,
  `nerve-node status` shows `confinement landlock v…`, or `confinement none`
  when it is missing. With `none`, `folder` mode refuses every command.
- Commands run with `no_new_privs`, so setuid programs cannot gain privileges.
  Only a command on the [sudo list](sudo.md) runs without it.
- When a call ends, the node kills the command's whole process group.
- A node that runs as root is refused. To allow it, run
  `nerve-node config set machine.allow_root true`.

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
  [modes](modes.md#what-a-command-can-reach-in-folder-mode-windows).
- A node that runs as an administrator (elevated) logs a warning when it
  starts: its commands run as one too, and in `folder` mode only their
  AppContainer holds them.
- Output that is not UTF-8 is read in the console code page.
- Paths in rules and over the wire look like `/c/Users/x`.

### No control socket

A running node cannot be told about changes. The CLI writes the signed
`node.toml` itself, and the node takes a change at its next start. A command
that the node runs for a center can therefore change the node's own policy.

Allow commands on Windows only for centers you would also give the
[settings grant](settings-grant.md).

### Windows protected paths

See [protected paths](protected-paths.md) for the Windows list. A folder that
is spelled so that it matches nothing is refused: a `..` part, an 8.3 short
name such as `NODE-S~1`, or a name that ends in a dot or a space. Use the full
name.
