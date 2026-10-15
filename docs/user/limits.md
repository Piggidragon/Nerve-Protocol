# Limits per command

Each command a center runs gets a limit on its memory, its CPU and its
number of processes. You set what a command gets and the most a call may ask
for. A call may ask for less, or for more up to that most, never beyond it.

Linux only for now. On Windows the settings are there, but commands are not
held to them yet.

## The settings

```toml
[limits.command]
memory_mb = 4096         # memory of one command, in MiB
memory_max_mb = 16384    # the most a call may ask for
cpu_percent = 200        # CPU time in percent of one CPU: 200 is two CPUs
cpu_max_percent = 800
processes = 1024         # processes and threads at once
processes_max = 8192
```

These are the defaults. Change them by name:

```sh
nerve-node config set limits.command.memory_mb 2048
nerve-node config set limits.command.memory_max_mb 8192
nerve-node config unset limits.command.memory_mb      # back to the default
```

Each value is at least 1, and a default may not be above its most. Only you
set them: a center with the [settings grant](settings-grant.md) cannot.

## What a call asks for

`exec_run` takes `memory_mb`, `cpu_percent` and `processes`, each optional:

```json
{"command": "make -j8", "memory_mb": 8192, "cpu_percent": 800}
```

A value the call leaves out is your default. A value above your most is
refused with `invalid_args`, and the error says the most. The node
describes the defaults and the most to the center, so the agent can see them
in the tool's parameters.

## Past a limit

| Limit | What happens |
|---|---|
| Memory | The command is killed, with everything it started. Its result has `"killed": "memory"` and a `reason`, such as `the command went past its memory limit of 4096 MiB and was killed`, and `"signal": "kill"`. |
| CPU | The command is slowed down. It is not killed. |
| Processes | The command cannot start more. A shell says `Cannot fork` or `Resource temporarily unavailable`. |

Swap does not count as room: a command past its memory is killed, not
swapped out. Files the command reads into the page cache count towards its
memory, but the kernel frees those first.

A command killed for its memory is in the [audit log](audit.md) as its own
entry, `killed`, after the `allowed` one, with the reason. The
[log](logs.md) has it as a warning.

## Where the limits hold

The node puts each command in a cgroup of its own. It needs a cgroup v2 that
systemd hands to it:

- **The installed service** has one. Its unit says `Delegate=cpu memory pids`
  ([service](service.md)). A node installed before this version has a unit
  without that line: run `sudo nerve-node install` again after the
  [update](service.md#update). It writes the unit and restarts the node, and
  keeps the config, the keys and the audit log.
- **A node you start yourself** has one when you start it in a scope of its
  own:

  ```sh
  systemd-run --user --scope -p Delegate=yes nerve-node run
  ```

  Started plainly in a terminal, it shares the terminal's cgroup, which is
  not its own to divide.

Without such a cgroup (no systemd, cgroup v1, a node started in a terminal),
commands run without these limits. `nerve-node status` says so, and why:

```
limits per command: memory 4096 MiB, CPU 200 %, 1024 processes; a call may ask for up to 16384 MiB, 800 %, 8192 processes
limits held by the cgroup /system.slice/nerve-node.service: memory, cpu, processes
```

or

```
commands run WITHOUT these limits: the node's cgroup /user.slice/… is not delegated to it: …
```

When a cgroup offers only some controllers, the line names the limits that
are not held.

When a command ends, everything still in its cgroup is killed: also a
process it moved out of its process group (`setsid`, `nohup … &`), which
would otherwise outlive it.

## What the limits do not cover

- A command that runs as the node's own user (a node you start yourself, in
  `allowlist` or `user` mode) can move itself out of its cgroup or raise its
  limits, as the cgroup's files are that user's. Commands of the installed
  service run as another account ([the account commands run
  as](service.md#the-account-commands-run-as)) and cannot. In `folder` mode
  Landlock keeps a command from writing the cgroup files.
- Disk space and disk speed are not limited.
- The limits are per command. `limits.max_running` (16 by default) bounds how
  many commands run at once, so many commands together can use more.
