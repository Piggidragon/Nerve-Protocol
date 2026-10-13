# Sudo

Sudo is a switch on the machine, not a mode. It works on Linux, and on
Windows on the node [installed as a service](service.md#windows) ([sudo on
Windows](#sudo-on-windows)). It is off by default.

| Switch | What happens to a `sudo` command |
|---|---|
| Off | Refused, even if the sudo list names it. The node holds no password |
| On | Runs only if the sudo list names it, in every mode. Deny rules and protected paths still apply |

A sudo command is one whose first word is `sudo` (or a path ending in
`/sudo`). It has its own list, `sudo`. The normal allow list does not count
for it.

## Turn it on

1. Put the commands on the sudo list. `sudo` in front is optional:

   ```sh
   nerve-node rule add sudo 'apt update'
   nerve-node rule add sudo 'apt update' --wildcard   # sudo apt, and anything after it
   ```

2. Switch sudo on. The node must be running. It asks for the sudo password
   of the account the commands run as: your own on a node you run yourself,
   the account `install` took or `setup` chose on a node installed as a
   [service](service.md#the-account-commands-run-as):

   ```sh
   nerve-node sudo on
   ```

3. Look or turn it off:

   ```sh
   nerve-node sudo status
   nerve-node sudo off
   ```

`rule add allow 'sudo …'` is refused. A sudo command goes on the sudo list.

## What the node does

On Linux (Windows differs, see [sudo on Windows](#sudo-on-windows)):

- It checks the password with `sudo -S -k -v`, run as the account the
  commands run as, so sudo checks that account's password and its sudoers
  entries. A wrong password is refused and the switch stays as it was.
- It keeps the password in memory only. Turning sudo off drops it. A node that
  restarts has sudo off.
- It never sends the password to a center. It replaces any copy in a frame or
  in the audit log with `[redacted]`. This holds on Windows too.
- A sudo command must be one simple command. One with `; & | $ ` ( ) < >` or a
  line break is refused. This holds on Windows too.
- A `--wildcard` entry covers plain commands only, as a [wildcard allow
  rule](rules.md#what-a-wildcard-covers) does. A line with `@ { } % ' " # , \`
  or a word such as `powershell`, `cmd`, `iex` or `-Command` runs only when an
  entry names the whole line. This holds on Windows too.
- It starts the command as that account, as `sudo -S -k -p <prompt> …`, so
  sudo raises it from that account. It runs without the Landlock
  sandbox, which would stop sudo from gaining privileges. It writes the
  password only after sudo prints the prompt.
- Every other command runs with `no_new_privs`. A `sudo` later in a command
  line, or any setuid program, cannot gain privileges.

## From the web UI

A center with the [settings grant](settings-grant.md) can turn sudo on and off.
In Settings, open the machine and press **Turn sudo on**. The browser seals the
password for the node, and the center only passes it on. The center cannot read
it.

The center serves the form that takes the password. A tampered center could
capture the password before the browser seals it. Turn sudo on from the
machine if you do not trust the center.

## Sudo on Windows

Windows has no `sudo` program. A sudo command runs as the
[account commands run as](service.md#the-account-commands-run-as-on-windows),
with that account's administrator rights: the elevated token that "Run as
administrator" gives, not the token UAC gives its other commands. So:

- It works only on the node installed as a service. A node you start
  yourself refuses to switch sudo on.
- The account commands run as must be an administrator. Otherwise the switch
  refuses to turn on.
- `sudo on` asks for that account's password, the one `install` stored. A
  wrong password is refused and the switch stays as it was.
- The node keeps the password with DPAPI in the config folder, as `install`
  keeps it (`sudo.dpapi`). Unlike on Linux, sudo stays on when the service
  restarts. `sudo off` removes the file, and `uninstall` removes it too.

Run the commands in a terminal opened with "Run as administrator". Windows
has no control socket, so `sudo on` takes effect when the service starts
again. `sudo off` takes effect at once: the running service drops the
password within a second.

```powershell
& "C:\Program Files\Nerve\nerve-node.exe" rule add sudo 'net session'
& "C:\Program Files\Nerve\nerve-node.exe" sudo on
Restart-Service nerve-node
& "C:\Program Files\Nerve\nerve-node.exe" sudo off
```

A center with the settings grant switches the running service at once, as on
Linux.

The node starts the command line after `sudo` with the shell
(`machine.shell`, Windows PowerShell 5.1 by default), logged on as a batch
job: the logon Windows uses for a scheduled task that runs with highest
privileges. The account needs the right "Log on as a batch job", which
administrators have unless a policy takes it. The command runs in a Job
Object like every other command, so a timeout or `exec.signal` ends it.

A sudo command can change anything on the machine and read the node's keys.
Put only the commands you mean on the sudo list.
