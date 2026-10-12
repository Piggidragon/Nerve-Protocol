# Audit

The node writes down every decision about a call, and every change to its
settings. Read it on the machine, or in the center's web UI.

## On the machine

```sh
nerve-node audit               # everything, oldest first
nerve-node audit --denied      # only refused calls
nerve-node audit --follow      # keep running and print new entries
```

A call looks like this: a time in milliseconds since the epoch, the center, the
action, the target and the decision. A refusal adds its reason.

```
1791834106607  lab  fs.read  /etc/hostname  forbidden: no allow rule matches /etc/hostname
1791834531401  lab  fs.read  /home/u/proj/a.txt  allowed
```

The reason says what is missing. Use it to write the rule you want
([rules](rules.md)).

Settings changes are lines like `1791834068828  settings v1 by local`. They
show the new version and who changed it: `local` for `nerve-node`, or the name
of a center. The log holds the old and the new value of each setting.

## What the log holds

- Targets: paths and command lines, cut at 512 characters.
- Never file contents or command output.
- Never the sudo password.
- Refusals of a changed `node.toml`, and the owner taking it with
  `config accept`.

## Where it is and how big it gets

The log is `audit.jsonl` in the node's state folder
([where](install.md#where-files-live)). One line is one JSON object.

At 10 MiB the node moves it to `audit.jsonl.1` and replaces the older copy, so
the log stays below about 20 MiB. A center that makes many refused calls cannot
push out what the node allowed or changed: refusals take at most half of a full
file, and the oldest refusals go first.

## The audit log and the log

The audit log is the node's record of its decisions. The [log](logs.md) is
what the program did: links, pairing, changes, errors. They are separate files
with their own sizes. A call that worked is only in the audit log; a call that
was refused or failed is in both, in the log with its reason.

## In the web UI

The Audit page lists the latest decisions of all machines, newest first. It
keeps at most 500 decisions or 1 MiB, in memory. See
[the web UI](web-ui.md#audit).
