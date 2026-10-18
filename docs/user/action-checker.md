# The action checker

The action checker is a gate on the **center**. It looks at each call before
the machine gets it, and can refuse it. The machine's own rules still decide
what it lets through: the checker can only make a call stricter, never more
permissive (a machine with nothing allowed still allows nothing).

It is set up in the web UI, on the **Action checker** page. Everything it keeps
is in the center's state, so it survives a restart and is in a backup.

## The order

For each call the checker goes through these steps, and stops at the first that
decides.

1. **Blocklist.** A deterministic list of dangerous commands and paths. A match
   is refused at once, with no model call. The blocklist wins over everything
   below.
2. **Allow rules.** Calls you saved as allowed. A match goes straight to the
   machine, with the model skipped. It does **not** skip the blocklist.
3. **Decision model** (optional, off by default). A small model that answers
   whether the call is dangerous. At or above the threshold the call is
   refused.
4. Otherwise the call goes to the machine, as before.

Every decision in steps 1 to 3 is in the center's audit feed and log, with what
made it. A refused call comes back to the agent as `forbidden`, with a message
it can pass on: that the center's action checker refused it, what did so, and
that you can change it here.

Each part has its own switch: the blocklist (on by default), the model (off by
default) and taint (below). A change takes effect for the next call.

## The blocklist

Entries are in the machine's own rule syntax, `<scope>:<pattern>`:

- `exec.run:rm -rf /*` — a command. The program, then the flags that must be
  present, then an operand pattern.
- `fs.write:/etc/sudoers` — a write to a path. `~` stands for any user's home.
- `re:` for a regular expression where a wildcard is not enough, e.g.
  `exec.run:re:(?i)\bmkfs\b`.

You can add entries, remove them, switch single ones off, and reset the whole
list to the built-in defaults. The defaults block truly dangerous things and
leave ordinary work alone: `rm file`, `rm -rf ./build`, `rm -rf node_modules`,
`docker ps`, `git push` and `kill <pid>` all stay allowed; wiping the root
filesystem, `mkfs`, `dd` to a disk, fork bombs, `chmod -R 777 /`, dropping a
database, a container that gives root on the host, `curl … | sh`, force-pushing
`main`, and the Windows equivalents (`Format-Volume`, `rd /s /q C:\`,
`vssadmin delete shadows`, disabling Defender, …) are blocked.

The matcher does not just look at the raw string. For a command it splits the
line into its commands (at `;`, `&&`, `||`, `|`, newlines, inside `$( )`,
backticks and `sh -c '…'` / `powershell -Command` bodies), strips wrappers
(`sudo`, `env A=B`, `nohup`, `time`, `nice`, `xargs`, …), takes the program's
base name (`/bin/rm` → `rm`), and treats short flags in any order, split or
joined (`-rf`, `-fr`, `-r -f`, `--recursive --force`) as the same.

**What it cannot see:** shell variables, aliases, a script written to a file
and then run, and base64-encoded commands. The matcher is one line of defence;
the decision model and the machine's own policy are the next. Treat the
blocklist as a safety net for obvious mistakes and obvious attacks, not as a
sandbox.

A refused call shows in the Audit page. For a blocklist refusal you change or
remove the entry here; for a model refusal you can add an allow rule with a
button there.

## Allow rules

Allow rules are the same syntax, saved for every machine or for one machine. A
call that matches one skips the decision model and goes to the machine. It does
not skip the blocklist: the blocklist is a hard deny, so to let something
through that the blocklist caught, remove or switch off the blocklist entry.

The Audit page has **Allow** and **Allow as wildcard** buttons on a model
refusal, which save an allow rule for you.

## The decision model

The model is off by default. Turn it on to have a System One model judge each
call. System One models answer a typed yes/no question in one pass, with no
text generated, so a judgement is fast and cheap. There are two sources:

- **A System One endpoint.** Give a URL (`https://` uses the system's root
  certificates), an optional bearer token and an optional model name
  (`jev-latest` for TypeSafe's hosted API). The token is a secret: it is kept
  in a file of its own in the state folder and is never shown back. It is a
  secret, so it is **not** in a center backup (as `state.json` holds no
  secrets); after a restore, enter the token again.
- **A llama-server the center runs.** The center starts `llama-server` itself
  (from `PATH`, or a path you set — the center does not download llama.cpp; you
  need a build with the `/v1/systemone` endpoint). Give a model to download
  (`-hf <repo>:<quant>`, cached under the state folder) or a local model file.
  It listens on loopback, on the CPU by default (GPU layers and threads are
  settings). The center checks the model is a decision model and refuses one
  that is not. The page shows the server's state (starting, downloading, ready
  or failed) and the last lines of its output.

The default local model is **LiquidAI d1-3B** (Q4_K_M). Its licence is the
**LFM Open License v1.0**, not Apache; check it suits you before you use it.

**Settings:**

- **Which calls the model sees.** By default every execute, write and actuate
  call (reads are not sent). You can add reads, or have it see only the calls
  of a tainted session (see below).
- **Threshold.** At or above this probability the call is refused. The default
  is tuned so ordinary work is almost never refused.
- **Timeout**, and what to do on an error or a timeout: **fail closed** (refuse
  the call, the default and the safe choice) or allow-and-log.
- **The question.** The instructions and the true/false criteria the model is
  asked. You can edit and reset them. The command text is never put into the
  question — it goes only into the state the model reads — so a crafted command
  cannot rephrase what is asked.

If the model is on and cannot be reached, a call is refused (fail closed) with a
message that says so and where to switch the model off. Switch it to
allow-and-log if you would rather let calls through when the model is down.

## Taint

A session becomes **tainted** once a call of it returned outside content: a
successful read, a search, or a command's output. While taint is on, a tainted
session is marked for the model (and the "only tainted sessions" scope applies).
The idea is that a session that has read untrusted content is the one where a
later dangerous call is most suspicious.

Taint has its own switch. Switching it off clears every mark at once, and with
it off no call is refused for an earlier read. The Overview and the sessions
list show which sessions are tainted.

## What the model is told

The state sent to the model is the call: its capability and action, the command
or path, the other arguments cut to a bounded size, the machine's OS, and
whether the session is tainted. The center never sends file contents or command
output to the model, and the question is fixed by the center.
