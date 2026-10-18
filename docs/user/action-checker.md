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

The blocklist is there to catch an agent's mistakes: a hallucinated
`rm -rf ~`, a `git push --force` to `main` it should not have made, a `mkfs` on
the wrong disk. It does not stop someone who writes commands on purpose to get
past it; a list of patterns cannot. Against that, what counts is the machine's
own policy: its mode, its deny rules and the folder sandbox.

Entries are in the machine's own rule syntax, `<scope>:<pattern>`:

- `exec.run:rm -rf /*` — a command. The program (in any letter case), then
  the flags that must be present, then an operand pattern.
- `fs.write:/etc/sudoers` — a write to a path. `~` stands for any user's home.
- `cmd-re:` for a regular expression over **each command** of the line, e.g.
  `exec.run:cmd-re:^terraform destroy( |$)`. The checker pulls the commands
  apart (see below) and writes each one as `program arg1 arg2 …`: the
  program's base name without `.exe` and without wrappers such as `sudo`,
  then the arguments as written, all **lower-cased**, with the quotes removed
  and one space between them. So `^` is the program, and a pattern must be in
  lower case (`^remove-item …`, not `^Remove-Item …`). An argument with a
  blank in it is written in double quotes, so a pattern can tell where it
  ends: `psql -c "DROP TABLE x"` is `psql -c "drop table x"`, which
  `^psql .*drop table` matches. The example blocks `terraform destroy` but not
  `grep "terraform destroy" notes.md`.
- `re:` for a regular expression over the **whole line**, e.g.
  `exec.run:re:(?i)\bdd\b[^|&;]*\bof=/dev/sd`. Runs of spaces become one, a
  line ended by `\` (or PowerShell's `` ` ``) is joined with the next, and any
  other line break becomes ` ; `, so `[^;]*` stops at the end of a command.
  It sees everything on the line, quotes and comments included, so a pattern
  that only looks for a word also refuses a commit message or a `grep` that
  mentions it: prefer a command pattern or `cmd-re:` where you can.

You can add entries, remove them, switch single ones off, and reset the whole
list to the built-in defaults. The defaults block truly dangerous things and
leave ordinary work alone: `rm file`, `rm -rf ./build`, `rm -rf node_modules`,
`docker ps`, `git push` and `kill <pid>` all stay allowed; wiping the root
filesystem or a home folder, `mkfs`, `dd` to a disk, fork bombs,
`chmod -R 777 /`, dropping a database, a container that gives root on the host,
running a downloaded script unseen (`curl … | sh`, `sh -c "$(curl …)"`,
`bash <(curl …)`, and on Windows `irm … | iex` or `iex (… DownloadString …)`),
force-pushing `main`, and the Windows equivalents (`Format-Volume`,
`format D:`, `rd /s /q C:\`, `Remove-Item -Recurse` of `~` or
`C:\Users\<name>`, `vssadmin delete shadows`, disabling Defender, …) are
blocked. The download entries also refuse a tool's official install one-liner;
to run one, ask the owner, who can switch the entry off for a while (an allow
rule does not get past the blocklist). Most defaults look at the command that
runs, not at every word on the line: `mkfs`, `wipefs`, `userdel`, `nsenter`,
`bcdedit`, `diskpart`, `format` and `Format-Volume` only as the program (so
`dotnet format C:\src\App.sln` is not formatting a drive), `shred`, `iptables -F`, stopping `sshd`
and the container flags (`--privileged`, `--pid=host`, `-v /:/…`) only in that
command's own words, `DROP TABLE` only in what a database client (`psql`,
`mysql`, `sqlite3`, `mongosh`, …) is given, a download only when something
runs it (`| sh`, `| sudo bash -s`, `| python3 -`, `| iex` at the end of a
command, `iex (…)`, `sh -c "$(curl …)"` or `bash <(curl …)` at its start, not
`| grep`, `| python -m json.tool` or `-o install.sh`), and a force-push only in
the `git push` itself. So a commit message, a `grep` or a note that merely
mentions one of them is not refused. One exception: a shell's quoted `-c` body
(`sudo sh -c 'curl … | sh'`, `powershell -c "irm … | iex"`) is read wherever
the shell's name stands, so a note that writes out such a whole line, shell and
quotes included, is refused too.

The matcher does not just look at the raw string. For a command it splits the
line into its commands (at `;`, `&&`, `||`, `|`, newlines, inside `$( )`,
backticks and `sh -c '…'` / `cmd /c` / `powershell -Command` bodies), strips
wrappers (`sudo`, `env A=B`, `nohup`, `time`, `nice`, `xargs`, …), reads the
program that `Start-Process` (also with `-Verb RunAs`) or `start` runs as a
command, takes the program's base name (`/bin/rm` → `rm`), and treats short flags in any order,
split or joined (`-rf`, `-fr`, `-r -f`, `-Rf`, `--recursive --force`) as the
same. The lines of a here-document are read as commands too, so a script
written with `cat > x.sh <<'EOF'` that holds `rm -rf ~` is refused, while one
with ordinary content is not. The same goes for a PowerShell here-string
(`@'` … `'@`). A quote in a document's or a here-string's line (an apostrophe
in "don't") ends with that line, so it cannot hide the commands after the
document. This also means a file written that way with `curl … | sh` in it (a
Dockerfile's `RUN curl … | bash -`, a CI step) is refused like the command
itself, and an allow rule does not get past it: have the agent write such a
file with the file tool (`fs.write`) instead, which the command entries do not
look at. A `#` comment runs to the end of its line. The
line is read by the rules of the machine's shell: PowerShell on Windows,
`/bin/sh` elsewhere. For a `fs` write it normalises the path first (`//`, `/.`
and `..` are resolved, and the match ignores letter case), so a
differently-spelled path still hits.

**What it cannot see:** shell variables and `$HOME` (it matches the literal
`$HOME` or `${HOME}`, not your home), aliases, a script written to a file and then run, and
base64-encoded commands. Its reading of a line is a simple one, not the
shell's own, so a line written to confuse it can get past it. For paths it sees
the path as the agent wrote it, not where a symlink would lead, and only this
machine (the center) resolves `..` and `//`, not the device's real canonical
path; the machine's own protected-path check is the backstop. A command line
nested absurdly deeply (more than 16 levels of `$( )`/`-c`) or with more than
100 000 commands, well beyond any real script, is refused outright rather than
half-analysed. Treat the blocklist as a safety net for an agent's obvious
mistakes, not as a sandbox: the decision model and the machine's own policy are
the next lines of defence.

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
- **A local model the center installs for you.** Pick the model, then press
  **Install on CPU** (or **Install on GPU**, offered when the machine has a
  GPU). The center downloads a prebuilt `llama-server` from llama.cpp's GitHub
  release and the model from Hugging Face into its own state folder — never
  system-wide — checks each against a pinned SHA-256, unpacks it, and runs it on
  loopback. GPU uses the Vulkan build (NVIDIA, AMD or Intel); after it is
  installed the center runs the build's device probe, and if it finds no GPU it
  keeps the model on the CPU and says so (so the page never claims the GPU when
  it is really the CPU). You can switch CPU/GPU later with one click. The page
  shows a
  progress bar for the download, then the server's state (starting, ready or
  failed) with the last lines of its output. During a reinstall or a switch the
  model already installed keeps checking calls while the new files download;
  it is stopped only for the moment the files are swapped, and if the install
  fails it keeps running as before. **Remove** turns the local model off and
  deletes the downloaded files; during an install the progress card has it
  too, and it ends the install first. A machine with no prebuilt build for it says so and points you to the
  endpoint source; for any other model, or your own llama.cpp, use the endpoint
  source too.

There are two local models; the page shows each one's size, licence, speed and
quality in one line:

| Model | Size | Licence | On a desktop CPU |
|---|---|---|---|
| **LiquidAI d1-3B** (the default) | 1.7 GB | LFM Open License v1.0 (not Apache) | Faster: about 1.7 s per call. Catches about 60 % of dangerous actions and 67 % of injection attempts, refuses about 2.5 % of ordinary work |
| **Kev-4B** (ggml-org) | 3.0 GB | Apache-2.0 | Catches more: about 79 % of dangerous actions and 93 % of injection attempts, refuses about 1.7 % of ordinary work, but about 4 to 5 s per call |

Pick d1-3B when the checker should stay quick on a CPU, Kev-4B when catching
more matters more than a few seconds per call, or when the machine has a GPU.
Switching the model downloads the other one and removes the first. Each model
comes with its own default threshold and timeout (d1-3B 0.8 and 4 s, Kev-4B 0.5
and 15 s, so Kev-4B's normal calls are not cut off); a switch sets them, and you
can change them afterwards. Check that a model's licence suits you before you
install it.

The speeds above are for a desktop CPU. A small machine is much slower (d1-3B
took about 35 s per call on a 4-core virtual machine); there, raise the timeout,
use the GPU, or use an endpoint, or the checker refuses every call it cannot
judge in time.

**Settings:**

- **Which calls the model sees.** By default every execute, write and actuate
  call (reads are not sent). You can add reads, or have it see only the calls
  of a tainted session (see below).
- **Threshold.** At or above this probability the call is refused. The default
  (per model, see above) is tuned so ordinary work is almost never refused.
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
