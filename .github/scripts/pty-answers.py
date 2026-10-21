#!/usr/bin/env python3
"""Runs a command in a pseudo-terminal and answers its questions.

    pty-answers.py [PATTERN=ANSWER ...] -- COMMAND [ARGS ...]

Each question the command asks (a regular expression, searched in what it
printed since the last answer) is answered once, in the order given, with
ANSWER and a line break; an empty ANSWER is Enter. What the command prints is
copied to this program's output. The exit code is the command's. It is 3 when
the command ended before it asked every question, 4 when it was silent for
too long. The python standard library only, for the node's `setup` and the
other commands that ask only at a terminal.
"""
import os
import pty
import re
import select
import sys
import time

QUIET = 120  # seconds without output before the command counts as stuck


def main() -> int:
    argv = sys.argv[1:]
    if "--" not in argv:
        print(__doc__, file=sys.stderr)
        return 2
    cut = argv.index("--")
    answers = [a.split("=", 1) for a in argv[:cut]]
    command = argv[cut + 1 :]
    if not command or any(len(a) != 2 for a in answers):
        print(__doc__, file=sys.stderr)
        return 2

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(command[0], command)
    heard = b""
    last = time.monotonic()
    stuck = False
    while True:
        ready, _, _ = select.select([fd], [], [], 1)
        if not ready:
            if time.monotonic() - last > QUIET:
                stuck = True
                os.kill(pid, 9)
                break
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:  # EIO: the other end of the terminal is closed
            break
        if not data:
            break
        last = time.monotonic()
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        heard += data
        if answers and re.search(answers[0][0].encode(), heard):
            os.write(fd, (answers.pop(0)[1] + "\n").encode())
            heard = b""
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if stuck:
        print(f"\npty-answers: no output for {QUIET} s, killed it", file=sys.stderr)
        return 4
    if answers:
        print(
            f"\npty-answers: the command ended before it asked {answers[0][0]!r}",
            file=sys.stderr,
        )
        return 3 if code == 0 else code
    return code


if __name__ == "__main__":
    sys.exit(main())
