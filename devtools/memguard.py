# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Runs a command and kills it if its process tree's resident memory exceeds a limit.

usage: python memguard.py LIMIT_GIB -- command args...
Prints the peak RSS it observed.
"""

import os
import signal
import subprocess
import sys
import time

limit = float(sys.argv[1]) * 2**30
cmd = sys.argv[sys.argv.index("--") + 1 :]
proc = subprocess.Popen(cmd, start_new_session=True)
peak = 0


def tree_rss(root):
    out = subprocess.run(
        ["ps", "-A", "-o", "pid=,ppid=,rss="],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    kids, rss = {}, {}
    for line in out.split("\n"):
        if line.strip():
            pid, ppid, r = map(int, line.split())
            kids.setdefault(ppid, []).append(pid)
            rss[pid] = r * 1024
    total, stack = 0, [root]
    while stack:
        p = stack.pop()
        total += rss.get(p, 0)
        stack += kids.get(p, [])
    return total


while proc.poll() is None:
    r = tree_rss(proc.pid)
    peak = max(peak, r)
    if r > limit:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        print(
            f"\nmemguard: KILLED at {r / 2**30:.1f} GiB (limit {limit / 2**30:.0f} GiB)",
            file=sys.stderr,
        )
        sys.exit(137)
    time.sleep(0.25)
print(
    f"\nmemguard: peak RSS {peak / 2**30:.1f} GiB, exit {proc.returncode}",
    file=sys.stderr,
)
sys.exit(proc.returncode)
