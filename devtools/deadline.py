# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Runs a command and kills its whole process tree at a deadline.

    python3 deadline.py SECONDS -- command args...

memguard.py starts its child in a new session, so killing memguard alone would
leave Ghidra's Java process running; this kills every descendant. Exit status
124 if the deadline was reached.
"""

import os
import signal
import subprocess
import sys
import time


def descendants(root):
    """The process and all its descendants, parents first."""
    out = subprocess.run(
        ["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, check=False
    ).stdout
    children = {}
    for line in out.splitlines():
        if line.strip():
            pid, ppid = map(int, line.split())
            children.setdefault(ppid, []).append(pid)
    result, stack = [], [root]
    while stack:
        pid = stack.pop()
        result.append(pid)
        stack += children.get(pid, [])
    return result


def main():
    if len(sys.argv) < 4 or "--" not in sys.argv:
        sys.exit(__doc__)
    limit = float(sys.argv[1])
    command = sys.argv[sys.argv.index("--") + 1 :]
    proc = subprocess.Popen(command)
    start = time.time()
    while proc.poll() is None:
        if time.time() - start > limit:
            for pid in reversed(descendants(proc.pid)):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait()
            print(f"deadline: killed after {limit:.0f} s", file=sys.stderr)
            sys.exit(124)
        time.sleep(1)
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
