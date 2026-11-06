#!/usr/bin/env python3
"""Fail if any tracked file is one the leak checker cannot read.

WHY THIS EXISTS
---------------
`scripts/leakcheck.py` skips a file silently when it contains a NUL byte or does
not decode as UTF-8. `read_text()` returns None and `scan_files()` does
`if text is None: continue`. There is no report, no warning and no non-zero exit.
The file is simply not scanned.

A reviewer proved the consequence end to end in this repository: a `.dat` file
carrying a real credential shape plus one NUL byte, and a UTF-16 file carrying
the same, both passed `python3 scripts/leakcheck.py` and
`python3 scripts/leakcheck.py --staged` with `leakcheck: clean` and exit 0, and
`git commit` then succeeded. The same content in a plain UTF-8 file was caught
with exit 1 and the pre-commit hook blocked the commit. So the gate is live, and
it can be walked straight past by encoding.

WHY THE FIX IS NOT IN leakcheck.py
-----------------------------------
`scripts/leakcheck.py`, `scripts/leakcheck_test.py` and `scripts/leakcheck.config`
are byte-identical copies of the RunOS CLI's, which is the canonical home. Forking
one here would mean this repository's gate quietly drifts from the other four
public repositories, which is a worse failure than the one being fixed. The
encoding gap is filed against the CLI repository. This script closes it HERE
without touching the shared files.

WHAT IT DOES
------------
Every tracked file must be readable as UTF-8 and must contain no NUL byte, so
that leakcheck really scans all of them. A file that is neither has to be
declared in ALLOWED below, with a reason, which turns a silent skip into a
decision somebody made on purpose.

Exit codes: 0 clean, 1 findings, 2 environment error.
"""

from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Repo-relative paths that are allowed to be unscannable, each with the reason.
# This repository ships text only, so the list is empty and should stay that
# way. An entry here is a file leakcheck does not read, so it must be one whose
# content somebody has looked at.
ALLOWED: dict[str, str] = {}


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.stderr.write("unscannable: cannot list tracked files: %s\n" % exc)
        sys.exit(2)
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def main() -> int:
    findings = []
    for rel in tracked_files():
        full = os.path.join(ROOT, rel)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            findings.append((rel, "cannot be read: %s" % exc))
            continue

        reason = None
        if b"\x00" in blob:
            reason = "contains a NUL byte"
        else:
            try:
                blob.decode("utf-8")
            except UnicodeDecodeError as exc:
                reason = "is not valid UTF-8 (%s at byte %d)" % (exc.reason, exc.start)

        if reason is None:
            continue
        if rel in ALLOWED:
            continue
        findings.append((rel, reason))

    stale = [rel for rel in ALLOWED if rel not in set(tracked_files())]

    if findings or stale:
        sys.stderr.write("\nunscannable FAILED\n")
        for rel, reason in findings:
            sys.stderr.write("  %s %s, so leakcheck SKIPS it silently.\n" % (rel, reason))
        if findings:
            sys.stderr.write(
                "\n  leakcheck reads a file with open(path,'rb') and returns None for\n"
                "  NUL-bearing or non-UTF-8 content, then continues without reporting.\n"
                "  A credential in a file like this passes the pre-commit hook, the\n"
                "  whole-tree scan and CI with exit 0.\n"
                "\n  Either make the file UTF-8 text, or add it to ALLOWED in\n"
                "  scripts/unscannable_check.py with a reason, having read it first.\n"
            )
        for rel in stale:
            sys.stderr.write("  ALLOWED names %s, which is no longer tracked. Remove it.\n" % rel)
        sys.stderr.write("\n")
        return 1

    print("unscannable: clean (every tracked file is UTF-8 text leakcheck can read)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
