#!/usr/bin/env python3
"""leakcheck: keep internal identifiers and credentials out of a PUBLIC repo.

This file is IDENTICAL in every public RunOS repo (nodeagent, clusteragent,
desktop, cli). Do not fork it. Change it here, then copy it across and bump
LEAKCHECK_VERSION so drift is visible in a diff.

WHERE IT RUNS
-------------
1. .github/workflows/leakcheck.yml   every push and every pull request. This is
                                     the gate that stands between a commit and
                                     GitHub, and nobody can skip it.
2. .githooks/pre-commit              opt-in per clone (`make hooks`), skippable
                                     with --no-verify. Fast feedback only.
3. scripts/release.sh                the release gate. It runs after the branch
                                     is already pushed, so it is a last check,
                                     not the first one.

It has no dependency beyond python3 and git.

TWO SEVERITIES
--------------
1. credential  Hard fail, always. Never baselineable. Same shapes as the
               SECRET_RE floor in scripts/release.sh, so behaviour matches.
2. internal    Ratcheted, like a knip dead-code baseline. A finding already
               listed in the baseline file passes. A NEW finding fails. The
               baseline only shrinks unless a human runs --update.

WHAT COUNTS AS AN INTERNAL IDENTIFIER
-------------------------------------
* Named lab machines and rented boxes, and account ids, both read from
  scripts/leakcheck.config.
* IP address literals, by ALLOW-LIST, not deny-list. You cannot tell a real
  address from an invented one by looking at it, so only the ranges that are
  reserved for writing about (documentation, loopback, link-local, unspecified,
  broadcast, well-known multicast) pass unasked. Everything else, RFC1918
  included, is ratcheted: a pasted lab address is caught, and a project
  constant such as a service CIDR is absorbed into the baseline once and never
  asked about again.

MODES
-----
  leakcheck.py                     scan every tracked file (the authoritative mode)
  leakcheck.py --staged            scan only added lines in the staged diff (pre-commit)
  leakcheck.py --range A..B        scan only added lines in a commit range
  leakcheck.py --paths F [F...]    scan the named files (used by the tests)
  leakcheck.py --update            rewrite the baseline from a full tree scan
  leakcheck.py --version           print the checker version

Exit codes: 0 clean, 1 findings, 2 usage or environment error.
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import os
import re
import subprocess
import sys

LEAKCHECK_VERSION = "1.2.1"

# ---------------------------------------------------------------------------
# Credential shapes. Kept in step with CREDENTIAL in scripts/release.sh.
# High precision on purpose: it must not fire on commit SHAs, pinned action
# SHAs, or the public OIDC identity URL.
#
# 1.2.0: RunOS's OWN token shape was missing. `runos_pat_<id>.<secret>` is the
# format `runos login --api-key` stores and the format every RunOS API key is
# minted in, and the gate that exists to keep RunOS secrets out of a public repo
# did not recognise it. Measured 2026-08-31: a file carrying a real-shaped
# `runos_pat_` passed `make leakcheck` clean in all five public repos, while a
# GitHub token on the line above it failed. The pattern requires the full
# id-dot-secret shape, so a doc placeholder like `runos_pat_<id>.<secret>` does
# not trip it. No public repo contained the string at all when this was added,
# so it introduced no false positive.
# ---------------------------------------------------------------------------
CREDENTIAL_RE = re.compile(
    r"(gh[pousr]_[A-Za-z0-9]{20,})"
    r"|(github_pat_[A-Za-z0-9_]{20,})"
    r"|(runos_pat_[A-Za-z0-9]{6,}\.[A-Za-z0-9]{20,})"
    r"|(xox[baprs]-[A-Za-z0-9-]{10,})"
    r"|(AKIA[0-9A-Z]{16})"
    r"|(-----BEGIN [A-Z ]*PRIVATE KEY-----)"
    r"|((api[_-]?key|secret|password|passwd|token|bearer)[\"' ]*[:=][\"' ]*[\"'][A-Za-z0-9/+_.=-]{16,}[\"'])",
    re.IGNORECASE,
)

# 1.0.1: a quoted assignment is only a credential when the VALUE could be one.
# Two shapes never are, and both already ship in these public repos:
#
#     "password": "POSTGRES_PASSWORD"      an env var NAME, not its value
#     RefreshToken: "some-refresh-token"   a placeholder in a test table
#
# release.sh's own comment says prose like `password: POSTGRES_PASSWORD` must
# not trip the floor. Requiring quotes was meant to achieve that and does not,
# because JSON and Go quote the name too, so the rule is enforced here instead.
# Neither shape can hide a real credential: a real one is not a bare
# SCREAMING_SNAKE identifier, and it is not a run of lowercase English words
# joined by hyphens. High-entropy values keep failing, including an all
# lowercase value with no hyphen.
#
# This filter applies to the quoted-assignment shape ONLY. The provider token
# prefixes, the cloud key id and the PEM header are never filtered.
QUOTED_VALUE_RE = re.compile(r"[\"']([A-Za-z0-9/+_.=-]{16,})[\"']\s*$")
NOT_A_SECRET_VALUE_RE = re.compile(r"^(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[a-z]+(?:-[a-z]+)+)$")


def is_placeholder_credential(matched: str) -> bool:
    """True when a `key: "value"` match holds a value that cannot be a secret."""
    value = QUOTED_VALUE_RE.search(matched)
    return bool(value) and bool(NOT_A_SECRET_VALUE_RE.match(value.group(1)))

# ---------------------------------------------------------------------------
# IP literals.
#
# IPv4: four octets, each 0-255, and NOT part of a longer dotted run. The
# lookaround on "." is what keeps semver, dates and dotted versions out:
# "1.2.3" is three octets so it never matches, and "1.2.3.4.5" is rejected
# because a dot sits on the boundary.
# ---------------------------------------------------------------------------
IPV4_CANDIDATE_RE = re.compile(r"(?<![0-9A-Za-z._-])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z._-])")

# IPv6: a candidate needs at least two colons, then it must either contain "::"
# or carry the full seven colons. That is what stops a clock ("10:30:00") and a
# MAC address ("00:11:22:33:44:55") from being read as an address. Every
# candidate is then validated by the ipaddress module, so nothing shaped like
# an address but invalid survives.
IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z:._-])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:._-])"
)

# Ranges that exist so people can write about addresses. These never fire.
ALLOWED_NETS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "192.0.2.0/24",  # RFC 5737 TEST-NET-1
        "198.51.100.0/24",  # RFC 5737 TEST-NET-2
        "203.0.113.0/24",  # RFC 5737 TEST-NET-3
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # IPv4 link-local
        "224.0.0.0/24",  # well-known (local network control) multicast
        "0.0.0.0/32",  # unspecified
        "255.255.255.255/32",  # limited broadcast
        "2001:db8::/32",  # RFC 3849 documentation
        "fe80::/10",  # IPv6 link-local
        "ff01::/16",  # IPv6 interface-local multicast (well-known groups)
        "ff02::/16",  # IPv6 link-local multicast (well-known groups)
        "::/128",  # unspecified
        "::1/128",  # loopback
    )
]

# Forced so a local git config (diff.noprefix, diff.external, textconv) cannot
# change the shape of the diff the parser reads.
DIFF_ARGS = ("--no-color", "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/", "-U0")

BASELINE_HEADER = """\
# leakcheck baseline (leakcheck v{version})
#
# WHAT THIS FILE IS
# Every line below is an internal identifier that is ALREADY PUBLISHED in this
# public repo. The gate ignores these lines so that existing work is not
# blocked, and fails on anything new.
#
# A LINE HERE IS A RECORD OF A LEAK THAT ALREADY HAPPENED. IT IS NOT A LICENCE
# TO ADD MORE. Never hand-add a line to get a commit through. The honest way to
# clear a finding is to delete the identifier from the source and run
# `make leakcheck-update`, which is the only direction this file should move.
#
# Columns are tab separated: <path> <kind> <token>
# Regenerate with: make leakcheck-update
"""


class Finding:
    __slots__ = ("path", "line", "kind", "token", "snippet")

    def __init__(self, path: str, line: int, kind: str, token: str, snippet: str):
        self.path = path
        self.line = line
        self.kind = kind
        self.token = token
        self.snippet = snippet

    @property
    def key(self) -> tuple:
        return (self.path, self.kind, self.token)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config(path: str) -> dict:
    """Read scripts/leakcheck.config.

    Format is one `key: value` per line. Blank lines and lines starting with #
    are ignored. Repeated keys accumulate.
    """
    cfg = {"name": [], "id": [], "exclude": []}
    if not os.path.exists(path):
        fail("missing config file: %s" % path)
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                fail("bad config line in %s: %r" % (path, raw.rstrip()))
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key not in cfg:
                fail("unknown config key %r in %s" % (key, path))
            if value:
                cfg[key].append(value)
    return cfg


def build_identifier_patterns(cfg: dict) -> list:
    """Compile one word-boundary regex per configured name and id.

    Word boundaries mean a bare token hits and an unrelated longer word does
    not. For a configured token "box9": "box9" matches, "sandbox9a" does not,
    and "node-box9-a" does, because a hyphen is a boundary.
    """
    patterns = []
    for kind, values in (("name", cfg["name"]), ("id", cfg["id"])):
        for value in values:
            # A trailing "+" in the config means "followed by one or more digits".
            if value.endswith("+"):
                body = re.escape(value[:-1]) + r"\d+"
            else:
                body = re.escape(value)
            patterns.append((kind, re.compile(r"(?<![0-9A-Za-z_])(" + body + r")(?![0-9A-Za-z_])", re.IGNORECASE)))
    return patterns


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def is_ipv4_netmask(addr) -> bool:
    """True for a contiguous IPv4 netmask of prefix length 8 or longer.

    1.1.0. A subnet mask is a MASK, not an address. It names nobody and
    nothing: no host, no network, no machine. Ratcheting one only spends
    baseline rows on lines a reader can see at a glance are not identifiers,
    and six such rows already sat in one repo's baseline.

    The first octet must be 255, so the rule covers exactly the masks people
    write in documentation and console output (prefix length 8 through 32) and
    refuses prefix lengths 1 through 7. That limit matters: the masks for
    prefix lengths 1, 2 and 3 are also plausible NETWORK BASES and a leak could
    hide in one, whereas the whole 255/8 range is reserved, so no host address
    and no network base can fall inside it. This rule cannot hide a leak.

    "Contiguous" means ones then zeros: the inverted value must be 2^k - 1. A
    mask-shaped quad that is not contiguous stays ratcheted, and so does a
    wildcard (inverse) mask, whose first octet is not 255.
    """
    if addr.version != 4:
        return False
    value = int(addr)
    if value >> 24 != 0xFF:
        return False
    inverted = (~value) & 0xFFFFFFFF
    return inverted & (inverted + 1) == 0


def classify_ip(token: str):
    """Return the address if it must be reported, or None if it is allowed."""
    try:
        addr = ipaddress.ip_address(token)
    except ValueError:
        return None
    for net in ALLOWED_NETS:
        if addr.version == net.version and addr in net:
            return None
    if is_ipv4_netmask(addr):
        return None
    return addr


def scan_line(path: str, lineno: int, text: str, patterns: list) -> list:
    findings = []
    snippet = text.strip()
    if len(snippet) > 160:
        snippet = snippet[:157] + "..."

    for match in CREDENTIAL_RE.finditer(text):
        if is_placeholder_credential(match.group(0)):
            continue
        findings.append(Finding(path, lineno, "credential", match.group(0)[:40], snippet))

    for kind, pattern in patterns:
        for match in pattern.finditer(text):
            findings.append(Finding(path, lineno, kind, match.group(1).lower(), snippet))

    for match in IPV4_CANDIDATE_RE.finditer(text):
        token = match.group(1)
        if classify_ip(token) is not None:
            findings.append(Finding(path, lineno, "ipv4", token, snippet))

    for match in IPV6_CANDIDATE_RE.finditer(text):
        token = match.group(1)
        if "::" not in token and token.count(":") != 7:
            continue
        if classify_ip(token) is not None:
            findings.append(Finding(path, lineno, "ipv6", token.lower(), snippet))

    return findings


def read_texts(path: str):
    """Return every readable rendering of a file, as (label, text) pairs.

    1.2.0. This used to return ONE utf-8 string, or None for a file holding a NUL
    byte or a byte sequence that is not valid utf-8, and the scan then SKIPPED it
    without a word. That is a hole, not a safeguard, and it was measured: a real
    shaped GitHub token in a utf-16 file, in a latin-1 file, and in a file with two
    leading NUL bytes all passed `leakcheck: clean` with exit 0, while the SAME
    token in a plain utf-8 file was caught. Every public repo carried it.

    A gate that silently skips what it cannot parse is not a gate. So the file is
    now rendered every way a secret could plausibly hide, and each rendering is
    scanned:

      utf-8      the ordinary case.
      utf-16     a token in a utf-16 file survives no other way, because its bytes
                 are `g\x00h\x00p\x00...` and every byte-wise reading sees single
                 characters separated by NULs.
      bytes      printable ASCII runs of eight characters or more, pulled out of
                 the raw bytes the way `strings` does. This is what catches latin-1,
                 a NUL-prefixed file, and a token embedded in any other byte soup.

    Duplicate findings across renderings are collapsed by the caller. The credential
    patterns are high precision (a provider prefix plus twenty or more characters, a
    cloud key id, a PEM header), so pulling ASCII runs out of a genuine binary does
    not invent matches.
    """
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return []
    if not blob:
        return []

    renderings = []
    try:
        renderings.append(("utf-8", blob.decode("utf-8")))
    except UnicodeDecodeError:
        pass

    # utf-16 only when the result really looks like text, so a random binary that
    # happens to have an even length does not become a page of noise.
    if len(blob) % 2 == 0:
        for encoding in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                candidate = blob.decode(encoding)
            except (UnicodeDecodeError, UnicodeError, ValueError):
                continue
            if not candidate:
                continue
            legible = sum(1 for ch in candidate if ch.isprintable() or ch.isspace())
            if legible / len(candidate) > 0.9:
                renderings.append((encoding, candidate))
                break

    runs = re.findall(rb"[\x20-\x7e]{8,}", blob)
    if runs:
        renderings.append(("bytes", b"\n".join(runs).decode("ascii")))

    # 1.2.1. NUL-stripped. utf-32 puts THREE NUL bytes between characters, so it
    # survives neither the utf-16 decode above nor the printable-run reading,
    # which needs eight CONSECUTIVE printable bytes. Interleaving NULs by hand
    # does the same thing and needs no encoder at all. Both passed
    # `leakcheck: clean` exit 0 on 1.2.0.
    #
    # Deleting the NULs and reading what is left covers utf-32 in either byte
    # order, any NUL-padded or NUL-interleaved format, and anything a future
    # encoder pads the same way, without this file having to enumerate encodings
    # one defect at a time. Only runs when the blob actually holds a NUL, so an
    # ordinary text file pays nothing.
    #
    # It cannot invent a match: removing bytes can only bring characters
    # together, and the credential patterns need a provider prefix plus twenty or
    # more characters, a cloud key id, or a PEM header.
    if b"\x00" in blob:
        stripped = blob.replace(b"\x00", b"")
        if stripped:
            renderings.append(("nul-stripped", stripped.decode("latin-1")))

    return renderings


def scan_files(paths, patterns, skip_globs) -> list:
    findings = []
    for path in paths:
        if is_skipped(path, skip_globs):
            continue
        seen = set()
        for label, text in read_texts(path):
            for lineno, line in enumerate(text.splitlines(), start=1):
                for finding in scan_line(path, lineno, line, patterns):
                    # The same secret shows up in several renderings of one file.
                    # Report it once, and prefer the utf-8 line number when there
                    # is one, because that is the line a human will go and edit.
                    key = (finding.path, finding.kind, finding.token)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(finding)
            del label
    return findings


# leakcheck's own config names the internal machines and its baseline lists the
# published tokens, so both would report themselves. Skipping them is not a
# loophole: neither file may hold anything but bare tokens.
#
# 1.1.0: matched by EXACT repo-relative path, not by basename. The basename rule
# left every file called leakcheck.config or leakcheck.baseline unscanned
# wherever it sat, so a tracked docs/leakcheck.baseline holding a cloud key id,
# a lab box name and a lab address passed the whole-tree scan with exit 0.
# Only these two paths are the checker's own data. Anything else with the same
# name is ordinary tracked content and gets scanned like everything else.
SELF_RELPATHS = frozenset({"scripts/leakcheck.config", "scripts/leakcheck.baseline"})

# The same two files by absolute path, so --paths and a scan run from any
# working directory skip them too. Derived from this file's own location.
SELF_ABSPATHS = frozenset(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    for name in ("leakcheck.config", "leakcheck.baseline")
)


def is_self_file(path: str, norm: str) -> bool:
    return norm in SELF_RELPATHS or os.path.abspath(path) in SELF_ABSPATHS


def is_skipped(path: str, skip_globs) -> bool:
    norm = path.replace(os.sep, "/")
    while norm.startswith("./"):
        norm = norm[2:]
    if is_self_file(path, norm):
        return True
    for glob in skip_globs:
        if fnmatch.fnmatch(norm, glob) or norm.endswith("/" + glob):
            return True
    return False


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scan_diff(diff_text: str, patterns: list, skip_globs) -> list:
    """Scan only the added lines of a unified diff.

    Line numbers come from the hunk headers, so a finding points at the line it
    will have in the committed file.

    1.1.0: a "--- a/x" / "+++ b/y" pair names a file ONLY inside a file header,
    which starts at a "diff --git" line and ends at that file's first hunk
    header. Before this rule the parser accepted the pair anywhere, so CONTENT
    could impersonate a header: a deleted line reading "-- a/x" renders as
    "--- a/x" and an added line reading "++ b/scripts/leakcheck.config" renders
    as "+++ b/scripts/leakcheck.config". The parser then pointed path at a
    skipped file and dropped the rest of the hunk. Reproduced before the fix:
    --staged reported clean and exited 0 while the whole-tree scan found the
    lab box name in the same staged content.

    Nothing is scanned before the first "diff --git", so an input that is not a
    git diff yields no findings rather than mis-attributed ones.
    """
    findings = []
    path = None
    lineno = 0
    skipping = True
    in_header = False
    awaiting_plus = False

    for raw in diff_text.splitlines():
        if raw.startswith("diff --git"):
            in_header = True
            awaiting_plus = False
            path = None
            skipping = True
            lineno = 0
            continue

        if in_header:
            if awaiting_plus:
                awaiting_plus = False
                if raw.startswith("+++ "):
                    target = raw[4:].strip()
                    if target == "/dev/null":
                        path = None
                        skipping = True
                    else:
                        path = target[2:] if target.startswith("b/") else target
                        skipping = is_skipped(path, skip_globs)
                    continue
                # A "--- " with no "+++ " after it was not a header pair.
            if raw.startswith("--- "):
                target = raw[4:].strip()
                if target == "/dev/null" or target.startswith("a/"):
                    awaiting_plus = True
                    continue
            head = HUNK_RE.match(raw)
            if head:
                in_header = False
                lineno = int(head.group(1))
            # Every other header line (index, mode, similarity, rename, binary)
            # carries nothing to scan.
            continue

        head = HUNK_RE.match(raw)
        if head:
            lineno = int(head.group(1))
            continue
        if raw.startswith("+"):
            if path and not skipping:
                findings.extend(scan_line(path, lineno, raw[1:], patterns))
            lineno += 1
        elif raw.startswith(" "):
            lineno += 1
    return findings


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------
def load_baseline(path: str) -> set:
    keys = set()
    if not os.path.exists(path):
        return keys
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 3:
                fail("bad baseline line in %s: %r" % (path, line))
            keys.add((parts[0], parts[1], parts[2]))
    return keys


def write_baseline(path: str, keys) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(BASELINE_HEADER.format(version=LEAKCHECK_VERSION))
        for key in sorted(keys):
            fh.write("%s\t%s\t%s\n" % key)


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------
def git(*args) -> str:
    proc = subprocess.run(
        ["git"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if proc.returncode != 0:
        fail("git %s failed: %s" % (" ".join(args), proc.stderr.strip()))
    return proc.stdout


def repo_root() -> str:
    return git("rev-parse", "--show-toplevel").strip()


def tracked_files() -> list:
    out = git("ls-files", "-z")
    return [p for p in out.split("\0") if p]


def fail(message: str):
    sys.stderr.write("leakcheck: %s\n" % message)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def report(findings, stream) -> None:
    # One line per (file, line, kind, token). A token that repeats on a line is
    # one problem, not several.
    seen = set()
    for finding in sorted(findings, key=lambda f: (f.path, f.line, f.kind, f.token)):
        mark = (finding.path, finding.line, finding.kind, finding.token)
        if mark in seen:
            continue
        seen.add(mark)
        stream.write(
            "  %s:%d  [%s] %s\n      %s\n"
            % (finding.path, finding.line, finding.kind, finding.token, finding.snippet)
        )


def main(argv) -> int:
    parser = argparse.ArgumentParser(prog="leakcheck", add_help=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="scan added lines in the staged diff")
    mode.add_argument("--range", dest="rng", metavar="A..B", help="scan added lines in a commit range")
    mode.add_argument("--paths", nargs="+", metavar="FILE", help="scan the named files")
    parser.add_argument("--update", action="store_true", help="rewrite the baseline from a full tree scan")
    parser.add_argument("--no-baseline", action="store_true", help="report every finding, baseline ignored")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--version", action="store_true", help="print the checker version")
    args = parser.parse_args(argv)

    if args.version:
        print("leakcheck %s" % LEAKCHECK_VERSION)
        return 0

    here = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(here, "leakcheck.config")
    baseline_path = os.path.join(here, "leakcheck.baseline")

    cfg = load_config(config_path)
    patterns = build_identifier_patterns(cfg)

    skip_globs = list(cfg["exclude"])

    if args.paths:
        findings = scan_files(args.paths, patterns, skip_globs)
    else:
        root = repo_root()
        os.chdir(root)
        if args.staged:
            findings = scan_diff(git("diff", "--cached", *DIFF_ARGS), patterns, skip_globs)
        elif args.rng:
            findings = scan_diff(git("diff", *(DIFF_ARGS + (args.rng,))), patterns, skip_globs)
        else:
            findings = scan_files(tracked_files(), patterns, skip_globs)

    credentials = [f for f in findings if f.kind == "credential"]
    internal = [f for f in findings if f.kind != "credential"]

    if args.update:
        if args.staged or args.rng or args.paths:
            fail("--update only works on a full tree scan")
        if credentials:
            sys.stderr.write("leakcheck: credential-shaped content found, refusing to update the baseline\n")
            report(credentials, sys.stderr)
            return 1
        write_baseline(baseline_path, {f.key for f in internal})
        print("leakcheck: baseline rewritten with %d entries (%s)" % (len({f.key for f in internal}), baseline_path))
        return 0

    baseline = set() if args.no_baseline else load_baseline(baseline_path)
    new_internal = [f for f in internal if f.key not in baseline]

    if args.json:
        import json

        print(
            json.dumps(
                [
                    {"path": f.path, "line": f.line, "kind": f.kind, "token": f.token}
                    for f in credentials + new_internal
                ],
                indent=2,
            )
        )
        return 1 if (credentials or new_internal) else 0

    if credentials:
        sys.stderr.write("\nleakcheck FAILED: credential-shaped content (never baselineable)\n")
        report(credentials, sys.stderr)

    if new_internal:
        sys.stderr.write("\nleakcheck FAILED: internal identifiers that are not in the baseline\n")
        report(new_internal, sys.stderr)
        sys.stderr.write(
            "\nRemove these before committing. This is a PUBLIC repo.\n"
            "If a hit is a false positive, fix the checker (scripts/leakcheck.py).\n"
            "Do not hand-add a line to scripts/leakcheck.baseline to get past this.\n"
        )

    if credentials or new_internal:
        return 1

    if not (args.staged or args.rng or args.paths or args.no_baseline):
        found = {f.key for f in internal}
        stale = baseline - found
        if stale:
            print(
                "leakcheck: clean (%d baselined). %d baseline entries no longer exist, "
                "prune them with `make leakcheck-update`." % (len(found), len(stale))
            )
            return 0
    print("leakcheck: clean (leakcheck %s)" % LEAKCHECK_VERSION)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
