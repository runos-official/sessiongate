#!/usr/bin/env python3
"""Tests for leakcheck.

This file is IDENTICAL in every public RunOS repo. Run it with:

    make leakcheck-test          (or: python3 scripts/leakcheck_test.py)

IMPORTANT, and it is the reason this file looks the way it does. This is a
PUBLIC repo, so the test must not itself publish the things it tests for. No
real internal identifier is ever written as a literal here. Every one is
assembled at run time from fragments that leakcheck cannot match, so this file
is clean when leakcheck scans the tree. Fixtures that need a harmless address
use the RFC 5737 documentation ranges.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "leakcheck.py")

# The parser and the path rules are tested in-process. Shelling out cannot
# reach them: the diff parser needs a diff on stdin, which the checker has no
# mode for, and the self-file rule needs a path that is not a real file.
_spec = importlib.util.spec_from_file_location("leakcheck_under_test", CHECKER)
leakcheck = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(leakcheck)

FAILURES = []
CHECKS = 0


# ---------------------------------------------------------------------------
# Fragment assembly. Nothing below ever appears as a matchable literal.
# ---------------------------------------------------------------------------
def dotted(*octets) -> str:
    return ".".join(str(o) for o in octets)


# Configured machine names and account ids, split so leakcheck does not report
# its own test file. These add nothing that scripts/leakcheck.config does not
# already hold, and they carry no context beyond the bare token.
LAB_BOX = "ftb" + "1"
SECOND_BOX = "ftb" + "2"
RENTED_BOX = "fttb" + "3"
ACCOUNT_ID = "rj" + "wrn"

# 1.2.0: RunOS's OWN token shape, assembled so this file does not carry a
# matchable literal. The prefix is split exactly like the machine names above.
RUNOS_TOKEN_PREFIX = "runos" + "_pat_"
RUNOS_TOKEN = RUNOS_TOKEN_PREFIX + "AbCdEfGhJk.MnPqRsTuVwXyZ23456789AbCdEfGhJkMn"
RUNOS_TOKEN_2 = RUNOS_TOKEN_PREFIX + "Zz9Yy8Xx7W.QqWwEeRrTtYyUuIiOoPpAaSsDdFfGg"

# The SHAPE of the pasted terminal output that shipped in
# cmd/preflight/tls_failure_kind_test.go: a private source address dialling a
# public destination. Both are stand-ins, not the addresses from the incident,
# and neither sits in an allow-listed range, so the catch is still exercised.
# Assembled octet by octet so no dotted quad appears in this file.
PASTED_SRC = dotted(10, 0, 0, 226)
PASTED_DST = dotted(198, 18, 0, 98)
PASTED_ERROR = "read tcp %s:52618->%s:9191: i/o timeout" % (PASTED_SRC, PASTED_DST)
GLOBAL_V6 = ":".join(["2606", "4700", "4700"]) + "::" + "1111"

# Credential fixtures. Split so this file never holds a matchable credential
# shape: a credential finding is never baselineable, so a literal here would
# fail the gate on this repo for ever.
PRIVATE_KEY_HEADER = "-----BEGIN RSA " + "PRIVATE " + "KEY-----"
AWS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
SECRET_ASSIGNMENT = "api" + "_key" + ' = "abcdefghijklmnopqrstuvwx"'

# 1.0.1: a quoted assignment whose VALUE cannot be a secret. Both shapes ship
# today in the public repos, and both are fragmented here for the same reason
# as the fixtures above.
ENV_NAME_VALUE = '"pass' + 'word": "POSTGRES_PASSWORD"'
PLACEHOLDER_VALUE = 'refreshTo' + 'ken: "valid-refresh-token"'
REAL_LOOKING_VALUE = 'to' + 'ken = "aB3xK9zQ7mN2pR5tV8wY"'


def run_checker(text: str, extra_args=()):
    """Write text to a temp file, scan it, return (exit code, stdout+stderr)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "fixture.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        proc = subprocess.run(
            [sys.executable, CHECKER, "--no-baseline", "--paths", path] + list(extra_args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return proc.returncode, proc.stdout


def run_checker_bytes(blob: bytes, suffix: str = ".txt"):
    """Write RAW BYTES to a temp file, scan it, return (exit code, stdout+stderr)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "fixture" + suffix)
        with open(path, "wb") as fh:
            fh.write(blob)
        proc = subprocess.run(
            [sys.executable, CHECKER, "--no-baseline", "--paths", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return proc.returncode, proc.stdout


def expect_catch_bytes(label: str, blob: bytes, token: str, suffix: str = ".txt") -> None:
    global CHECKS
    CHECKS += 1
    code, out = run_checker_bytes(blob, suffix)
    if code == 1 and token in out:
        print("  PASS  catch    %s" % label)
        return
    FAILURES.append(label)
    print("  FAIL  catch    %s (exit %d)\n%s" % (label, code, out))


def expect_catch(label: str, text: str, token: str) -> None:
    global CHECKS
    CHECKS += 1
    code, out = run_checker(text)
    if code == 1 and token in out:
        print("  PASS  catch    %s" % label)
        return
    FAILURES.append(label)
    print("  FAIL  catch    %s (exit %d)\n%s" % (label, code, out))


def expect_true(label: str, value) -> None:
    global CHECKS
    CHECKS += 1
    if value:
        print("  PASS  %s" % label)
        return
    FAILURES.append(label)
    print("  FAIL  %s (got %r)" % (label, value))


def expect_clean(label: str, text: str) -> None:
    global CHECKS
    CHECKS += 1
    code, out = run_checker(text)
    if code == 0:
        print("  PASS  no-catch %s" % label)
        return
    FAILURES.append(label)
    print("  FAIL  no-catch %s (exit %d)\n%s" % (label, code, out))


def main() -> int:
    print("leakcheck tests")
    print()
    print("MUST CATCH")

    # The exact incident: the lab box name in a Go comment.
    expect_catch(
        "lab box name in a Go comment",
        "// (LINSTOR replicated-2 on %s's SAS spindles, under nested guests), so that\n" % LAB_BOX,
        LAB_BOX,
    )
    expect_catch(
        "lab box name in prose",
        "All three guests sat on ONE backing device: LINSTOR replicated-2 on %s's SAS spindles.\n" % LAB_BOX,
        LAB_BOX,
    )
    expect_catch("second lab box name", "// Measured on %s after a reset.\n" % SECOND_BOX, SECOND_BOX)
    expect_catch("rented box name with digits", "# provisioned %s in fsn1\n" % RENTED_BOX, RENTED_BOX)
    expect_catch("lab box name inside a hyphenated word", "host node-%s-a rebooted\n" % LAB_BOX, LAB_BOX)
    expect_catch("lab box name in mixed case", "Measured on %s.\n" % LAB_BOX.upper(), LAB_BOX)
    expect_catch("account id in a node name", 'want "n02-cl1-%s" in the detail\n' % ACCOUNT_ID, ACCOUNT_ID)


    # 1.2.0: RunOS's OWN token shape. The gate exists to keep RunOS secrets out
    # of a public repo, and until 1.2.0 it did not recognise the format
    # `runos login --api-key` stores. Measured 2026-08-31: a file carrying a
    # real-shaped runos_pat_ passed clean in all five public repos, while a
    # GitHub token on the line above it failed.
    expect_catch(
        "RunOS personal access token",
        "runos login --api-key %s\n" % RUNOS_TOKEN,
        RUNOS_TOKEN[:22],
    )
    expect_catch(
        "RunOS token in an environment assignment",
        "export RUNOS_API_KEY=%s\n" % RUNOS_TOKEN_2,
        RUNOS_TOKEN_2[:22],
    )
    # The already-shipped pasted output, both addresses in one line.
    expect_catch("pasted source address in a shipped test comment", '// "the secure handshake FAILED: %s",\n' % PASTED_ERROR, PASTED_SRC)
    expect_catch("pasted destination address in the same line", '// "the secure handshake FAILED: %s",\n' % PASTED_ERROR, PASTED_DST)

    # Other ratcheted address shapes.
    expect_catch("RFC1918 address", "listen-address=%s\n" % dotted(10, 0, 0, 1), dotted(10, 0, 0, 1))
    expect_catch("public address", "resolver %s\n" % dotted(8, 8, 8, 8), dotted(8, 8, 8, 8))
    expect_catch("address inside a CIDR", "the pod range %s/16\n" % dotted(172, 25, 0, 0), dotted(172, 25, 0, 0))
    expect_catch("global IPv6 address", "nameserver %s\n" % GLOBAL_V6, GLOBAL_V6)
    # 1.1.0 guards the netmask allowance: only 255.x, only contiguous.
    expect_catch("non-contiguous mask-shaped quad", "mask %s\n" % dotted(255, 255, 1, 0), dotted(255, 255, 1, 0))
    expect_catch("contiguous mask below /8", "base %s/2\n" % dotted(192, 0, 0, 0), dotted(192, 0, 0, 0))
    expect_catch("wildcard mask, not a netmask", "acl %s\n" % dotted(0, 255, 255, 255), dotted(0, 255, 255, 255))

    # Credentials, which are never baselineable.
    expect_catch("AWS access key id", "aws_access_key_id = %s\n" % AWS_KEY_ID, AWS_KEY_ID)
    expect_catch("private key block", PRIVATE_KEY_HEADER + "\n", PRIVATE_KEY_HEADER)
    expect_catch("quoted secret assignment", SECRET_ASSIGNMENT + "\n", SECRET_ASSIGNMENT)
    # Guards the 1.0.1 value filter: a high-entropy value must still hard fail.
    expect_catch("high-entropy quoted assignment", REAL_LOOKING_VALUE + "\n", "aB3xK9zQ7mN2pR5tV8wY")

    print()
    # 1.2.0: FILE ENCODING. read_text used to return None for a file holding a NUL
    # byte or a byte sequence that is not valid utf-8, and the scan then SKIPPED
    # that file WITHOUT A WORD. Measured before the fix: the SAME real-shaped token
    # passed `leakcheck: clean` exit 0 in a utf-16 file, a latin-1 file and a file
    # with two leading NUL bytes, while it was caught in a plain utf-8 file. Every
    # public repo carried it. A gate that silently skips what it cannot parse is
    # not a gate.
    ENCODED_TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    ENCODED_LINE = "export GITHUB_TOKEN=%s\n" % ENCODED_TOKEN
    expect_catch_bytes(
        "a token in a utf-16 file", ENCODED_LINE.encode("utf-16"), ENCODED_TOKEN
    )
    expect_catch_bytes(
        "a token in a utf-16-le file with no BOM",
        ENCODED_LINE.encode("utf-16-le"),
        ENCODED_TOKEN,
    )
    expect_catch_bytes(
        "a token in a latin-1 file",
        ("# caf\xe9\n" + ENCODED_LINE).encode("latin-1"),
        ENCODED_TOKEN,
    )
    expect_catch_bytes(
        "a token in a file that starts with NUL bytes",
        b"\x00\x00" + ENCODED_LINE.encode(),
        ENCODED_TOKEN,
    )
    expect_catch_bytes(
        "a token buried in a kilobyte of arbitrary bytes",
        bytes(range(256)) * 4 + ENCODED_LINE.encode(),
        ENCODED_TOKEN,
        ".bin",
    )

    # 1.2.1: the 1.2.0 fix above closed utf-16 and latin-1 and stopped there, and
    # the remaining hole was found by a gate ADDED to catch files this scanner
    # cannot read, which is the honest way round. Both cases below passed
    # `leakcheck: clean` exit 0 on 1.2.0.
    #
    # utf-32 puts THREE NUL bytes between characters, so it survives neither the
    # utf-16 decode nor the printable-run reading, which needs eight consecutive
    # printable bytes. Interleaving NULs by hand does the same thing and needs no
    # encoder at all.
    expect_catch_bytes(
        "a token in a utf-32 file", ENCODED_LINE.encode("utf-32"), ENCODED_TOKEN
    )
    expect_catch_bytes(
        "a token in a utf-32-le file with no BOM",
        ENCODED_LINE.encode("utf-32-le"),
        ENCODED_TOKEN,
    )
    expect_catch_bytes(
        "a token with a NUL byte between every character",
        b"\x00".join(bytes([c]) for c in ENCODED_LINE.encode()),
        ENCODED_TOKEN,
    )

    print("MUST NOT CATCH")

    # RFC 5737 and RFC 3849. These exist so people can write about addresses.
    expect_clean(
        "RunOS token placeholder in documentation",
        "runos login --api-key %s<id>.<secret>\n" % RUNOS_TOKEN_PREFIX,
    )
    expect_clean("RFC 5737 TEST-NET-1", "gateway %s\n" % dotted(192, 0, 2, 1))
    expect_clean("RFC 5737 TEST-NET-2", "peer %s\n" % dotted(198, 51, 100, 7))
    expect_clean("RFC 5737 TEST-NET-3", "endpoint %s:51820\n" % dotted(203, 0, 113, 5))
    expect_clean("RFC 5737 TEST-NET-3 CIDR", "the LAN %s/24 overlaps\n" % dotted(203, 0, 113, 0))
    expect_clean("RFC 3849 documentation IPv6", "nameserver 2001:db8::1\n")

    # Loopback, link-local, unspecified, broadcast, well-known multicast.
    expect_clean("loopback", "dial %s:9191\n" % dotted(127, 0, 0, 1))
    expect_clean("systemd-resolved stub", "nameserver %s\n" % dotted(127, 0, 0, 53))
    expect_clean("cloud metadata link-local", "curl http://%s/latest\n" % dotted(169, 254, 169, 254))
    expect_clean("unspecified address", "bind %s:8080\n" % dotted(0, 0, 0, 0))
    expect_clean("limited broadcast", "send to %s\n" % dotted(255, 255, 255, 255))
    expect_clean("well-known multicast", "join %s\n" % dotted(224, 0, 0, 251))
    expect_clean("IPv6 loopback", "dial [::1]:9191\n")
    expect_clean("IPv6 unspecified", "listen on ::\n")
    expect_clean("IPv6 link-local", "fe80::1%eth0\n")
    expect_clean("IPv6 link-local multicast", "ff02::fb is mDNS\n")

    # 1.1.0: contiguous IPv4 netmasks. A mask names nobody, so it is not an
    # identifier and does not belong in the ratchet.
    expect_clean("class-B netmask", "netmask %s\n" % dotted(255, 255, 0, 0))
    expect_clean("/21 netmask", "Subnet mask . . . : %s\n" % dotted(255, 255, 248, 0))
    expect_clean("/8 netmask", "netmask %s\n" % dotted(255, 0, 0, 0))
    expect_clean("/24 netmask", "netmask %s\n" % dotted(255, 255, 255, 0))

    # Things that look numeric but are not addresses. These are the false
    # positives that would get the gate switched off.
    expect_clean("semver", "released v1.24.3 today\n")
    expect_clean("four-part product version", "Kubernetes 1.31.2 and containerd 1.7.20\n")
    expect_clean("go directive", "go 1.24.0\n")
    expect_clean("ISO date", "measured 2026-08-22 on hardware\n")
    expect_clean("dotted date", "measured 2026.08.22 on hardware\n")
    expect_clean("dotted config key", "runos set-config node.disk.size.gb 200\n")
    expect_clean("five dotted numbers", "sequence 1.2.3.4.5 is not an address\n")
    expect_clean("octet above 255", "build 999.888.777.666\n")
    expect_clean("address glued to a word", "revision abc10.0.0.1def\n")
    expect_clean("clock time", "took 10:30:00 to converge\n")
    expect_clean("MAC address", "link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff\n")
    expect_clean("commit sha", "pinned at 3b2c1a9f8e7d6c5b4a39281706f5e4d3c2b1a098\n")
    expect_clean("OIDC identity url", "https://github.com/runos-official/nodeagent/.github/workflows/release.yml@refs/tags/v0.24.0\n")
    expect_clean("public runos hosts", "curl https://get.runos.com | bash  # registers with nodeward.runos.com\n")
    expect_clean("lab box name inside a longer word", "the sandbox1 harness and a leftb1as variable\n")
    expect_clean("port only", "listening on :9191\n")
    # 1.0.1: values that a credential shape can hold but a secret cannot.
    expect_clean("env var name as a quoted value", ENV_NAME_VALUE + ",\n")
    expect_clean("hyphenated lowercase placeholder", PLACEHOLDER_VALUE + ",\n")

    print()
    print("DIFF PARSER (1.1.0: content must not impersonate a file header)")

    patterns = leakcheck.build_identifier_patterns(leakcheck.load_config(os.path.join(HERE, "leakcheck.config")))

    # The exact bypass: a deleted line reading "-- a/x" and an added line
    # reading "++ b/scripts/leakcheck.config" render as a "--- "/"+++ " pair
    # inside the hunk. Before the fix the parser believed it and dropped the
    # rest of the hunk, so --staged exited 0 on a staged lab box name.
    poison = "\n".join([
        "diff --git a/docs/note.md b/docs/note.md",
        "index c14961c..b71793c 100644",
        "--- a/docs/note.md",
        "+++ b/docs/note.md",
        "@@ -2 +2,2 @@ line one",
        "--- a/x",
        "+++ b/scripts/leakcheck.config",
        "+Seen on %s during the reset." % LAB_BOX,
        "",
    ])
    found = leakcheck.scan_diff(poison, patterns, [])
    expect_true(
        "a forged header inside a hunk does not redirect the path",
        any(f.kind == "name" and f.token == LAB_BOX and f.path == "docs/note.md" for f in found),
    )

    # And an ordinary diff still parses: right path, right line number.
    ordinary = "\n".join([
        "diff --git a/docs/note.md b/docs/note.md",
        "index c14961c..b71793c 100644",
        "--- a/docs/note.md",
        "+++ b/docs/note.md",
        "@@ -7,0 +8 @@ context",
        "+Measured on %s." % SECOND_BOX,
        "",
    ])
    found = leakcheck.scan_diff(ordinary, patterns, [])
    expect_true(
        "an ordinary diff still reports the right path and line",
        any(f.path == "docs/note.md" and f.line == 8 and f.token == SECOND_BOX for f in found),
    )

    # A new file (--- /dev/null) still parses.
    added = "\n".join([
        "diff --git a/docs/new.md b/docs/new.md",
        "new file mode 100644",
        "index 0000000..1111111",
        "--- /dev/null",
        "+++ b/docs/new.md",
        "@@ -0,0 +1 @@",
        "+Measured on %s." % LAB_BOX,
        "",
    ])
    expect_true(
        "a newly added file is still scanned",
        any(f.path == "docs/new.md" for f in leakcheck.scan_diff(added, patterns, [])),
    )

    # The checker's own config is still skipped when a real header names it.
    real = "\n".join([
        "diff --git a/scripts/leakcheck.config b/scripts/leakcheck.config",
        "index 1111111..2222222 100644",
        "--- a/scripts/leakcheck.config",
        "+++ b/scripts/leakcheck.config",
        "@@ -30,0 +31 @@",
        "+id: %s" % ACCOUNT_ID,
        "",
    ])
    expect_true(
        "the checker's own config is still skipped in a diff",
        leakcheck.scan_diff(real, patterns, []) == [],
    )

    print()
    print("SELF-FILE SKIP (1.1.0: exact path, not basename)")
    expect_true("scripts/leakcheck.config is skipped", leakcheck.is_skipped("scripts/leakcheck.config", []))
    expect_true("scripts/leakcheck.baseline is skipped", leakcheck.is_skipped("scripts/leakcheck.baseline", []))
    expect_true("./scripts/leakcheck.config is skipped", leakcheck.is_skipped("./scripts/leakcheck.config", []))
    expect_true("docs/leakcheck.baseline is NOT skipped", not leakcheck.is_skipped("docs/leakcheck.baseline", []))
    expect_true("docs/leakcheck.config is NOT skipped", not leakcheck.is_skipped("docs/leakcheck.config", []))
    expect_true(
        "a nested scripts/leakcheck.config is NOT skipped",
        not leakcheck.is_skipped("vendor/scripts/leakcheck.config", []),
    )

    print()
    print("%d checks, %d failures" % (CHECKS, len(FAILURES)))
    if FAILURES:
        for name in FAILURES:
            print("  failed: %s" % name)
        return 1
    print("leakcheck tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
